#!/usr/bin/env python3
"""
ruleforge_ui.py
===============
A local web interface for the detection-rule pipeline.

    python ruleforge_ui.py

Opens http://127.0.0.1:8765 in your browser. Every stage of the pipeline -
generate, check, verify against Chronicle, test against EvidenceForge, build
reports - runs from one page, with a live log and a cancel button.

Design notes
------------
* Standard library only. No pip install.
* Bound to 127.0.0.1, so it is reachable from this machine only - never from
  the network.
* It does not reimplement anything. Each button runs the real script as a
  subprocess, so the UI and the command line can never disagree. The generator
  is driven through `--answers`, which supplies answers by stable key rather
  than by prompt order.
* Your last-used settings are remembered in ui_settings.json.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
SETTINGS = HERE / "ui_settings.json"
HOST = "127.0.0.1"

# Report files the UI is allowed to serve. Anything else is refused, so the
# local server can never be used to read arbitrary files off the disk.
SERVABLE = {
    "check_report.html", "check_report.csv", "evidence_report.html",
    "evidence_report.csv", "status_report.html", "new_list.csv",
    "rules_for_validation.csv", "heatmap/coverage_heatmap.html",
    "heatmap/attack_layer.json",
}

DEFAULTS = {
    "language": "2", "coverage_file": "coverage.csv", "include_subs": True,
    "mode": "1", "depth_covered": 2, "depth_gap": 3, "depth_tail": 1,
    "depth_covered_tail": 0,
    "platform_scope": "2", "balance": True, "count": 100, "resume": True,
    "model": "", "rules_dir": "output",
    "manual_techniques": "", "manual_count": 3, "manual_include_subs": True,
    "fix": False, "verify_limit": 100, "recheck": False,
    "ef_dir": "", "scenario": "", "ef_local": True,
}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def load_settings() -> dict:
    s = dict(DEFAULTS)
    if SETTINGS.is_file():
        try:
            s.update(json.loads(SETTINGS.read_text(encoding="utf-8")))
        except Exception:
            pass
    return s


def save_settings(s: dict) -> None:
    keep = {k: s[k] for k in DEFAULTS if k in s}
    SETTINGS.write_text(json.dumps(keep, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Job runner - one subprocess at a time, output streamed into a buffer
# ---------------------------------------------------------------------------
class Job:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.lines: list[str] = []
        self.name = ""
        self.started = 0.0
        self.exit_code: int | None = None

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, name: str, argv: list[str], stdin_text: str = "",
              env_extra: dict | None = None) -> str | None:
        with self.lock:
            if self.running:
                return f"'{self.name}' is still running. Wait for it, or cancel it."
            env = dict(os.environ)
            env.update({"PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"})
            env.update(env_extra or {})
            self.lines, self.name, self.exit_code = [], name, None
            self.started = time.time()
            try:
                self.proc = subprocess.Popen(
                    [sys.executable, *argv], cwd=HERE, env=env,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
            except Exception as e:
                self.proc = None
                return f"Could not start {argv[0]}: {e}"
            threading.Thread(target=self._pump, args=(stdin_text,), daemon=True).start()
            return None

    def _pump(self, stdin_text: str) -> None:
        p = self.proc
        try:
            if stdin_text:
                p.stdin.write(stdin_text.encode("utf-8"))
            p.stdin.close()
        except Exception:
            pass
        for raw in iter(p.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            with self.lock:
                self.lines.append(line)
                if len(self.lines) > 20000:          # bound memory on huge runs
                    self.lines = self.lines[-15000:]
        p.wait()
        with self.lock:
            self.exit_code = p.returncode

    def cancel(self) -> None:
        with self.lock:
            if self.running:
                self.proc.terminate()
                self.lines.append("--- cancelled ---")

    def snapshot(self, since: int) -> dict:
        with self.lock:
            return {"name": self.name, "running": self.running,
                    "exit_code": self.exit_code, "total": len(self.lines),
                    "lines": self.lines[since:],
                    "elapsed": round(time.time() - self.started) if self.started else 0}


JOB = Job()

# Models that can't write rules (embeddings, speech, images) are hidden.
NON_CHAT = ("embedding", "tts", "whisper", "dall-e", "imagen", "transcribe",
            "translategemma", "image")
_models_cache: dict = {}


def fetch_models(refresh: bool = False) -> dict:
    """Ask Fuel iX which models this account has, via the generator itself."""
    if _models_cache and not refresh:
        return _models_cache
    try:
        out = subprocess.run([sys.executable, "gap_ruleforge.py", "--list-models"],
                             cwd=HERE, capture_output=True, timeout=60,
                             env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        lines = [l for l in out.stdout.decode("utf-8", "replace").splitlines()
                 if l.strip().startswith("{")]
        data = json.loads(lines[-1]) if lines else {"default": "", "models": []}
    except Exception as e:
        return {"default": "", "models": [], "error": f"Couldn't reach Fuel iX: {e}"}
    models = sorted(m for m in data.get("models", [])
                    if not any(k in m.lower() for k in NON_CHAT))
    result = {"default": data.get("default", ""), "models": models}
    if not models:
        result["error"] = ("Fuel iX returned no models. Check the VPN and the "
                           "API key in your .env.")
    _models_cache.clear()
    _models_cache.update(result)
    return result


# ---------------------------------------------------------------------------
# Building each stage's command
# ---------------------------------------------------------------------------
def yn(v) -> str:
    return "y" if v in (True, "true", "on", "y", "1", 1) else "n"


def build(stage: str, s: dict) -> tuple[str, list[str], str, dict]:
    """Return (display name, argv, stdin text, extra env) for a stage."""
    rules = s.get("rules_dir") or "output"
    env = {"OUTPUT_DIR": rules}
    if s.get("model"):
        env["FUELIX_MODEL"] = s["model"]

    if stage == "generate":
        answers = {
            "language": s["language"], "coverage_file": s["coverage_file"],
            "include_subs": yn(s["include_subs"]), "id_column": "all",
            "status_column": "", "mode": s["mode"],
            "depth_covered": s["depth_covered"], "depth_gap": s["depth_gap"],
            "depth_tail": s["depth_tail"],
            "depth_covered_tail": s.get("depth_covered_tail", 0),
            "platform_scope": s["platform_scope"],
            "balance": yn(s["balance"]), "resume": yn(s["resume"]),
            "count": s["count"], "proceed": "y", "continue_outdated": "n",
            "manual_techniques": s.get("manual_techniques", ""),
            "manual_count": s.get("manual_count", 3),
            # One visible checkbox controls sub-techniques in both modes. Derived
            # here rather than trusting a separate client-side copy.
            "manual_include_subs": yn(s["include_subs"]),
            "manual_pick": "", "manual_order": "",
        }
        f = HERE / ".ui_answers.json"
        f.write_text(json.dumps(answers), encoding="utf-8")
        return "Generate rules", ["gap_ruleforge.py", "--answers", f.name], "", env

    if stage == "check":
        argv = ["check_rules.py"] + (["--fix"] if s.get("fix") else [])
        return "Check rules", argv, f"{rules}\n", env

    if stage == "verify":
        argv = ["check_rules.py", "--verify", "--limit", str(s.get("verify_limit", 100))]
        if s.get("recheck"):
            argv.append("--recheck")
        return "Verify with Chronicle", argv, f"{rules}\n", env

    if stage == "connection":
        return "Test Chronicle connection", ["gap_ruleforge.py", "--verify-setup"], "", env

    if stage == "evidence":
        argv = ["evidence_test.py", "--ef", s.get("ef_dir", ""), "--rules", rules]
        if s.get("scenario"):
            argv += ["--scenario", s["scenario"]]
        if s.get("ef_local"):
            argv.append("--local")
        return "Test against EvidenceForge", argv, "", env

    if stage == "heatmap":
        return "Build coverage heatmap", ["build_heatmap.py"], \
            f"{s['coverage_file']}\n{rules}\n", env
    if stage == "status":
        return "Build status report", ["build_status_report.py"], \
            f"{rules}\n{s['coverage_file']}\n", env
    if stage == "newlist":
        return "Build review sheet", ["build_new_list.py"], f"{rules}\n", env
    if stage == "export":
        return "Export for validator", ["export_for_validator.py"], f"{rules}\n", env

    raise ValueError(f"unknown stage {stage}")


# ---------------------------------------------------------------------------
# Library state - what the pipeline rail shows
# ---------------------------------------------------------------------------
def _csv(path: Path, col: str) -> dict[str, int]:
    out: dict[str, int] = {}
    if not path.is_file():
        return out
    try:
        with path.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                k = row.get(col, "")
                out[k] = out.get(k, 0) + 1
    except Exception:
        pass
    return out


def state(s: dict) -> dict:
    rules_dir = HERE / (s.get("rules_dir") or "output")
    names = {f.name for ext in ("*.yaral", "*.kql")
             for f in rules_dir.rglob(ext)} if rules_dir.is_dir() else set()
    check = _csv(HERE / "check_report.csv", "severity_bucket")
    chron = _csv(HERE / "check_report.csv", "chronicle")
    evid = _csv(HERE / "evidence_report.csv", "verdict")
    scripts = {n: (HERE / n).is_file() for n in (
        "gap_ruleforge.py", "check_rules.py", "evidence_test.py",
        "build_heatmap.py", "build_status_report.py", "build_new_list.py",
        "export_for_validator.py")}
    cov = s.get("coverage_file") or "coverage.csv"
    config = {
        "mitre_techniques_19.1.json": ("MITRE ATT&CK data",
                                       "the generator will try to download it"),
        "priority_techniques.json": ("Top 10 priority list",
                                     "all techniques are treated equally - no Top 10 weighting"),
        "log_sources.json": ("log-source mix", "rules won't be spread across log sources"),
        "reference_lists.json": ("reference list names",
                                 "built-in defaults are used"),
        "udm_field_schema.json": ("UDM field schema",
                                  "field checking falls back to a small built-in list"),
        cov: ("coverage spreadsheet", "generation can't run without it"),
    }
    missing_config = [{"file": f, "what": w, "effect": e}
                      for f, (w, e) in config.items() if not (HERE / f).is_file()]
    reports = sorted(r for r in SERVABLE if (HERE / r).is_file())
    return {"rules": len(names), "check": check, "chronicle": chron,
            "evidence": evid, "scripts": scripts, "reports": reports,
            "missing_config": missing_config}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:      # keep the terminal quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if u.path == "/api/state":
            s = load_settings()
            return self._json({"settings": s, **state(s)})
        if u.path == "/api/models":
            refresh = "refresh" in parse_qs(u.query)
            return self._json(fetch_models(refresh))
        if u.path == "/api/job":
            since = int(parse_qs(u.query).get("since", ["0"])[0])
            return self._json(JOB.snapshot(since))
        if u.path.startswith("/files/"):
            rel = u.path[len("/files/"):]
            if rel not in SERVABLE:
                return self._send(404, b"Not available", "text/plain")
            f = HERE / rel
            if not f.is_file():
                return self._send(404, b"Not generated yet", "text/plain")
            ctype = ("text/html; charset=utf-8" if rel.endswith(".html")
                     else "application/json" if rel.endswith(".json")
                     else "text/csv; charset=utf-8")
            return self._send(200, f.read_bytes(), ctype)
        self._send(404, b"Not found", "text/plain")

    def do_POST(self) -> None:
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if u.path == "/api/run":
            s = load_settings()
            s.update(body.get("settings", {}))
            save_settings(s)
            try:
                name, argv, stdin_text, env = build(body["stage"], s)
            except Exception as e:
                return self._json({"error": str(e)}, 400)
            if not (HERE / argv[0]).is_file():
                return self._json({"error": f"{argv[0]} isn't in {HERE}. "
                                   f"Put it beside this file."}, 400)
            err = JOB.start(name, argv, stdin_text, env)
            return self._json({"error": err} if err else {"ok": True, "name": name})
        if u.path == "/api/settings":
            s = load_settings()
            s.update(body.get("settings", {}))
            save_settings(s)
            return self._json({"ok": True})
        if u.path == "/api/cancel":
            JOB.cancel()
            return self._json({"ok": True})
        self._send(404, b"Not found", "text/plain")


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection rule pipeline</title>
<style>
:root{
  --ground:#EEF1F4; --surface:#FFFFFF; --ink:#14202E; --muted:#5B6878;
  --rule:#D5DBE2; --accent:#4B286D; --accent-soft:#EFE9F5;
  --pass:#2E7D4F; --warn:#A8701A; --fail:#B23A3A;
  --console:#1B2430; --console-ink:#D6DEE7;
  --radius:6px;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--ground);color:var(--ink);
  font:15px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
  display:grid;grid-template-rows:auto 1fr;}
header{display:flex;align-items:baseline;gap:18px;padding:14px 24px;
  background:var(--surface);border-bottom:1px solid var(--rule)}
header h1{margin:0;font-size:18px;font-weight:600;letter-spacing:-.01em}
header .lib{color:var(--muted);font-size:14px;display:flex;align-items:baseline;gap:8px}
header .lib b{color:var(--ink);font-weight:600}
header .lib input{width:150px;padding:4px 8px;font-size:14px}
.app{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:0}

/* --- the pipeline rail: the one memorable element --- */
nav{background:var(--surface);border-right:1px solid var(--rule);padding:18px 0;overflow:auto}
nav ol{list-style:none;margin:0;padding:0;counter-reset:s}
nav li{counter-increment:s}
nav button{all:unset;box-sizing:border-box;display:grid;
  grid-template-columns:30px 1fr;column-gap:10px;width:100%;
  padding:12px 20px;cursor:pointer;position:relative}
nav button::before{content:counter(s);grid-row:1/3;align-self:start;
  width:26px;height:26px;border-radius:50%;display:grid;place-items:center;
  font-size:13px;font-weight:600;border:1.5px solid var(--rule);color:var(--muted);
  background:var(--surface);position:relative;z-index:1}
nav li:not(:last-child) button::after{content:"";position:absolute;left:32px;
  top:38px;bottom:-12px;width:1.5px;background:var(--rule)}
nav .t{font-weight:600;font-size:15px}
nav .r{font-size:13px;color:var(--muted);grid-column:2}
nav button:hover{background:#F6F8FA}
nav button:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
nav button[aria-current="step"]{background:var(--accent-soft)}
nav button[aria-current="step"]::before{background:var(--accent);
  border-color:var(--accent);color:#fff}
.r .ok{color:var(--pass)} .r .bad{color:var(--fail)} .r .mid{color:var(--warn)}

main{display:grid;grid-template-rows:minmax(0,1fr) clamp(190px,30vh,330px);min-height:0}
.panel{padding:22px 28px 0;overflow:auto;border-bottom:1px solid var(--rule)}
.panel h2{margin:0 0 4px;font-size:20px;font-weight:600;letter-spacing:-.01em}
.panel .lede{margin:0 0 20px;color:var(--muted);max-width:68ch}
section[hidden]{display:none}

.fields{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));
  gap:16px 22px;max-width:960px}
.f{display:flex;flex-direction:column;gap:5px}
.f.wide{grid-column:1/-1}
.f label{font-size:14px;font-weight:600}
.f .h{font-size:13px;color:var(--muted)}
.f .h a{color:var(--accent);font-weight:600}
input[type=text],input[type=number],select{font:inherit;padding:8px 10px;
  border:1px solid var(--rule);border-radius:var(--radius);background:var(--surface);
  color:var(--ink);min-width:0}
input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:1px;
  border-color:var(--accent)}
.check{flex-direction:row;align-items:center;gap:9px}
.check input{width:17px;height:17px;accent-color:var(--accent)}
.check label{font-weight:400}
fieldset{border:0;padding:0;margin:0;min-width:0}  /* fieldsets won't shrink otherwise */

.actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap;
  position:sticky;bottom:0;margin:22px -28px 0;padding:14px 28px;
  background:var(--ground);border-top:1px solid var(--rule)}
.btn{font:inherit;font-weight:600;padding:9px 18px;border-radius:var(--radius);
  border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}
.btn.quiet{background:var(--surface);color:var(--accent)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.note{font-size:13px;color:var(--muted)}
.links{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.links a{color:var(--accent);font-size:14px;font-weight:600}
.warnbox{margin-top:16px;padding:10px 14px;border-left:3px solid var(--warn);
  background:#FBF6EC;font-size:14px;max-width:760px}

/* --- console: the source of truth --- */
.console{display:grid;grid-template-rows:auto 1fr;min-height:0;background:var(--console)}
.cbar{display:flex;align-items:center;gap:14px;padding:9px 20px;color:var(--console-ink);
  font-size:14px;border-bottom:1px solid #2A3544}
.cbar .st{font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;background:#56657A}
.dot.run{background:#E0B24A;animation:p 1.1s ease-in-out infinite}
.dot.done{background:#5FB87E} .dot.err{background:#E06A6A}
@keyframes p{50%{opacity:.35}}
@media (prefers-reduced-motion:reduce){.dot.run{animation:none}}
.cbar .sp{margin-left:auto}
pre{margin:0;padding:12px 20px 20px;overflow:auto;color:var(--console-ink);
  font:13px/1.45 ui-monospace,"Cascadia Mono",Consolas,monospace;white-space:pre-wrap}
pre .e{color:#F09A9A} pre .w{color:#E8C074} pre .g{color:#8FD4A6}

header{flex-wrap:wrap;row-gap:6px}
@media (max-width:820px){
  /* Narrow screens: drop the fixed-height split and let the page scroll. */
  body,.app,main{display:block}
  header{padding:12px 16px}
  nav{border-right:0;border-bottom:1px solid var(--rule);padding:8px 0}
  nav button{padding:9px 16px}
  .panel{overflow:visible;padding:18px 16px 0}
  .actions{position:static;margin:22px -16px 0;padding:12px 16px}
  .console{height:320px}
}
</style></head><body>
<header><h1>Detection rule pipeline</h1>
  <span class="lib"><span id="lib">Loading library</span>
  <label for="rules_dir">in folder</label><input type="text" id="rules_dir"></span></header>
<div class="app">
<nav aria-label="Pipeline stages"><ol>
  <li><button data-s="generate"><span class="t">Generate</span><span class="r" id="r-generate"></span></button></li>
  <li><button data-s="check"><span class="t">Check</span><span class="r" id="r-check"></span></button></li>
  <li><button data-s="verify"><span class="t">Verify with Chronicle</span><span class="r" id="r-verify"></span></button></li>
  <li><button data-s="evidence"><span class="t">Test against attacks</span><span class="r" id="r-evidence"></span></button></li>
  <li><button data-s="reports"><span class="t">Reports</span><span class="r" id="r-reports"></span></button></li>
</ol></nav>

<main>
<div class="panel">
<div class="warnbox" id="cfgwarn" hidden style="margin:0 0 18px"></div>

<section id="p-generate">
  <h2>Generate rules</h2>
  <p class="lede">Writes detection rules for gaps in your coverage, weighted toward the
  techniques behind most of your incidents. Already-generated rules are skipped, so you
  can run this in batches.</p>
  <div class="warnbox" id="bigrun" hidden style="margin:0 0 18px"></div>
  <div class="fields">
    <div class="f"><label for="language">Rule language</label>
      <select id="language"><option value="2">YARA-L (Google SecOps)</option>
      <option value="1">KQL (Microsoft Sentinel)</option></select></div>
    <div class="f"><label for="coverage_file">Coverage spreadsheet</label>
      <input type="text" id="coverage_file"></div>
    <div class="f"><label for="mode">What to generate</label>
      <select id="mode"><option value="1">Whole library</option>
      <option value="2">Specific techniques</option></select></div>
    <div class="f"><label for="count">Rules in this batch</label>
      <input type="number" id="count" min="1" max="5000">
      <span class="h" id="eta">About 3.5 minutes per 10 rules</span></div>
    <div class="f"><label for="model">Model</label>
      <select id="model"><option value="">Loading models</option></select>
      <span class="h" id="model-note"><a href="#" id="model-refresh">Refresh list</a></span></div>
  </div>
  <fieldset id="auto-opts" style="margin-top:18px"><div class="fields">
    <div class="f"><label for="depth_covered">Rules per covered Top 10 technique</label>
      <input type="number" id="depth_covered" min="0" max="7"></div>
    <div class="f"><label for="depth_gap">Rules per uncovered Top 10 technique</label>
      <input type="number" id="depth_gap" min="0" max="7"></div>
    <div class="f"><label for="depth_tail">Rules per other uncovered technique</label>
      <input type="number" id="depth_tail" min="0" max="7"></div>
    <div class="f"><label for="depth_covered_tail">Rules per other covered technique</label>
      <input type="number" id="depth_covered_tail" min="0" max="6">
      <span class="h">Techniques you already detect, outside the Top 10. 0 skips them.</span></div>
    <div class="f"><label for="platform_scope">Platforms</label>
      <select id="platform_scope"><option value="2">Common in client environments</option>
      <option value="1">Everything ATT&amp;CK lists</option>
      <option value="3">Windows only</option></select></div>
  </div></fieldset>
  <fieldset id="manual-opts" hidden style="margin-top:18px"><div class="fields">
    <div class="f wide"><label for="manual_techniques">Technique IDs</label>
      <input type="text" id="manual_techniques" placeholder="T1078, T1003.001">
      <span class="h">Separate with commas. Retired IDs such as T1562 are translated.</span></div>
    <div class="f"><label for="manual_count">Rules per technique</label>
      <input type="number" id="manual_count" min="1" max="7"></div>
  </div></fieldset>
  <div class="fields" style="margin-top:14px">
    <div class="f check"><input type="checkbox" id="resume"><label for="resume">Skip rules already generated</label></div>
    <div class="f check"><input type="checkbox" id="include_subs"><label for="include_subs">Include sub-techniques</label></div>
    <div class="f check"><input type="checkbox" id="balance"><label for="balance">Spread rules across platforms</label></div>
  </div>
  <div class="actions"><button class="btn" data-run="generate">Generate rules</button>
    <span class="note">Your API key comes from the .env file.</span></div>
</section>

<section id="p-check" hidden>
  <h2>Check rules</h2>
  <p class="lede">Reads every rule on disk and flags invalid syntax, fields that don't exist
  in UDM, reference lists your tenant doesn't have, and banned indicators. Nothing is sent
  anywhere.</p>
  <div class="fields"><div class="f check"><input type="checkbox" id="fix">
    <label for="fix">Apply automatic fixes to the rule files</label></div></div>
  <div class="actions"><button class="btn" data-run="check">Check rules</button></div>
</section>

<section id="p-verify" hidden>
  <h2>Verify with Chronicle</h2>
  <p class="lede">Sends rules to your SecOps tenant's own compiler. This is the only check
  that knows what exists in your environment. Rules are compiled, never saved or enabled.</p>
  <div class="fields">
    <div class="f"><label for="verify_limit">Rules per pass</label>
      <input type="number" id="verify_limit" min="1" max="1000">
      <span class="h">Chronicle has a quota. Run again to continue where it stopped.</span></div>
    <div class="f check"><input type="checkbox" id="recheck">
      <label for="recheck">Re-verify rules already confirmed</label></div>
  </div>
  <div class="actions"><button class="btn" data-run="verify">Verify rules</button>
    <button class="btn quiet" data-run="connection">Test connection</button></div>
  <div class="warnbox">Needs the VPN, and a working token from your .env. If every rule
  fails the same way, test the connection first.</div>
</section>

<section id="p-evidence" hidden>
  <h2>Test against attacks</h2>
  <p class="lede">Runs your rules against synthetic attack telemetry from EvidenceForge and
  scores each one: did it catch the attack, and how often does it fire on normal activity?
  Nothing is ingested into your SIEM.</p>
  <div class="fields">
    <div class="f wide"><label for="ef_dir">EvidenceForge output folder</label>
      <input type="text" id="ef_dir" placeholder="C:\...\EvidenceForge-main\output"></div>
    <div class="f wide"><label for="scenario">Scenario file</label>
      <input type="text" id="scenario" placeholder="Found automatically when left blank"></div>
    <div class="f check"><input type="checkbox" id="ef_local">
      <label for="ef_local">Use built-in log parsing</label></div>
  </div>
  <div class="actions"><button class="btn" data-run="evidence">Run attack test</button></div>
  <div class="warnbox">Correlation rules aren't evaluated, and only Windows logs are read
  today. A missed technique that ran on a Linux host is a limit of this test, not
  necessarily of the rule.</div>
</section>

<section id="p-reports" hidden>
  <h2>Reports</h2>
  <p class="lede">Turn the library into something you can hand to someone.</p>
  <div class="actions" style="margin-top:0">
    <button class="btn" data-run="status">Status report</button>
    <button class="btn quiet" data-run="heatmap">Coverage heatmap</button>
    <button class="btn quiet" data-run="newlist">Review sheet</button>
    <button class="btn quiet" data-run="export">Export for validator</button>
  </div>
  <div class="links" id="links"></div>
</section>

</div>

<div class="console" aria-live="polite">
  <div class="cbar"><span class="dot" id="dot"></span>
    <span class="st" id="st">Nothing running</span><span id="el"></span>
    <span class="sp"></span>
    <button class="btn quiet" id="cancel" disabled style="padding:5px 12px">Cancel</button></div>
  <pre id="log">Choose a stage and run it. Output appears here.</pre>
</div>
</main></div>

<script>
const $ = id => document.getElementById(id);
const FIELDS = ["language","coverage_file","mode","count","model","depth_covered","depth_gap",
  "depth_tail","depth_covered_tail","platform_scope","manual_techniques","manual_count","resume",
  "include_subs","balance","fix","verify_limit","recheck","ef_dir","scenario",
  "ef_local","rules_dir"];
const REPORT_NAMES = {"status_report.html":"Status report","check_report.html":"Check results",
  "evidence_report.html":"Attack test results","heatmap/coverage_heatmap.html":"Coverage heatmap",
  "new_list.csv":"Review sheet (CSV)","rules_for_validation.csv":"Validator export (CSV)",
  "check_report.csv":"Check results (CSV)","evidence_report.csv":"Attack test (CSV)",
  "heatmap/attack_layer.json":"ATT&CK Navigator layer"};
let since = 0, polling = null;

function show(stage){
  document.querySelectorAll("nav button").forEach(b =>
    b.setAttribute("aria-current", b.dataset.s===stage ? "step" : "false"));
  document.querySelectorAll(".panel section").forEach(s =>
    s.hidden = s.id !== "p-"+stage);
}
document.querySelectorAll("nav button").forEach(b =>
  b.addEventListener("click", () => show(b.dataset.s)));

$("mode").addEventListener("change", () => {
  const manual = $("mode").value === "2";
  $("auto-opts").hidden = manual; $("manual-opts").hidden = !manual;
});

function collect(){
  const s = {};
  FIELDS.forEach(k => { const el = $(k); if(!el) return;
    s[k] = el.type==="checkbox" ? el.checked
         : el.type==="number" ? Number(el.value) : el.value; });
  s.manual_include_subs = s.include_subs;
  return s;
}
function fill(s){
  FIELDS.forEach(k => { const el = $(k); if(!el || s[k]===undefined) return;
    if(el.type==="checkbox") el.checked = !!s[k]; else el.value = s[k]; });
  $("mode").dispatchEvent(new Event("change"));
}

function pct(n,d){ return d ? Math.round(100*n/d) : 0; }
function summarise(st){
  $("lib").innerHTML = st.rules ? `<b>${st.rules}</b> rules` : "No rules yet";
  $("r-generate").textContent = st.rules ? `${st.rules} rules` : "Not run";
  const c = st.check, ct = Object.values(c).reduce((a,b)=>a+b,0);
  const fix = (c["must-fix"]||0)+(c["compile-error"]||0), rev = c.review||0;
  const parts = [`<span class="ok">${c.clean||0} clean</span>`];
  if(rev) parts.push(`<span class="mid">${rev} to review</span>`);
  if(fix) parts.push(`<span class="bad">${fix} to fix</span>`);
  $("r-check").innerHTML = ct ? parts.join(", ") : "Not run";
  const v = st.chronicle, vok = v.compiles||0, vbad = v.FAILED||0;
  $("r-verify").innerHTML = (vok+vbad) ?
    `<span class="${vbad ? "mid" : "ok"}">${vok} of ${vok+vbad}</span> compile` : "Not run";
  const e = st.evidence;
  const det = (e.DETECTED||0)+(e["DETECTED+NOISY"]||0), noisy=(e.NOISY||0)+(e["DETECTED+NOISY"]||0);
  const ep = [`<span class="ok">${det} caught</span>`];
  if(e.MISSED) ep.push(`<span class="bad">${e.MISSED} missed</span>`);
  if(noisy) ep.push(`<span class="mid">${noisy} noisy</span>`);
  $("r-evidence").innerHTML = Object.keys(e).length ? ep.join(", ") : "Not run";
  $("r-reports").textContent = st.reports.length ? `${st.reports.length} available` : "None yet";
  $("links").innerHTML = st.reports.map(r =>
    `<a href="/files/${r}" target="_blank" rel="noopener">${REPORT_NAMES[r]||r}</a>`).join("");
  const missing = Object.entries(st.scripts).filter(([,ok])=>!ok).map(([n])=>n);
  const msgs = [];
  if(missing.length) msgs.push("These scripts aren't in this folder, so their stages won't run:\n  "
                               + missing.join("\n  "));
  if(st.missing_config.length) msgs.push("Missing files - things will still run, but:\n"
    + st.missing_config.map(m => `  ${m.file} (${m.what}): ${m.effect}`).join("\n"));
  const box = $("cfgwarn");
  box.hidden = !st.missing_config.length;
  box.innerHTML = st.missing_config.length ? "<b>Missing files.</b> " +
    st.missing_config.map(m => `<span>${m.file}: ${m.effect}.</span>`).join(" ") : "";
  if(msgs.length && !$("log").dataset.used) $("log").textContent = msgs.join("\n\n");
}
async function refresh(){
  const st = await (await fetch("/api/state")).json();
  summarise(st); return st;
}

function paint(line){
  const esc = line.replace(/&/g,"&amp;").replace(/</g,"&lt;");
  if(/FAIL|ERROR|Traceback|FATAL|MUST FIX|COMPILE ERROR/.test(line)) return `<span class="e">${esc}</span>`;
  if(/WARN|review|NOISY|MISSED|INCONCLUSIVE/.test(line)) return `<span class="w">${esc}</span>`;
  if(/\bOK\b|compiles|DETECTED|Wrote |Done in|SUCCESS/.test(line)) return `<span class="g">${esc}</span>`;
  return esc;
}
async function poll(){
  const j = await (await fetch("/api/job?since="+since)).json();
  if(j.lines.length){
    const log = $("log"), atEnd = log.scrollTop+log.clientHeight >= log.scrollHeight-40;
    if(since===0) log.innerHTML = "";
    log.insertAdjacentHTML("beforeend", j.lines.map(paint).join("\n")+"\n");
    since = j.total; if(atEnd) log.scrollTop = log.scrollHeight;
  }
  const m = Math.floor(j.elapsed/60), sec = String(j.elapsed%60).padStart(2,"0");
  $("el").textContent = j.name ? `${m}:${sec}` : "";
  if(j.running){ $("dot").className="dot run"; $("st").textContent = j.name+" running"; }
  else if(j.name){
    const ok = j.exit_code===0;
    $("dot").className = "dot "+(ok?"done":"err");
    $("st").textContent = j.name + (ok ? " finished" : ` stopped (exit ${j.exit_code})`);
  }
  $("cancel").disabled = !j.running;
  document.querySelectorAll("[data-run]").forEach(b => b.disabled = j.running);
  if(!j.running && polling){ clearInterval(polling); polling=null; refresh(); }
}

document.querySelectorAll("[data-run]").forEach(b => b.addEventListener("click", async () => {
  if(b.dataset.run==="evidence" && !$("ef_dir").value.trim()){
    $("ef_dir").focus(); $("log").textContent = "Enter the EvidenceForge output folder first.";
    return;
  }
  const r = await fetch("/api/run",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({stage:b.dataset.run, settings:collect()})});
  const res = await r.json();
  if(res.error){ $("log").textContent = res.error; return; }
  since = 0; $("log").dataset.used = "1"; $("log").textContent = "Starting "+res.name+"\n";
  if(!polling) polling = setInterval(poll, 900);
  poll();
}));
$("cancel").addEventListener("click", () => fetch("/api/cancel",{method:"POST"}));

// The model this pipeline's prompt and validator were tuned and verified against.
const VALIDATED = "claude-sonnet-4-5";
let MODELS = {models: [], default: ""};
async function loadModels(refresh){
  const sel = $("model"), keep = sel.value || window._savedModel || "";
  sel.innerHTML = '<option value="">Loading models</option>';
  MODELS = await (await fetch("/api/models" + (refresh ? "?refresh=1" : ""))).json();
  const def = MODELS.default ? ` (${MODELS.default})` : "";
  sel.innerHTML = [`<option value="">Default from .env${def}</option>`]
    .concat(MODELS.models.map(m =>
      `<option value="${m}">${m}${m===VALIDATED ? " - validated" : ""}</option>`)).join("");
  if([...sel.options].some(o => o.value===keep)) sel.value = keep;
  modelNote();
}
function modelNote(){
  const chosen = $("model").value || MODELS.default;
  let html = MODELS.error ? `${MODELS.error} ` : `${MODELS.models.length} available. `;
  if(chosen && chosen !== VALIDATED)
    html = `<b>Not validated with this pipeline.</b> Run 10 and check them before a big batch. `;
  $("model-note").innerHTML = html + `<a href="#" id="model-refresh">Refresh list</a>`;
  $("model-refresh").onclick = e => { e.preventDefault(); loadModels(true); };
}
$("model").addEventListener("change", modelNote);

// Measured: about 21 seconds per rule with the validated model.
function estimate(){
  const n = Number($("count").value) || 0, secs = n * 21;
  const h = Math.floor(secs/3600), m = Math.round((secs%3600)/60);
  $("eta").textContent = n ? `About ${h ? h + " h " : ""}${m} min at the measured pace` : "";
  const big = $("bigrun");
  big.hidden = n < 300;
  if(n >= 300) big.innerHTML = `<b>This is a long run.</b> Stop your laptop sleeping, `+
    `and stay on the VPN. If it drops, the run stops itself after five failures - `+
    `start it again with "Skip rules already generated" ticked and it carries on. `+
    `Above about 5 rules per technique, expect more rules flagged as duplicates.`;
}
$("count").addEventListener("input", estimate);
$("rules_dir").addEventListener("change", async () => {
  await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({settings:collect()})});
  refresh();
});

(async () => {
  const st = await refresh(); window._savedModel = st.settings.model || "";
  fill(st.settings); show("generate"); estimate(); loadModels(false);
  const j = await (await fetch("/api/job?since=0")).json();
  if(j.running){ polling = setInterval(poll, 900); }
})();
</script></body></html>"""


def main() -> None:
    port = 8765
    for p in range(8765, 8775):
        try:
            server = ThreadingHTTPServer((HOST, p), Handler)
            port = p
            break
        except OSError:
            continue
    else:
        sys.exit("Couldn't find a free port between 8765 and 8774.")
    url = f"http://{HOST}:{port}"
    print(f"Detection rule pipeline running at {url}")
    print("Reachable from this machine only. Press Ctrl+C to stop.")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        JOB.cancel()
        print("\nStopped.")


if __name__ == "__main__":
    main()
