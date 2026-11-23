#!/usr/bin/env python3
"""
evidence_test.py
================
Test generated YARA-L rules against realistic synthetic attack telemetry from
Cisco Talos EvidenceForge - WITHOUT ingesting anything into your SIEM.

Why not just ingest?  Loading synthetic attack data (credential dumping,
lateral movement) into a production tenant can raise real alerts and send
analysts after an intrusion that never happened. This tool never ingests.

Pipeline
--------
  1. EvidenceForge   -> raw native logs (Sysmon, Windows Security XML)
  2. Normalise to UDM:
       - Chronicle mode (preferred): Chronicle's OWN parser, via the run_parser
         API. Authoritative field mapping. Parses in-memory; stores nothing.
       - Local mode (fallback): a built-in approximate Sysmon/Security -> UDM
         mapping. Good enough to find obviously broken or noisy rules.
  3. Evaluate each single-event rule against the UDM events locally.
  4. Score against EvidenceForge ground truth:
       - DETECTED  : fired on events from a malicious storyline step
       - NOISY     : fired on a large share of benign background activity
       - SILENT    : fired on nothing (fine if its technique is absent)

Limitations - be explicit about these when reporting results
-----------------------------------------------------------
  * Rule evaluation is local, not Chronicle's rule engine. Single-event rules
    are evaluated faithfully for common predicate forms; correlation rules
    (multiple event variables joined over a window) are NOT evaluated and are
    reported as such.
  * Reference lists are treated as EMPTY (matching your current tenant), so
    `not ... in %list` always passes and `... in %list` never does.
  * Coverage is only as good as the scenario: a rule for a technique the
    scenario doesn't contain will correctly be SILENT.

Usage
-----
  python evidence_test.py --probe                 # check Chronicle parser access
  python evidence_test.py                         # run the test
  python evidence_test.py --local                 # force local normalisation
  python evidence_test.py --sample 3000           # background events to test

Requires: EvidenceForge output directory (from `eforge generate ...`).
"""
from __future__ import annotations

import base64
import collections
import hashlib
import html
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import gap_ruleforge as G          # reuse .env loading + config
except ImportError:
    sys.exit("Run this from the same folder as gap_ruleforge.py")


# ---------------------------------------------------------------------------
# 1. Extract raw events from EvidenceForge output
# ---------------------------------------------------------------------------
FORMATS = {
    # file name in each host dir      -> Chronicle log type
    "windows_event_sysmon.xml":   "WINDOWS_SYSMON",
    "windows_event_security.xml": "WINEVTLOG",
}
EVENT_RE = re.compile(r"<Event[\s>].*?</Event>", re.S)


def extract_raw(ef_dir: Path) -> dict[str, list[dict]]:
    """Return {log_type: [{"raw": str, "host": str}, ...]}."""
    out: dict[str, list[dict]] = collections.defaultdict(list)
    data = ef_dir / "data"
    if not data.is_dir():
        sys.exit(f"No data/ folder in {ef_dir} - is this EvidenceForge output?")
    for host_dir in sorted(p for p in data.iterdir() if p.is_dir()):
        for fname, log_type in FORMATS.items():
            f = host_dir / fname
            if not f.is_file():
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            for m in EVENT_RE.finditer(text):
                out[log_type].append({"raw": m.group(0), "host": host_dir.name})
    return out


# ---------------------------------------------------------------------------
# 2a. Local (approximate) native -> UDM normalisation
# ---------------------------------------------------------------------------
def _xml_fields(raw: str) -> dict[str, str]:
    """Pull EventID, Computer, TimeCreated and every <Data Name=..> value."""
    f: dict[str, str] = {}
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", raw)
    if m:
        f["EventID"] = m.group(1)
    m = re.search(r"<Computer>(.*?)</Computer>", raw)
    if m:
        f["Computer"] = m.group(1)
    m = re.search(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]", raw)
    if m:
        f["TimeCreated"] = m.group(1)
    for n, v in re.findall(r"<Data Name=['\"]([^'\"]+)['\"]>(.*?)</Data>", raw, re.S):
        f[n] = html.unescape(v)
    return f


def _set(d: dict, path: str, value) -> None:
    if value in (None, "", "-"):
        return
    cur = d
    parts = path.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _ts(s: str | None) -> int | None:
    """ISO-8601 (with or without Z / fractional seconds) -> epoch seconds."""
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)", s)
    if not m:
        return None
    tz = m.group(3) or "+00:00"
    try:
        return int(datetime.fromisoformat(m.group(1) + tz).timestamp())
    except ValueError:
        return None


def local_to_udm(raw: str, log_type: str) -> dict | None:
    f = _xml_fields(raw)
    eid = f.get("EventID")
    if not eid:
        return None
    u: dict = {}
    _set(u, "principal.hostname", f.get("Computer"))
    secs = _ts(f.get("TimeCreated"))
    if secs:
        _set(u, "metadata.event_timestamp.seconds", secs)
    _set(u, "metadata.product_event_type", eid)

    if log_type == "WINDOWS_SYSMON":
        if eid == "1":
            _set(u, "metadata.event_type", "PROCESS_LAUNCH")
            _set(u, "target.process.file.full_path", f.get("Image"))
            _set(u, "target.process.command_line", f.get("CommandLine"))
            _set(u, "target.process.pid", f.get("ProcessId"))
            _set(u, "principal.process.file.full_path", f.get("ParentImage"))
            _set(u, "principal.process.command_line", f.get("ParentCommandLine"))
            _set(u, "principal.user.userid", f.get("User"))
        elif eid == "3":
            _set(u, "metadata.event_type", "NETWORK_CONNECTION")
            _set(u, "principal.process.file.full_path", f.get("Image"))
            _set(u, "principal.ip", f.get("SourceIp"))
            _set(u, "principal.port", f.get("SourcePort"))
            _set(u, "target.ip", f.get("DestinationIp"))
            _set(u, "target.port", f.get("DestinationPort"))
            _set(u, "target.hostname", f.get("DestinationHostname"))
            _set(u, "principal.user.userid", f.get("User"))
        elif eid == "10":
            _set(u, "metadata.event_type", "PROCESS_OPEN")
            _set(u, "principal.process.file.full_path", f.get("SourceImage"))
            _set(u, "target.process.file.full_path", f.get("TargetImage"))
            _set(u, "target.process.access_mask", f.get("GrantedAccess"))
        elif eid == "11":
            _set(u, "metadata.event_type", "FILE_CREATION")
            _set(u, "principal.process.file.full_path", f.get("Image"))
            _set(u, "target.file.full_path", f.get("TargetFilename"))
        elif eid in ("12", "13", "14"):
            _set(u, "metadata.event_type",
                 "REGISTRY_CREATION" if eid == "12" else "REGISTRY_MODIFICATION")
            _set(u, "principal.process.file.full_path", f.get("Image"))
            _set(u, "target.registry.registry_key", f.get("TargetObject"))
            _set(u, "target.registry.registry_value_data", f.get("Details"))
        elif eid == "22":
            _set(u, "metadata.event_type", "NETWORK_DNS")
            _set(u, "principal.process.file.full_path", f.get("Image"))
            _set(u, "network.dns.questions.name", f.get("QueryName"))
        elif eid == "7":
            _set(u, "metadata.event_type", "PROCESS_MODULE_LOAD")
            _set(u, "principal.process.file.full_path", f.get("Image"))
            _set(u, "target.file.full_path", f.get("ImageLoaded"))
        else:
            _set(u, "metadata.event_type", "GENERIC_EVENT")
    else:  # WINEVTLOG (Windows Security)
        if eid == "4688":
            _set(u, "metadata.event_type", "PROCESS_LAUNCH")
            _set(u, "target.process.file.full_path", f.get("NewProcessName"))
            _set(u, "target.process.command_line", f.get("CommandLine"))
            _set(u, "principal.process.file.full_path", f.get("ParentProcessName"))
            _set(u, "principal.user.userid", f.get("SubjectUserName"))
        elif eid in ("4624", "4625"):
            _set(u, "metadata.event_type", "USER_LOGIN")
            _set(u, "target.user.userid", f.get("TargetUserName"))
            _set(u, "principal.ip", f.get("IpAddress"))
            _set(u, "principal.hostname", f.get("WorkstationName") or f.get("Computer"))
            _set(u, "extensions.auth.mechanism", f.get("LogonType"))
            _set(u, "security_result.action", "BLOCK" if eid == "4625" else "ALLOW")
        elif eid == "4698":
            _set(u, "metadata.event_type", "SCHEDULED_TASK_CREATION")
            _set(u, "target.resource.name", f.get("TaskName"))
            _set(u, "principal.user.userid", f.get("SubjectUserName"))
        elif eid == "4697":
            _set(u, "metadata.event_type", "SERVICE_CREATION")
            _set(u, "target.process.file.full_path", f.get("ServiceFileName"))
            _set(u, "target.resource.name", f.get("ServiceName"))
        elif eid == "4720":
            _set(u, "metadata.event_type", "USER_CREATION")
            _set(u, "target.user.userid", f.get("TargetUserName"))
            _set(u, "principal.user.userid", f.get("SubjectUserName"))
        elif eid in ("4728", "4732", "4756"):
            _set(u, "metadata.event_type", "GROUP_MODIFICATION")
            _set(u, "target.user.userid", f.get("MemberName"))
            _set(u, "target.group.group_display_name", f.get("TargetUserName"))
        elif eid == "1102":
            _set(u, "metadata.event_type", "SETTING_MODIFICATION")
        else:
            _set(u, "metadata.event_type", "GENERIC_EVENT")
    return u


# ---------------------------------------------------------------------------
# 2b. Chronicle normalisation (authoritative) - parses, never ingests
# ---------------------------------------------------------------------------
class ChronicleNormaliser:
    BATCH = 500        # below the 1000-log API cap, to stay clear of quota

    def __init__(self) -> None:
        from secops import SecOpsClient     # noqa: imported lazily
        self.client = SecOpsClient().chronicle(
            customer_id=G.CHRONICLE_INSTANCE, project_id=G.CHRONICLE_PROJECT,
            region=G.CHRONICLE_LOCATION or "us")
        self._parser_code: dict[str, str] = {}

    def parser_code(self, log_type: str) -> str:
        if log_type in self._parser_code:
            return self._parser_code[log_type]
        parsers = self.client.list_parsers(log_type=log_type)
        if not parsers:
            raise RuntimeError(f"No parser available for log type {log_type}")
        active = next((p for p in parsers
                       if str(p.get("state", "")).upper() == "ACTIVE"), parsers[0])
        cbn = (active.get("cbn") or "")
        code = base64.b64decode(cbn).decode("utf-8") if cbn else ""
        if not code:
            raise RuntimeError(f"Parser for {log_type} returned no code")
        self._parser_code[log_type] = code
        return code

    def normalise(self, raws: list[str], log_type: str) -> list[dict | None]:
        code = self.parser_code(log_type)
        out: list[dict | None] = []
        for i in range(0, len(raws), self.BATCH):
            batch = raws[i:i + self.BATCH]
            for attempt in range(3):
                try:
                    res = self.client.run_parser(log_type=log_type, parser_code=code,
                                                 parser_extension_code=None, logs=batch)
                    break
                except Exception as e:
                    if "429" in str(e) and attempt < 2:
                        time.sleep(30 * (attempt + 1))
                        continue
                    raise
            results = res.get("runParserResults", [])
            for r in results:
                evs = r.get("parsedEvents") or []
                ev = evs[0] if evs else None
                if isinstance(ev, dict):
                    ev = ev.get("event", ev.get("udm", ev))
                out.append(ev)
            out.extend([None] * (len(batch) - len(results)))
            print(f"    parsed {min(i + self.BATCH, len(raws))}/{len(raws)} {log_type}")
        return out


# ---------------------------------------------------------------------------
# 3. Local single-event YARA-L evaluator
# ---------------------------------------------------------------------------
PRED_RE = re.compile(
    r"^(?P<neg>not\s+)?\$(?P<var>[a-z_][a-z0-9_]*)\.(?P<path>[A-Za-z0-9_.]+)\s*"
    r"(?P<op>=|!=|>=|<=|>|<)\s*"
    r"(?P<val>/(?:[^/\\]|\\.)*/|\"(?:[^\"\\]|\\.)*\"|-?\d+)"
    r"(?P<nocase>\s+nocase)?\s*$")
LIST_RE = re.compile(
    r"^(?P<neg>not\s+)?\$(?P<var>[a-z_][a-z0-9_]*)\.(?P<path>[A-Za-z0-9_.]+)\s+"
    r"(?P<notin>not\s+)?in\s+%(?P<list>[A-Za-z0-9_]+)")
FIELD_CMP_RE = re.compile(
    r"^(?P<neg>not\s+)?\$(?P<var>[a-z_][a-z0-9_]*)\.(?P<path>[A-Za-z0-9_.]+)\s*"
    r"(?P<op>=|!=)\s*\$(?P<var2>[a-z_][a-z0-9_]*)\.(?P<path2>[A-Za-z0-9_.]+)\s*$")
REGEX_FN_RE = re.compile(
    r"^(?P<neg>not\s+)?re\.regex\(\s*\$(?P<var>[a-z_][a-z0-9_]*)\.(?P<path>[A-Za-z0-9_.]+)"
    r"\s*,\s*(?P<val>`[^`]*`|/(?:[^/\\]|\\.)*/|\"(?:[^\"\\]|\\.)*\")\s*\)"
    r"(?P<nocase>\s+nocase)?\s*$")


def _values(ev: dict, path: str) -> list:
    """Resolve a dotted path; repeated fields fan out to every element."""
    cur = [ev]
    for part in path.split("."):
        nxt = []
        for c in cur:
            if isinstance(c, dict) and part in c:
                v = c[part]
                nxt.extend(v if isinstance(v, list) else [v])
            elif isinstance(c, list):
                for item in c:
                    if isinstance(item, dict) and part in item:
                        v = item[part]
                        nxt.extend(v if isinstance(v, list) else [v])
        cur = nxt
        if not cur:
            return []
    return [c for c in cur if not isinstance(c, (dict, list))]


def _compile(val: str, nocase: bool):
    if val.startswith("/") or val.startswith("`"):
        pat = val[1:-1]
        flags = re.I if nocase else 0
        if pat.startswith("(?i)"):
            pat, flags = pat[4:], re.I
        try:
            return ("re", re.compile(pat, flags))
        except re.error:
            return ("bad", None)
    if val.startswith('"'):
        s = val[1:-1].encode().decode("unicode_escape", errors="ignore")
        return ("str", s.lower() if nocase else s)
    return ("num", int(val))


class Rule:
    def __init__(self, name: str, text: str) -> None:
        # Apply the same deterministic repair the generator uses, so older rules
        # carrying /pattern/i suffix flags are evaluated as Chronicle would see
        # them after repair rather than being skipped.
        try:
            text, _ = G.fix_regex_suffix_flags(text)
        except Exception:
            pass
        self.name, self.text = name, text
        self.preds: list[tuple] = []
        self.unsupported: list[str] = []
        self.correlation = False
        self.technique = ""
        m = re.search(r'mitre_technique\s*=\s*"([^"]+)"', text)
        if m:
            self.technique = m.group(1).strip()
        self._parse()

    def _parse(self) -> None:
        m = re.search(r"events:(.*?)(?:\n\s*match:|\n\s*outcome:|\n\s*condition:)",
                      self.text, re.S)
        body = m.group(1) if m else ""
        body = re.sub(r"//[^\n]*", "", body)
        lines = [l.strip() for l in body.splitlines() if l.strip()]
        variables = set(re.findall(r"\$([a-z_][a-z0-9_]*)\.", body))
        if len(variables) > 1:
            self.correlation = True
            return
        for line in lines:
            line = line.rstrip()
            if re.search(r"=\s*\$[a-z_][a-z0-9_]*\s*$", line):
                continue                   # placeholder join - irrelevant here
            if "event_timestamp" in line:
                continue
            if (mm := PRED_RE.match(line)):
                kind, comp = _compile(mm["val"], bool(mm["nocase"]))
                self.preds.append(("cmp", bool(mm["neg"]), mm["path"], mm["op"],
                                   kind, comp, bool(mm["nocase"])))
            elif (mm := FIELD_CMP_RE.match(line)):
                self.preds.append(("field", bool(mm["neg"]), mm["path"],
                                   mm["op"], mm["path2"]))
            elif (mm := LIST_RE.match(line)):
                # Lists are empty in the tenant: `in` never matches.
                negated = bool(mm["neg"]) ^ bool(mm["notin"])
                self.preds.append(("list", negated, mm["path"]))
            elif (mm := REGEX_FN_RE.match(line)):
                kind, comp = _compile(mm["val"], bool(mm["nocase"]))
                self.preds.append(("cmp", bool(mm["neg"]), mm["path"], "=",
                                   kind, comp, bool(mm["nocase"])))
            elif line in ("and", "or") or line.startswith(("(", ")")):
                self.unsupported.append(line)
            else:
                self.unsupported.append(line)

    @property
    def evaluable(self) -> bool:
        return not self.correlation and bool(self.preds)

    def matches(self, ev: dict) -> bool:
        for p in self.preds:
            if p[0] == "field":
                _, neg, a, op, b = p
                va, vb = set(map(str, _values(ev, a))), set(map(str, _values(ev, b)))
                if not va or not vb:
                    hit = False
                else:
                    hit = bool(va & vb) if op == "=" else not (va & vb)
                if hit == neg:
                    return False
                continue
            if p[0] == "list":
                _, negated, path = p
                hit = False                 # empty list: never a member
                if hit == negated:
                    return False
                continue
            _, neg, path, op, kind, comp, nocase = p
            vals = _values(ev, path)
            if kind == "bad":
                return False
            hit = False
            for v in vals:
                if kind == "re":
                    hit = bool(comp.search(str(v)))
                elif kind == "str":
                    sv = str(v).lower() if nocase else str(v)
                    hit = {"=": sv == comp, "!=": sv != comp}.get(op, False)
                else:
                    try:
                        n = int(v)
                    except (TypeError, ValueError):
                        continue
                    hit = {"=": n == comp, "!=": n != comp, ">": n > comp,
                           "<": n < comp, ">=": n >= comp, "<=": n <= comp}[op]
                if op == "!=" and kind == "re":
                    hit = not hit
                if hit:
                    break
            if hit == neg:
                return False
        return True


# ---------------------------------------------------------------------------
# 4. Ground truth
# ---------------------------------------------------------------------------
def find_scenario(ef_dir: Path, name: str) -> Path | None:
    """Find the scenario .yaml an EvidenceForge output was generated from.

    Newer EvidenceForge writes RESOLVED_SCENARIO.yaml into its output; older
    releases don't. Fall back to the repo layout: output usually sits beside
    scenarios/<name>/scenario.yaml.
    """
    direct = ef_dir / "RESOLVED_SCENARIO.yaml"
    if direct.is_file():
        return direct
    for base in (ef_dir, *list(ef_dir.parents)[:4]):
        for cand in (base / "scenarios" / name / "scenario.yaml",
                     base / name / "scenario.yaml"):
            if cand.is_file():
                return cand
    return None


def load_ground_truth(ef_dir: Path, scenario: Path | None) -> dict:
    gt = json.loads((ef_dir / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    techniques: set[str] = set()
    # EvidenceForge writes RESOLVED_SCENARIO.yaml into its own output, so prefer
    # that - it always matches the data. Fall back to a user-supplied path.
    sources = []
    if scenario:
        sources.append(scenario)
    found = find_scenario(ef_dir, str(gt.get("scenario_name", "")))
    if found:
        sources.append(found)
    for src in sources:
        if src.is_file():
            techniques = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b",
                                        src.read_text(encoding="utf-8", errors="replace")))
            if techniques:
                break
    windows = []
    for e in gt.get("events", []):
        if e.get("ground_truth_section") != "storyline":
            continue
        secs = _ts(e.get("time"))
        if secs:
            windows.append({"t": secs, "host": str(e.get("system", "")).lower(),
                            "activity": e.get("activity", "")})
    return {"techniques": techniques, "windows": windows,
            "name": gt.get("scenario_name", ef_dir.name),
            "scenario_file": str(next((s for s in sources if s.is_file()), ""))}


def is_storyline(ev: dict, gt: dict, slack: int = 300) -> bool:
    secs = next(iter(_values(ev, "metadata.event_timestamp.seconds")), None)
    host = str(next(iter(_values(ev, "principal.hostname")), "")).lower()
    if secs is None:
        return False
    try:
        secs = int(secs)
    except (TypeError, ValueError):
        return False
    for w in gt["windows"]:
        if abs(secs - w["t"]) <= slack and (not w["host"] or w["host"] in host
                                            or host.startswith(w["host"].split(".")[0])):
            return True
    return False


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = sys.argv[1:]
    force_local = "--local" in args
    probe = "--probe" in args
    sample = 3000
    if "--sample" in args:
        sample = int(args[args.index("--sample") + 1])

    print("EvidenceForge rule tester\n")

    if probe:
        print("  Probing Chronicle parser access (parses a single event, stores nothing)")
        try:
            n = ChronicleNormaliser()
            code = n.parser_code("WINDOWS_SYSMON")
            print(f"  [ok] fetched WINDOWS_SYSMON parser ({len(code)} chars)")
            sample_ev = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                         "<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
                         "<TimeCreated SystemTime='2024-05-14T12:00:00.000Z'/>"
                         "<Computer>probe-host</Computer></System><EventData>"
                         "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
                         "<Data Name='CommandLine'>cmd.exe /c whoami</Data></EventData></Event>")
            res = n.normalise([sample_ev], "WINDOWS_SYSMON")
            print(f"  [ok] run_parser returned: "
                  f"{json.dumps(res[0])[:200] if res and res[0] else 'no event'}")
            print("\n  Chronicle mode is available - normalisation will use your "
                  "tenant's real parsers.")
        except Exception as e:
            print(f"  [!!] Chronicle parser access failed: {str(e)[:220]}")
            print("\n  The tester will fall back to local normalisation. Common causes:")
            print("    - not on VPN / proxy blocks googleapis.com")
            print("    - ADC not set: run `gcloud auth application-default login`")
            print("    - missing permission to read/run parsers (ask for Chronicle Editor)")
        return

    ef_dir = Path(input("EvidenceForge output folder: ").strip().strip('"'))
    if not (ef_dir / "GROUND_TRUTH.json").is_file():
        sys.exit(f"No GROUND_TRUTH.json in {ef_dir}")
    scen = ""
    gt_name = json.loads((ef_dir / "GROUND_TRUTH.json").read_text(
        encoding="utf-8")).get("scenario_name", "")
    auto = find_scenario(ef_dir, gt_name)
    if auto:
        print(f"  Found scenario: {auto}")
    else:
        while not scen:
            scen = input("Scenario .yaml it was generated from: ").strip().strip('"')
            if scen and not Path(scen).is_file():
                print(f"    Not found: {scen}")
                scen = ""
            elif not scen:
                print("    Needed - without it, MISSED can't be detected.")
    rules_dir = Path(input("Generated rules folder [output]: ").strip() or "output")

    gt = load_ground_truth(ef_dir, Path(scen) if scen else None)
    print(f"\n  Scenario: {gt['name']}")
    print(f"  Techniques in scenario: {', '.join(sorted(gt['techniques'])) or '(unknown)'}")
    if not gt["techniques"]:
        print("  WARNING: no techniques found - MISSED cannot be detected, so rules that")
        print("           should have fired will be reported as SILENT instead.")
    print(f"  Malicious storyline events: {len(gt['windows'])}")

    # --- load rules
    newest: dict[str, Path] = {}
    for f in sorted(rules_dir.rglob("*.yaral")):
        newest[f.name] = f
    rules = [Rule(n, p.read_text(encoding="utf-8", errors="replace"))
             for n, p in sorted(newest.items())]
    evaluable = [r for r in rules if r.evaluable]
    print(f"  Rules: {len(rules)} ({len(evaluable)} single-event evaluable, "
          f"{sum(r.correlation for r in rules)} correlation - not evaluated)")

    # --- raw events: storyline-adjacent events plus a background sample
    raw = extract_raw(ef_dir)
    total_raw = sum(len(v) for v in raw.values())
    print(f"  Raw Windows events available: {total_raw}")

    # --- normalise
    mode = "local (approximate)"
    normaliser = None
    use_chronicle = (not force_local and hasattr(G, "chronicle_configured")
                     and G.chronicle_configured())
    if use_chronicle:
        try:
            normaliser = ChronicleNormaliser()
            mode = "Chronicle run_parser (authoritative)"
        except Exception as e:
            print(f"  Chronicle unavailable ({str(e)[:90]}) - using local normalisation")
    print(f"  Normalisation: {mode}\n")

    cache_file = ef_dir / ".udm_cache.json"
    cache = {}
    if cache_file.is_file():
        try:
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            cache = {}

    events: list[dict] = []
    for log_type, items in raw.items():
        # keep everything near storyline times, sample the rest as background
        near, far = [], []
        for it in items:
            ts = _ts((re.search(r"SystemTime=['\"]([^'\"]+)", it["raw"]) or [None, None])[1])
            if ts and any(abs(ts - w["t"]) <= 600 for w in gt["windows"]):
                near.append(it)
            else:
                far.append(it)
        step = max(1, len(far) // max(1, sample // max(1, len(raw))))
        chosen = near + far[::step]

        keys = [hashlib.sha1(it["raw"].encode()).hexdigest()[:16] for it in chosen]
        todo = [(k, it) for k, it in zip(keys, chosen) if f"{mode}:{k}" not in cache]
        print(f"  {log_type}: {len(chosen)} events ({len(near)} near storyline) - "
              f"{len(todo)} to normalise, {len(chosen) - len(todo)} cached")
        if todo:
            if normaliser:
                udms = normaliser.normalise([it["raw"] for _, it in todo], log_type)
            else:
                udms = [local_to_udm(it["raw"], log_type) for _, it in todo]
            for (k, _), u in zip(todo, udms):
                cache[f"{mode}:{k}"] = u
        for k in keys:
            u = cache.get(f"{mode}:{k}")
            if u:
                events.append(u)
    cache_file.write_text(json.dumps(cache), encoding="utf-8")

    malicious = [e for e in events if is_storyline(e, gt)]
    benign = [e for e in events if not is_storyline(e, gt)]
    print(f"\n  UDM events: {len(events)} ({len(malicious)} storyline, {len(benign)} background)")

    # --- evaluate
    results = []
    for r in rules:
        row = {"rule": r.name, "technique": r.technique,
               "in_scenario": any(r.technique.startswith(t) or t.startswith(r.technique)
                                  for t in gt["techniques"]) if r.technique else False}
        if r.correlation:
            row.update(verdict="NOT EVALUATED", reason="correlation rule",
                       mal=0, ben=0, precision="")
        elif not r.preds:
            row.update(verdict="NOT EVALUATED",
                       reason="no supported predicates", mal=0, ben=0, precision="")
        else:
            mal = sum(1 for e in malicious if r.matches(e))
            ben = sum(1 for e in benign if r.matches(e))
            # Precision is the SOC-relevant measure: of the times this rule
            # fires, how often is it real? Dividing background hits by ALL
            # background events understates noise badly, because most events
            # (registry, network, logons) are a different type from the one
            # the rule targets.
            precision = mal / (mal + ben) if (mal + ben) else 0.0
            etype = next((pp[5] for pp in r.preds if pp[0] == "cmp"
                          and pp[2] == "metadata.event_type" and pp[4] == "str"), None)
            same_type = [e for e in benign
                         if not etype or etype in _values(e, "metadata.event_type")]
            type_rate = ben / max(1, len(same_type))
            if mal and precision >= 0.5:
                v, why = "DETECTED", f"{mal} storyline hit(s), {precision:.0%} precision"
            elif mal:
                v, why = ("DETECTED+NOISY",
                          f"{mal} storyline vs {ben} benign - {precision:.0%} precision")
            elif ben >= 10 or type_rate >= 0.01:
                v, why = ("NOISY", f"{ben} benign hits, no storyline "
                          f"({type_rate:.1%} of {etype or 'all'} events)")
            elif ben:
                v, why = "LOW-VOLUME", f"{ben} benign hit(s), no storyline"
            elif row["in_scenario"]:
                v, why = "MISSED", "technique is in the scenario but rule never fired"
            else:
                v, why = "SILENT", "no matches (technique not in scenario)"
            row["precision"] = round(precision, 3)
            if r.unsupported:
                # Predicates are AND-ed, so skipping any makes the rule match a
                # SUPERSET of what it really matches.
                #   - superset matched nothing  -> real rule matches nothing (reliable)
                #   - superset matched something -> only an upper bound (not reliable)
                if mal or ben:
                    v = "INCONCLUSIVE"
                    why = (f"upper bound only: {mal} storyline / {ben} benign with "
                           f"{len(r.unsupported)} condition(s) not evaluated - real "
                           f"rule matches at most this")
                else:
                    why += (f" | reliable despite {len(r.unsupported)} unevaluated "
                            f"condition(s): a looser version still matched nothing")
            row.update(verdict=v, reason=why, mal=mal, ben=ben)
        results.append(row)

    # --- report
    counts = collections.Counter(x["verdict"] for x in results)
    print("\n  Results:")
    for k in ("DETECTED", "DETECTED+NOISY", "MISSED", "NOISY", "LOW-VOLUME",
              "SILENT", "INCONCLUSIVE", "NOT EVALUATED"):
        if counts.get(k):
            print(f"    {counts[k]:>5}  {k}")

    order = {"MISSED": 0, "NOISY": 1, "DETECTED+NOISY": 2, "DETECTED": 3,
             "LOW-VOLUME": 4, "SILENT": 5, "INCONCLUSIVE": 6, "NOT EVALUATED": 7}
    colour = {"DETECTED": "#2e7d32", "DETECTED+NOISY": "#ef6c00", "MISSED": "#c62828",
              "NOISY": "#ef6c00", "LOW-VOLUME": "#6d6d6d", "SILENT": "#9e9e9e",
              "INCONCLUSIVE": "#7b61a8", "NOT EVALUATED": "#9e9e9e"}
    trs = "".join(
        f"<tr><td>{html.escape(x['rule'])}</td><td>{html.escape(x['technique'])}</td>"
        f"<td>{'yes' if x['in_scenario'] else ''}</td>"
        f"<td style='color:{colour[x['verdict']]};font-weight:600'>{x['verdict']}</td>"
        f"<td>{x['mal']}</td><td>{x['ben']}</td><td>{html.escape(x['reason'])}</td></tr>"
        for x in sorted(results, key=lambda x: (order[x["verdict"]], x["rule"])))
    cards = "".join(
        f"<div class='c'><div class='n' style='color:{colour[k]}'>{counts.get(k,0)}</div>"
        f"<div class='l'>{k}</div></div>" for k in order if counts.get(k))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    page = f"""<!doctype html><html><head><meta charset='utf-8'>
<title>EvidenceForge rule test</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f5f7}}
header{{background:#0a2540;color:#fff;padding:18px 26px}}h1{{margin:0;font-size:19px}}
.w{{padding:18px 26px}}.cs{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}}
.c{{background:#fff;border:1px solid #e6e8ec;border-radius:10px;padding:12px 18px}}
.n{{font-size:24px;font-weight:700}}.l{{font-size:11px;color:#667;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;background:#fff;font-size:12px}}
th,td{{padding:7px 10px;border-bottom:1px solid #eef0f2;text-align:left}}th{{background:#f8f9fb}}
.m{{color:#667;font-size:12px;line-height:1.5}}</style></head><body>
<header><h1>EvidenceForge rule test &mdash; {html.escape(gt['name'])}</h1>
<div style='opacity:.75;font-size:13px;margin-top:4px'>{len(rules)} rules &middot;
{len(events)} UDM events &middot; normalisation: {mode} &middot; {ts}</div></header>
<div class='w'><div class='cs'>{cards}</div>
<p class='m'><b>INCONCLUSIVE</b> = some conditions could not be evaluated locally, so
the hit counts are only an upper bound (the real rule matches at most that many).
<b>MISSED</b> = the technique is in the scenario but the rule never fired
- the most important finding. <b>NOISY</b> = fires on &ge;2% of benign background
activity. Rule evaluation is local and single-event only; correlation rules are not
evaluated. Reference lists are treated as empty. Nothing was ingested into the SIEM.</p>
<table><tr><th>Rule</th><th>Technique</th><th>In scenario</th><th>Verdict</th>
<th>Storyline hits</th><th>Background hits</th><th>Detail</th></tr>{trs}</table></div>
</body></html>"""
    Path("evidence_report.html").write_text(page, encoding="utf-8")
    with open("evidence_report.csv", "w", newline="", encoding="utf-8-sig") as fh:
        import csv
        w = csv.DictWriter(fh, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print("\n  Wrote evidence_report.html and evidence_report.csv")
    print("  Note: nothing was ingested into your SIEM.")


if __name__ == "__main__":
    main()
