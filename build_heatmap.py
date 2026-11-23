#!/usr/bin/env python3
"""
build_heatmap.py
================
Build a MITRE ATT&CK coverage heatmap from:
  - your existing coverage spreadsheet (.csv/.json), and
  - the rules this pipeline has generated (the output/ folders).

Produces two artifacts in ./heatmap/:
  1. attack_layer.json  - a MITRE ATT&CK Navigator layer. Open the hosted
     Navigator (https://mitre-attack.github.io/attack-navigator/), choose
     "Open Existing Layer" -> "Upload from local", and select this file.
  2. coverage_heatmap.html - a standalone, self-contained interactive matrix
     you can open in any browser or drop into a deck/email. No internet needed.

Colour meaning (existing + generated):
  grey   = no coverage
  blue   = covered by an EXISTING detection only
  green  = covered by a GENERATED rule only (net-new from this project)
  teal   = covered by BOTH
Shade intensity scales with how many rules hit the technique (depth).

Reuses the same technique data file and coverage-parsing logic as the
generator, so the two always agree.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("defense-impairment", "Defense Impairment"),
    ("stealth", "Stealth"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
TACTIC_LABEL = dict(TACTIC_ORDER)

# Colours (existing / generated / both / none)
C_NONE = "#ebedf0"
C_EXISTING = "#4a90d9"
C_GENERATED = "#4caf50"
C_BOTH = "#009688"


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
def load_techniques(path: Path) -> tuple[str, list[dict], dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return (data.get("attack_version", "unknown"),
            data["techniques"], data.get("id_remap", {}) or {})


def _rows(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                return v
    return data if isinstance(data, list) else []


def existing_coverage(path: Path, remap: dict) -> set[str]:
    """Same 'scan all columns, remap retired IDs' logic as the generator."""
    ids: set[str] = set()
    for r in _rows(path):
        blob = " ".join(str(v) for v in r.values()) if isinstance(r, dict) else str(r)
        for m in TECHNIQUE_RE.findall(blob):
            tid = m.upper()
            ids.add(remap.get(tid, tid))
    return ids


def generated_coverage(output_dir: Path) -> dict[str, int]:
    """Count generated rule files per technique across all run folders."""
    counts: dict[str, int] = defaultdict(int)
    if not output_dir.is_dir():
        return counts
    for f in output_dir.rglob("*.yaral"):
        m = re.match(r"^(T\d{4}(?:_\d{3})?)", f.stem.upper())
        if m:
            counts[m.group(1).replace("_", ".")] += 1
    for f in output_dir.rglob("*.kql"):
        m = re.match(r"^(T\d{4}(?:_\d{3})?)", f.stem.upper())
        if m:
            counts[m.group(1).replace("_", ".")] += 1
    return counts


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def classify(tid: str, existing: set[str], generated: dict[str, int]) -> tuple[str, str, int]:
    """Return (state, colour, generated_count) for a technique ID.

    A parent counts as covered if the parent OR any of its sub-techniques is.
    """
    parent = tid.split(".")[0]
    has_existing = tid in existing or (("." not in tid) and any(
        e.split(".")[0] == tid for e in existing))
    gen_count = generated.get(tid, 0)
    if "." not in tid:
        gen_count += sum(c for k, c in generated.items() if k.split(".")[0] == tid and k != tid)
    has_generated = gen_count > 0

    if has_existing and has_generated:
        return "both", C_BOTH, gen_count
    if has_existing:
        return "existing", C_EXISTING, gen_count
    if has_generated:
        return "generated", C_GENERATED, gen_count
    return "none", C_NONE, 0


# ---------------------------------------------------------------------------
# Output 1: Navigator layer
# ---------------------------------------------------------------------------
def build_navigator_layer(version: str, techniques: list[dict],
                          existing: set[str], generated: dict[str, int]) -> dict:
    entries = []
    for t in techniques:
        state, colour, gen = classify(t["id"], existing, generated)
        if state == "none":
            continue
        has_existing = state in ("existing", "both")
        entries.append({
            "techniqueID": t["id"],
            "color": colour,
            "comment": (f"{'Existing detection. ' if has_existing else ''}"
                        f"{f'{gen} generated rule(s). ' if gen else ''}").strip(),
            "enabled": True,
            "metadata": [
                {"name": "existing_coverage", "value": "yes" if has_existing else "no"},
                {"name": "generated_rules", "value": str(gen)},
            ],
        })
    return {
        "name": f"TELUS Detection Coverage (ATT&CK v{version})",
        "versions": {"attack": version.split(".")[0], "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Existing coverage (spreadsheet) plus rules generated by "
                        "the detection pipeline. Blue=existing, Green=generated, "
                        "Teal=both."),
        "techniques": entries,
        "legendItems": [
            {"label": "Existing detection", "color": C_EXISTING},
            {"label": "Generated rule (net-new)", "color": C_GENERATED},
            {"label": "Both", "color": C_BOTH},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "sorting": 0,
    }


# ---------------------------------------------------------------------------
# Output 2: standalone HTML
# ---------------------------------------------------------------------------
def build_html(version: str, techniques: list[dict],
               existing: set[str], generated: dict[str, int]) -> str:
    # Group techniques into tactic columns (parents only; subs fold under parents).
    by_tactic: dict[str, list[dict]] = {k: [] for k, _ in TACTIC_ORDER}
    parents = [t for t in techniques if not t["sub"]]
    sub_by_parent: dict[str, list[dict]] = defaultdict(list)
    for t in techniques:
        if t["sub"]:
            sub_by_parent[t["id"].split(".")[0]].append(t)

    for t in parents:
        for tac in t["tactics"]:
            if tac in by_tactic:
                by_tactic[tac].append(t)

    # Coverage stats
    total = len(parents)
    covered_states = {tid: classify(tid, existing, generated)[0] for tid in [p["id"] for p in parents]}
    n_existing = sum(1 for s in covered_states.values() if s == "existing")
    n_generated = sum(1 for s in covered_states.values() if s == "generated")
    n_both = sum(1 for s in covered_states.values() if s == "both")
    n_covered = n_existing + n_generated + n_both
    total_gen_rules = sum(generated.values())

    cells_by_tactic = {}
    for tac, _ in TACTIC_ORDER:
        cells = []
        for t in sorted(by_tactic[tac], key=lambda x: x["id"]):
            state, colour, gen = classify(t["id"], existing, generated)
            subs = sub_by_parent.get(t["id"], [])
            sub_cov = sum(1 for s in subs
                          if classify(s["id"], existing, generated)[0] != "none")
            fg = "#fff" if state != "none" else "#333"
            title = (f"{t['id']} {t['name']}&#10;"
                     f"State: {state}&#10;Generated rules: {gen}"
                     + (f"&#10;Sub-techniques covered: {sub_cov}/{len(subs)}" if subs else ""))
            cells.append(
                f'<div class="cell" style="background:{colour};color:{fg}" title="{title}">'
                f'<span class="tid">{t["id"]}</span>'
                f'<span class="tname">{t["name"]}</span>'
                + (f'<span class="badge">{gen}</span>' if gen else "")
                + (f'<span class="subs">{sub_cov}/{len(subs)}</span>' if subs else "")
                + '</div>')
        cells_by_tactic[tac] = cells

    columns_html = ""
    for tac, label in TACTIC_ORDER:
        if not by_tactic[tac]:
            continue
        col_cells = "".join(cells_by_tactic[tac])
        columns_html += (
            f'<div class="col"><div class="colhead">{label}'
            f'<span class="colcount">{len(by_tactic[tac])}</span></div>{col_cells}</div>')

    pct = round(100 * n_covered / total) if total else 0
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TELUS Detection Coverage - ATT&CK v{version}</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; }}
  body {{ margin:0; background:#f4f5f7; color:#1a1a1a; }}
  header {{ background:#0a2540; color:#fff; padding:18px 24px; }}
  header h1 {{ margin:0; font-size:19px; font-weight:600; }}
  header .sub {{ opacity:.75; font-size:13px; margin-top:4px; }}
  .stats {{ display:flex; gap:14px; flex-wrap:wrap; padding:16px 24px; background:#fff;
           border-bottom:1px solid #e0e0e0; }}
  .stat {{ background:#f8f9fb; border:1px solid #e6e8ec; border-radius:8px; padding:10px 16px;
          min-width:120px; }}
  .stat .n {{ font-size:24px; font-weight:700; }}
  .stat .l {{ font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:#667; }}
  .legend {{ display:flex; gap:18px; flex-wrap:wrap; align-items:center; padding:12px 24px;
            font-size:13px; }}
  .legend .sw {{ display:inline-block; width:14px; height:14px; border-radius:3px;
                vertical-align:middle; margin-right:6px; }}
  .controls {{ padding:0 24px 10px; }}
  .controls input {{ padding:7px 12px; border:1px solid #cdd2da; border-radius:7px;
                     width:260px; font-size:13px; }}
  .matrix {{ display:flex; gap:6px; padding:16px 24px 40px; overflow-x:auto; align-items:flex-start; }}
  .col {{ flex:0 0 168px; }}
  .colhead {{ font-size:12px; font-weight:600; background:#205b8f; color:#fff;
             padding:8px; border-radius:6px 6px 0 0; display:flex; justify-content:space-between; }}
  .colcount {{ opacity:.7; font-weight:400; }}
  .cell {{ position:relative; padding:6px 7px; margin-top:3px; border-radius:5px;
          font-size:11px; line-height:1.25; cursor:default; min-height:20px; }}
  .cell .tid {{ font-weight:700; display:block; font-size:10px; opacity:.9; }}
  .cell .tname {{ display:block; }}
  .cell .badge {{ position:absolute; top:4px; right:5px; background:rgba(0,0,0,.28);
                 border-radius:9px; padding:0 6px; font-size:10px; font-weight:700; }}
  .cell .subs {{ position:absolute; bottom:3px; right:5px; font-size:9px; opacity:.85; }}
  .cell.dim {{ opacity:.12; }}
  footer {{ padding:16px 24px 30px; font-size:11px; color:#889; }}
</style></head>
<body>
<header>
  <h1>TELUS Detection Coverage &mdash; MITRE ATT&amp;CK Enterprise v{version}</h1>
  <div class="sub">Existing detections plus pipeline-generated rules &middot; generated {ts}</div>
</header>
<div class="stats">
  <div class="stat"><div class="n">{n_covered}/{total}</div><div class="l">Techniques covered ({pct}%)</div></div>
  <div class="stat"><div class="n" style="color:{C_EXISTING}">{n_existing}</div><div class="l">Existing only</div></div>
  <div class="stat"><div class="n" style="color:{C_GENERATED}">{n_generated}</div><div class="l">Generated only</div></div>
  <div class="stat"><div class="n" style="color:{C_BOTH}">{n_both}</div><div class="l">Both</div></div>
  <div class="stat"><div class="n">{total_gen_rules}</div><div class="l">Generated rules total</div></div>
</div>
<div class="legend">
  <span><span class="sw" style="background:{C_NONE}"></span>No coverage</span>
  <span><span class="sw" style="background:{C_EXISTING}"></span>Existing detection</span>
  <span><span class="sw" style="background:{C_GENERATED}"></span>Generated (net-new)</span>
  <span><span class="sw" style="background:{C_BOTH}"></span>Both</span>
  <span style="color:#889">Number badge = generated rule count &middot; x/y = sub-techniques covered</span>
</div>
<div class="controls">
  <input id="filter" placeholder="Filter techniques (name or ID)..." oninput="flt(this.value)">
</div>
<div class="matrix" id="matrix">{columns_html}</div>
<footer>
  Note: parents are shaded if the technique or any sub-technique is covered.
  Coverage is derived from static rule presence, not runtime validation.
  For the interactive version, upload <code>attack_layer.json</code> to the MITRE ATT&amp;CK Navigator.
</footer>
<script>
  function flt(q) {{
    q = q.trim().toLowerCase();
    document.querySelectorAll('.cell').forEach(function(c) {{
      var hit = !q || c.textContent.toLowerCase().indexOf(q) >= 0;
      c.classList.toggle('dim', !hit);
    }});
  }}
</script>
</body></html>"""


# ---------------------------------------------------------------------------
def main() -> None:
    print("MITRE ATT&CK coverage heatmap builder\n")

    tfile = Path("mitre_techniques_19.1.json")
    if not tfile.is_file():
        matches = sorted(Path(".").glob("mitre_techniques*.json"))
        if not matches:
            sys.exit("No mitre_techniques*.json found. Run it from your Mitre-tool folder.")
        tfile = matches[0]
    version, techniques, remap = load_techniques(tfile)
    print(f"  Techniques: {len(techniques)} (ATT&CK v{version})")

    cov_path = Path(input("Path to coverage file (.csv/.json) [coverage.csv]: ").strip()
                    or "coverage.csv").expanduser()
    if not cov_path.is_file():
        sys.exit(f"Coverage file not found: {cov_path}")
    existing = existing_coverage(cov_path, remap)
    print(f"  Existing coverage: {len(existing)} technique IDs")

    out_dir = Path(input("Path to generated rules folder [output]: ").strip() or "output")
    generated = generated_coverage(out_dir)
    print(f"  Generated rules: {sum(generated.values())} across {len(generated)} techniques")

    dest = Path("heatmap")
    dest.mkdir(exist_ok=True)

    layer = build_navigator_layer(version, techniques, existing, generated)
    (dest / "attack_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

    html = build_html(version, techniques, existing, generated)
    (dest / "coverage_heatmap.html").write_text(html, encoding="utf-8")

    print(f"\n  Wrote {dest/'attack_layer.json'}")
    print(f"  Wrote {dest/'coverage_heatmap.html'}")
    print("\nNext:")
    print("  - Open coverage_heatmap.html in any browser (self-contained).")
    print("  - Or go to https://mitre-attack.github.io/attack-navigator/ ->")
    print("    'Open Existing Layer' -> 'Upload from local' -> attack_layer.json")


if __name__ == "__main__":
    main()
