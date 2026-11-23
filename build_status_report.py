#!/usr/bin/env python3
"""
build_status_report.py
======================
Sweep every run_summary.json under output/ and produce a one-page project
status report (status_report.html) - the artifact to open in a supervisor
meeting or attach to an update. Stdlib only.

Shows: total rules generated, progress toward the plan, breakdown by priority
tier and rule type, the batch-by-batch review-rate trend, the list of declined
techniques, and the current coverage delta vs. the master spreadsheet.
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def load_summaries(output_dir: Path) -> list[dict]:
    out = []
    for s in sorted(output_dir.rglob("run_summary.json")):
        try:
            d = json.loads(s.read_text(encoding="utf-8"))
            d["_path"] = str(s.parent.name)
            out.append(d)
        except Exception:
            pass
    return out


def existing_count(cov_path: Path, remap: dict) -> int:
    if not cov_path.is_file():
        return 0
    ids = set()
    if cov_path.suffix.lower() == ".csv":
        with cov_path.open(newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
    else:
        rows = json.loads(cov_path.read_text(encoding="utf-8"))
        rows = rows if isinstance(rows, list) else []
    for r in rows:
        blob = " ".join(str(v) for v in r.values()) if isinstance(r, dict) else str(r)
        for m in TECHNIQUE_RE.findall(blob):
            t = m.upper()
            ids.add(remap.get(t, t))
    return len(ids)


def main() -> None:
    print("Project status report builder\n")
    out_dir = Path(input("Generated rules folder [output]: ").strip() or "output")
    if not out_dir.is_dir():
        print(f"  {out_dir} not found."); return

    summaries = load_summaries(out_dir)
    if not summaries:
        print("  No run summaries found."); return

    # Dedup rules by (id, variant) keeping the newest, across all runs.
    latest: dict[tuple, dict] = {}
    for s in summaries:
        for r in s.get("results", []):
            latest[(r.get("id"), r.get("variant"), r.get("pivot"))] = r
    rules = list(latest.values())

    written = [r for r in rules if r.get("file")]
    declined = [r for r in rules if r.get("declined")]
    needing = [r for r in written if r.get("warnings")]
    by_tier = Counter(r.get("priority_label") or "Long tail"
                      for r in written)
    by_type = Counter(r.get("rule_type", "?") for r in written)

    # Batch trend: review rate per run (chronological)
    trend = []
    for s in summaries:
        res = [r for r in s.get("results", []) if r.get("file")]
        if not res:
            continue
        rev = sum(1 for r in res if r.get("warnings"))
        trend.append((s.get("run_id", s["_path"])[:16], len(res), rev,
                      round(100 * rev / len(res))))

    # Coverage delta
    version = summaries[-1].get("attack_version", "?")
    remap = {}
    tfile = sorted(Path(".").glob("mitre_techniques*.json"))
    total_techniques = 697
    if tfile:
        td = json.loads(tfile[0].read_text(encoding="utf-8"))
        remap = td.get("id_remap", {})
        total_techniques = td.get("technique_count", 697)
    cov_path = Path(input("Coverage file for delta [coverage.csv]: ").strip() or "coverage.csv")
    n_existing = existing_count(cov_path, remap)
    gen_techniques = len({r.get("id", "").split(".")[0] for r in written})

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    review_pct = round(100 * len(needing) / max(len(written), 1))

    tier_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in sorted(by_tier.items(), key=lambda x: -x[1]))
    type_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td><td>{round(100*v/max(len(written),1))}%</td></tr>"
        for k, v in by_type.most_common())
    trend_rows = "".join(
        f"<tr><td>{rid}</td><td>{n}</td><td>{rev}</td><td>{pct}%</td></tr>"
        for rid, n, rev, pct in trend)
    declined_rows = "".join(
        f"<li>{r.get('id')} v{r.get('variant')} ({r.get('pivot','')})</li>"
        for r in declined) or "<li>None</li>"

    bar = lambda pct, color: (
        f'<div style="background:#e6e8ec;border-radius:6px;height:22px;overflow:hidden">'
        f'<div style="width:{pct}%;background:{color};height:100%"></div></div>')

    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Detection Pipeline - Status Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f5f7;color:#1a1a1a}}
 header{{background:#0a2540;color:#fff;padding:20px 28px}}
 header h1{{margin:0;font-size:20px}} header .s{{opacity:.75;font-size:13px;margin-top:4px}}
 .wrap{{max-width:900px;margin:0 auto;padding:22px 28px}}
 .cards{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px}}
 .card{{background:#fff;border:1px solid #e6e8ec;border-radius:10px;padding:14px 18px;flex:1;min-width:150px}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:11px;text-transform:uppercase;color:#667;letter-spacing:.4px}}
 h2{{font-size:15px;margin:24px 0 8px}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;font-size:13px}}
 th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #eef0f2}} th{{background:#f8f9fb}}
 .box{{background:#fff;border:1px solid #e6e8ec;border-radius:10px;padding:16px}}
 ul{{margin:6px 0;padding-left:20px;font-size:13px}} .muted{{color:#889;font-size:12px}}
</style></head><body>
<header><h1>Detection Rule Pipeline &mdash; Status Report</h1>
<div class="s">MITRE ATT&amp;CK v{version} &middot; YARA-L / Google SecOps &middot; generated {ts}</div></header>
<div class="wrap">
 <div class="cards">
  <div class="card"><div class="n">{len(written)}</div><div class="l">Rules generated</div></div>
  <div class="card"><div class="n">{gen_techniques}</div><div class="l">Techniques touched</div></div>
  <div class="card"><div class="n">{review_pct}%</div><div class="l">Needing review</div></div>
  <div class="card"><div class="n">{len(declined)}</div><div class="l">Declined by model</div></div>
 </div>

 <h2>Progress toward plan (~527 rules)</h2>
 <div class="box">{bar(min(100,round(100*len(written)/527)), '#4caf50')}
  <div class="muted" style="margin-top:6px">{len(written)} of ~527 generated
  ({round(100*len(written)/527)}%)</div></div>

 <h2>Coverage snapshot</h2>
 <div class="box">
  Existing coverage (spreadsheet): <b>{n_existing}</b> technique IDs of {total_techniques}.
  This pipeline has generated rules touching <b>{gen_techniques}</b> parent techniques.
  <div class="muted" style="margin-top:6px">Note: coverage counts rule presence, not
  runtime-validated detections.</div></div>

 <h2>By priority tier</h2><table><tr><th>Tier</th><th>Rules</th></tr>{tier_rows}</table>

 <h2>By rule type</h2><table><tr><th>Type</th><th>Rules</th><th>Share</th></tr>{type_rows}</table>

 <h2>Review-rate trend (per batch)</h2>
 <table><tr><th>Run</th><th>Rules</th><th>Flagged</th><th>Rate</th></tr>{trend_rows}</table>
 <div class="muted">A stable rate around 15-20% is healthy; a sudden spike is worth pausing on.</div>

 <h2>Declined techniques (model judged not behaviorally detectable)</h2>
 <div class="box"><ul>{declined_rows}</ul>
  <div class="muted">These are correct refusals, not failures - the model avoided
  hallucinating logic for techniques that need an IOC.</div></div>

 <h2>Recommended next step</h2>
 <div class="box">Before generating the remaining rules, compile 2-3 of these in a
  Chronicle test tenant to confirm they import cleanly. If they do, proceed with the
  batch; if not, the fix propagates to all rules and is cheaper to catch now.</div>
 <p class="muted" style="margin-top:20px">All figures are AI-generated pipeline output
  pending human review. Not deployment-ready without engineer sign-off.</p>
</div></body></html>"""

    dest = Path("status_report.html")
    dest.write_text(html, encoding="utf-8")
    print(f"\n  Wrote {dest}")
    print(f"  {len(written)} rules, {review_pct}% needing review, {len(declined)} declined.")
    print("  Open it in a browser, or attach to your supervisor update.")


if __name__ == "__main__":
    main()
