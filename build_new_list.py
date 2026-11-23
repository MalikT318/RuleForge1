#!/usr/bin/env python3
"""
build_new_list.py
=================
Sweep the generated rules in output/ and produce `new_list.csv` - a review
sheet whose columns match the team's master coverage spreadsheet, ready to be
imported into the master workbook as a new tab ("New List") for review.

- Parses each generated rule's meta block (severity, tactic, technique,
  description, log prerequisites, false positives, tuning guidance).
- Joins in pipeline metadata from each run's run_summary.json (pivot/angle,
  rule type, validation warnings) so reviewers can sort by "needs attention".
- De-duplicates across run folders: if the same rule file was regenerated in a
  later run, only the newest version is exported.

Stdlib only - no pip install needed.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from datetime import date
from pathlib import Path

# Column headers of the team's master coverage sheet, in order.
MASTER_COLUMNS = [
    "Rule", "KQL Query", "Code", "Severity", "MITRE Tactic", "MITRE Technique",
    "YAML (if applicable)", "Log Source Examples", "Prerequisites", "Description",
    "Comments", "Tested? (Y/N)", "Test Date", "SOC Recommended Actions",
    "Date Created", "Top 10",
]


def meta_field(rule_text: str, field: str) -> str:
    m = re.search(rf'{field}\s*=\s*"([^"]*)"', rule_text)
    return m.group(1).strip() if m else ""


def rule_name(rule_text: str) -> str:
    m = re.search(r"\brule\s+([A-Za-z0-9_]+)", rule_text)
    return m.group(1) if m else ""


def strip_header_comment(rule_text: str) -> str:
    """Drop the pipeline's /* ... */ provenance header for the Code column."""
    return re.sub(r"^\s*/\*.*?\*/\s*", "", rule_text, flags=re.S).strip()


def load_run_metadata(output_dir: Path) -> dict[str, dict]:
    """filename -> spec metadata (pivot, rule_type, warnings) from summaries."""
    meta: dict[str, dict] = {}
    for summ in sorted(output_dir.rglob("run_summary.json")):
        try:
            data = json.loads(summ.read_text(encoding="utf-8"))
        except Exception:
            continue
        for r in data.get("results", []):
            if r.get("file"):
                meta[r["file"]] = r     # later runs overwrite earlier - wanted
    return meta


def newest_rule_files(output_dir: Path) -> dict[str, Path]:
    """filename -> newest path (regenerated rules supersede older copies)."""
    newest: dict[str, Path] = {}
    for ext in ("*.yaral", "*.kql"):
        for f in sorted(output_dir.rglob(ext)):        # sorted => later runs last
            newest[f.name] = f
    return newest


def main() -> None:
    print("Generated-rules review sheet builder\n")
    out_dir = Path(input("Path to generated rules folder [output]: ").strip() or "output")
    if not out_dir.is_dir():
        sys.exit(f"Folder not found: {out_dir}")

    run_meta = load_run_metadata(out_dir)
    files = newest_rule_files(out_dir)
    if not files:
        sys.exit("No .yaral or .kql rule files found.")
    print(f"  Found {len(files)} unique rule file(s) "
          f"(newest version kept where regenerated).")

    today = date.today().strftime("%m/%d/%Y")
    rows: list[dict] = []
    for fname, path in sorted(files.items()):
        text = path.read_text(encoding="utf-8", errors="replace")
        spec = run_meta.get(fname, {})
        is_kql = fname.lower().endswith(".kql")

        all_warnings = spec.get("warnings") or []
        # Auto-fix notices are receipts, not review items - don't flag them.
        warnings = [w for w in all_warnings if not w.lower().startswith("auto-fixed")]
        pivot = spec.get("pivot", "")
        rtype = spec.get("rule_type", "")
        tier = spec.get("priority_label", "")
        is_top10 = bool(spec.get("priority_tier") and spec["priority_tier"] != 999)

        comments_bits = ["AI-generated (Fuel iX) - PENDING REVIEW"]
        if pivot:
            comments_bits.append(f"angle: {pivot}")
        if rtype:
            comments_bits.append(f"type: {rtype}")
        if warnings:
            comments_bits.append("REVIEW FLAGS: " + "; ".join(warnings))

        tech_id = meta_field(text, "mitre_technique") or spec.get("id", "")
        tech_name = meta_field(text, "mitre_technique_name") or spec.get("name", "")

        rows.append({
            "Rule": rule_name(text) or fname,
            "KQL Query": strip_header_comment(text) if is_kql else "",
            "Code": "" if is_kql else strip_header_comment(text),
            "Severity": meta_field(text, "severity").strip().title(),
            "MITRE Tactic": meta_field(text, "mitre_tactic"),
            "MITRE Technique": f"{tech_id} - {tech_name}".strip(" -"),
            "YAML (if applicable)": f"relevantTechniques:\n- {tech_id}" if tech_id else "",
            "Log Source Examples": meta_field(text, "log_prerequisites"),
            "Prerequisites": meta_field(text, "log_prerequisites"),
            "Description": meta_field(text, "description"),
            "Comments": " | ".join(comments_bits),
            "Tested? (Y/N)": "FALSE",
            "Test Date": "",
            "SOC Recommended Actions": (meta_field(text, "false_positives") +
                                        (" Tuning: " + meta_field(text, "tuning_guidance")
                                         if meta_field(text, "tuning_guidance") else "")).strip(),
            "Date Created": today,
            "Top 10": "TRUE" if is_top10 else "",
        })

    dest = Path("new_list.csv")
    # utf-8-sig so Excel opens it with correct characters by double-click
    with dest.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=MASTER_COLUMNS)
        w.writeheader()
        w.writerows(rows)

    flagged = sum(1 for r in rows if "REVIEW FLAGS" in r["Comments"])
    print(f"\n  Wrote {dest} - {len(rows)} rule(s), {flagged} carrying review flags.")
    print("\nTo add as the 'New List' tab in the master workbook:")
    print("  1. Open the master spreadsheet in Excel.")
    print("  2. Right-click the sheet tabs at the bottom -> Insert -> Worksheet.")
    print("  3. Rename the new tab to: New List")
    print("  4. In the new tab: Data -> Get Data -> From Text/CSV -> new_list.csv")
    print("     (or simply open new_list.csv and copy-paste everything in).")
    print("  Reviewers can sort/filter the Comments column for 'REVIEW FLAGS'.")


if __name__ == "__main__":
    main()
