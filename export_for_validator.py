#!/usr/bin/env python3
"""
export_for_validator.py
=======================
Export generated YARA-L rules into the CSV format the MSS SIEM Rule Translator
expects, so they can be validated against Google SecOps (:verifyRuleText) and
auto-corrected by its AI fix loop.

Their standard mode reads:
    rule_name   - name of the detection rule
    rule_text   - full YARA-L rule text
    Log Type    - optional; enables an extra gate that checks fields against
                  what that log source's parser actually emits

Then, in the translator repo:
    python validator.py --input rules_for_validation.csv \\
                        --output fixed_rules.csv

Usage:  python export_for_validator.py [--with-log-type]

Notes
-----
- Only the newest copy of each rule file is exported (rules regenerated in a
  later run supersede earlier ones).
- The pipeline's provenance header comment is stripped, since the validator
  wants the rule itself.
- Log Type is OFF by default. The translator treats an absent column as
  dormant, which is safe; a WRONG value would make the extra gate reject valid
  rules. Turn it on only after confirming the log type strings with whoever
  maintains the translator.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

# Our log-source families -> Chronicle log type names.
# VERIFY THESE with the translator's maintainer before enabling --with-log-type.
LOG_TYPE_MAP = {
    "windows_endpoint": "WINEVTLOG",
    "linux_endpoint":   "LINUX_SYSLOG",
    "identity":         "WINDOWS_AD",
    "m365":             "OFFICE_365",
    "cloud_audit":      "AWS_CLOUDTRAIL",
    # Left unmapped on purpose - vendor-specific, so a guess could be wrong:
    # firewall, ips, dns, vmware_esxi, container, macos_endpoint
}


def strip_header(text: str) -> str:
    """Remove the generator's /* provenance */ header, keep the rule."""
    return re.sub(r"^\s*/\*.*?\*/\s*", "", text, flags=re.S).strip()


def rule_name_of(text: str, fallback: str) -> str:
    m = re.search(r"\brule\s+([A-Za-z0-9_]+)", text)
    return m.group(1) if m else Path(fallback).stem


def main() -> None:
    with_log_type = "--with-log-type" in sys.argv

    print("Export rules for the MSS SIEM Rule Translator\n")
    out_dir = Path(input("Generated rules folder [output]: ").strip() or "output")
    if not out_dir.is_dir():
        sys.exit(f"Not found: {out_dir}")

    # newest copy of each filename wins
    newest: dict[str, Path] = {}
    for f in sorted(out_dir.rglob("*.yaral")):
        newest[f.name] = f
    if not newest:
        sys.exit("No .yaral files found.")

    # spec metadata (for log_source) from the run summaries
    specs: dict[str, dict] = {}
    for s in sorted(out_dir.rglob("run_summary.json")):
        try:
            for r in json.loads(s.read_text(encoding="utf-8")).get("results", []):
                if r.get("file"):
                    specs[r["file"]] = r
        except Exception:
            pass

    rows = []
    unmapped: set[str] = set()
    for name, path in sorted(newest.items()):
        text = strip_header(path.read_text(encoding="utf-8", errors="replace"))
        if not text:
            continue
        row = {"rule_name": rule_name_of(text, name), "rule_text": text}
        if with_log_type:
            fam = (specs.get(name) or {}).get("log_source", "")
            lt = LOG_TYPE_MAP.get(fam, "")
            if fam and not lt:
                unmapped.add(fam)
            row["Log Type"] = lt
        rows.append(row)

    fields = ["rule_name", "rule_text"] + (["Log Type"] if with_log_type else [])
    dest = Path("rules_for_validation.csv")
    with dest.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print(f"\n  Wrote {dest} - {len(rows)} rule(s), columns: {', '.join(fields)}")
    if unmapped:
        print(f"  No log type mapped for: {', '.join(sorted(unmapped))} "
              f"(left blank - that gate stays dormant for those rules)")
    if not with_log_type:
        print("  Log Type column omitted (safe default). Re-run with "
              "--with-log-type once the log type strings are confirmed.")
    print("\nNext, in the translator repo:")
    print("  python validator.py --input rules_for_validation.csv "
          "--output fixed_rules.csv")
    print("  (add --dry-run first to see what it would do)")


if __name__ == "__main__":
    main()
