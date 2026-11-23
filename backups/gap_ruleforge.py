#!/usr/bin/env python3
"""
gap_ruleforge.py
================
Generate detection rules (KQL for Microsoft Sentinel, or YARA-L 2.0 for Google
SecOps) for MITRE ATT&CK techniques that TELUS does *not* currently cover.

Pipeline
--------
1. Load the live MITRE ATT&CK Enterprise matrix (auto-resolves the latest
   released version; cached locally so re-runs are fast).
2. Load a TELUS coverage file (.csv or .json), auto-detect which column holds
   the MITRE technique IDs, and let the operator confirm/override.
3. Diff matrix vs. coverage -> the gap set (uncovered techniques).
4. For each gap (up to an operator-set cap), build a detailed prompt and send
   it to Fuel iX (/v1/chat/completions) to generate a rule in the chosen
   language.
5. Write one rule file per technique + a run summary.

Auth / config lives in a .env file (see .env.example). No secrets in code.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# .env loading is deliberately self-contained rather than using python-dotenv.
# python-dotenv rejects values like:
#     CMD="C:\Program Files\tool.cmd" --flag
# (quoted path followed by arguments) and silently yields nothing, which is very
# hard to diagnose. This parser accepts that form, and behaves identically on
# every machine regardless of what happens to be pip-installed.
def load_dotenv(path: str = ".env") -> None:
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        # Only strip quotes when they wrap the WHOLE value, so a quoted path
        # followed by arguments survives intact.
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ.setdefault(key.strip(), val)


# ---------------------------------------------------------------------------
# Configuration (env-driven, with safe defaults)
# ---------------------------------------------------------------------------
load_dotenv()

FUELIX_API_KEY   = os.getenv("FUELIX_API_KEY", "").strip()
FUELIX_BASE_URL  = os.getenv("FUELIX_BASE_URL", "https://api.fuelix.ai").rstrip("/")
FUELIX_MODEL_ENV = os.getenv("FUELIX_MODEL", "").strip()          # optional default model
MITRE_VERSION    = os.getenv("MITRE_ATTACK_VERSION", "").strip()  # e.g. "19.1"; blank = latest
MITRE_TECHNIQUES_FILE = os.getenv("MITRE_TECHNIQUES_FILE", "").strip()  # offline pre-processed file
MAX_USE_CASES    = int(os.getenv("MAX_USE_CASES", "500"))         # hard upper limit safeguard
PRIORITY_FILE    = os.getenv("PRIORITY_FILE", "priority_techniques.json")
LOG_SOURCE_FILE  = os.getenv("LOG_SOURCE_FILE", "log_sources.json")
CHRONICLE_VERIFY_URL = os.getenv("CHRONICLE_VERIFY_URL", "").strip()
CHRONICLE_ENDPOINT   = os.getenv("CHRONICLE_ENDPOINT", "").strip()
CHRONICLE_PROJECT    = os.getenv("CHRONICLE_PROJECT", "").strip()
CHRONICLE_LOCATION   = os.getenv("CHRONICLE_LOCATION", "").strip()
CHRONICLE_INSTANCE   = os.getenv("CHRONICLE_INSTANCE", "").strip()
CHRONICLE_TOKEN      = os.getenv("CHRONICLE_TOKEN", "").strip()
CHRONICLE_TOKEN_CMD  = os.getenv("CHRONICLE_TOKEN_CMD", "").strip()
CHRONICLE_SA_KEY     = os.getenv("CHRONICLE_SA_KEY", "").strip()
REQUEST_TEMP     = float(os.getenv("FUELIX_TEMPERATURE", "0.2"))  # low temp = more deterministic rules
REQUEST_PAUSE    = float(os.getenv("FUELIX_REQUEST_PAUSE", "0.8"))# seconds between calls (rate courtesy)
CACHE_DIR        = Path(os.getenv("CACHE_DIR", ".cache"))
OUTPUT_DIR       = Path(os.getenv("OUTPUT_DIR", "output"))

# Corporate proxy support. Set FUELIX_PROXY (or the standard HTTPS_PROXY) in .env
# to route outbound calls through your company proxy, e.g.
#   FUELIX_PROXY=http://webproxy.telus.com:8080
# If it needs a login:  http://user:password@webproxy.telus.com:8080
FUELIX_PROXY = (os.getenv("FUELIX_PROXY") or os.getenv("HTTPS_PROXY")
                or os.getenv("https_proxy") or "").strip()
if FUELIX_PROXY:
    _opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": FUELIX_PROXY, "https": FUELIX_PROXY}))
    urllib.request.install_opener(_opener)

STIX_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
STIX_BASE      = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Populated from the techniques data file: retired technique ID -> current ID.
# MITRE renumbers techniques between ATT&CK versions (e.g. T1562 -> T1685), so a
# spreadsheet written against an older version must be translated forward or its
# coverage is silently lost.
ID_REMAP: dict[str, str] = {}

# Tactic shortname -> human label. Unknown shortnames are title-cased on the fly,
# so the script survives ATT&CK renames without code changes.
TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
    "initial-access": "Initial Access", "execution": "Execution",
    "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion", "credential-access": "Credential Access",
    "discovery": "Discovery", "lateral-movement": "Lateral Movement",
    "collection": "Collection", "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration", "impact": "Impact",
}


# ---------------------------------------------------------------------------
# Small console helpers
# ---------------------------------------------------------------------------
def hr(char: str = "-", n: int = 70) -> None:
    print(char * n)

def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or (default or "")

def die(msg: str) -> None:
    sys.exit(f"\n[FATAL] {msg}")

def tactic_label(short: str) -> str:
    return TACTIC_LABELS.get(short, short.replace("-", " ").title())


# ---------------------------------------------------------------------------
# 1. MITRE ATT&CK matrix
# ---------------------------------------------------------------------------
def resolve_stix_url() -> tuple[str, str]:
    """Return (version, url) for the Enterprise STIX bundle to use."""
    if MITRE_VERSION:
        return MITRE_VERSION, f"{STIX_BASE}/enterprise-attack-{MITRE_VERSION}.json"
    with urllib.request.urlopen(STIX_INDEX_URL, timeout=60) as r:
        idx = json.load(r)
    coll = next(c for c in idx["collections"] if "Enterprise" in c["name"])
    latest = sorted(coll["versions"],
                    key=lambda v: [int(x) for x in v["version"].split(".")])[-1]
    return latest["version"], latest["url"]


def _find_prebuilt_file() -> Path | None:
    """Locate a pre-processed techniques file for offline use, if present."""
    if MITRE_TECHNIQUES_FILE:
        p = Path(MITRE_TECHNIQUES_FILE).expanduser()
        return p if p.is_file() else None
    # Auto-detect: any 'mitre_techniques*.json' in the current folder.
    matches = sorted(Path(".").glob("mitre_techniques*.json"))
    return matches[0] if matches else None


def load_mitre_techniques() -> tuple[str, list[dict]]:
    """Return (version, techniques).

    Priority:
    1. A pre-processed techniques file (offline; no network). This is the path
       for locked-down networks that block GitHub - see MITRE_TECHNIQUES_FILE
       in .env, or just drop a 'mitre_techniques_*.json' file in this folder.
    2. Otherwise, fetch (or read a cached copy of) the live STIX bundle.
    """
    global ID_REMAP
    prebuilt = _find_prebuilt_file()
    if prebuilt:
        print(f"  Using pre-processed techniques file ({prebuilt}) - no download needed.")
        data = json.loads(prebuilt.read_text(encoding="utf-8"))
        techniques = data["techniques"]
        # Old -> new technique ID map (MITRE retires/renumbers techniques between
        # versions). Used so coverage recorded under an old ID still counts.
        ID_REMAP = data.get("id_remap", {}) or {}
        if ID_REMAP:
            print(f"  Loaded {len(ID_REMAP)} retired-ID remappings.")
        techniques.sort(key=lambda t: (t["id"].split(".")[0], t["id"]))
        return data.get("attack_version", "local"), techniques

    version, url = resolve_stix_url()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"enterprise-attack-{version}.json"

    if cache_file.exists():
        print(f"  Using cached ATT&CK v{version} ({cache_file})")
        bundle = json.loads(cache_file.read_text())
    else:
        print(f"  Downloading ATT&CK Enterprise v{version} ...")
        with urllib.request.urlopen(url, timeout=180) as r:
            raw = r.read()
        cache_file.write_bytes(raw)
        bundle = json.loads(raw)

    techniques = []
    byid = {o["id"]: o for o in bundle["objects"]}

    def _ext_id(o: dict) -> str | None:
        for e in o.get("external_references", []):
            if e.get("source_name") == "mitre-attack" and e.get("external_id"):
                return e["external_id"]
        return None

    # Build retired -> current ID map from 'revoked-by' relationships, so coverage
    # recorded under an older ATT&CK numbering still counts. (Same data the
    # pre-processed file carries; built here for the live-download path.)
    remap: dict[str, str] = {}
    for r in bundle["objects"]:
        if r.get("type") != "relationship" or r.get("relationship_type") != "revoked-by":
            continue
        src, tgt = byid.get(r.get("source_ref", "")), byid.get(r.get("target_ref", ""))
        if not src or not tgt or src.get("type") != "attack-pattern":
            continue
        o_id, n_id = _ext_id(src), _ext_id(tgt)
        if o_id and n_id:
            remap[o_id] = n_id
    # Follow chains (old -> intermediate -> current).
    def _resolve(k: str) -> str:
        seen: set[str] = set()
        while k in remap and k not in seen:
            seen.add(k)
            k = remap[k]
        return k
    ID_REMAP = {k: _resolve(k) for k in remap}
    if ID_REMAP:
        print(f"  Built {len(ID_REMAP)} retired-ID remappings from ATT&CK data.")

    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = [e for e in obj.get("external_references", [])
               if e.get("source_name") == "mitre-attack" and e.get("external_id")]
        if not ext:
            continue
        techniques.append({
            "id":        ext[0]["external_id"],
            "url":       ext[0].get("url", ""),
            "name":      obj.get("name", ""),
            "sub":       bool(obj.get("x_mitre_is_subtechnique", False)),
            "tactics":   [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                          if p.get("kill_chain_name") == "mitre-attack"],
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": (obj.get("x_mitre_detection", "") or "").strip(),
            "description": (obj.get("description", "") or "").strip(),
        })
    techniques.sort(key=lambda t: (t["id"].split(".")[0], t["id"]))
    return version, techniques


# ---------------------------------------------------------------------------
# 2. TELUS coverage file  (schema auto-detection)
# ---------------------------------------------------------------------------
def _rows_from_file(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):                       # {"rules": [...]} or similar
            for v in data.values():
                if isinstance(v, list):
                    data = v
                    break
        if not isinstance(data, list):
            die("JSON coverage file must be a list of records (or a dict wrapping one).")
        # normalise scalars/nested to flat-ish string cells for scanning
        return [r if isinstance(r, dict) else {"value": r} for r in data]
    die("Unsupported file type. Use .csv or .json.")


def _score_column(rows: list[dict], col: str) -> int:
    hits = 0
    for r in rows:
        if TECHNIQUE_RE.search(str(r.get(col, ""))):
            hits += 1
    return hits


def load_coverage(path: Path) -> set[str]:
    """Auto-detect the technique-ID column, confirm with the operator, return covered IDs."""
    rows = _rows_from_file(path)
    if not rows:
        die("Coverage file is empty.")

    cols = list(rows[0].keys())
    scored = sorted(((c, _score_column(rows, c)) for c in cols),
                    key=lambda x: x[1], reverse=True)

    print(f"\n  Loaded {len(rows)} rows. Column scan for MITRE technique IDs:")
    for c, s in scored:
        flag = "  <-- best match" if (c, s) == scored[0] and s > 0 else ""
        print(f"    {s:>4} hits   {c}{flag}")

    best_col, best_hits = scored[0]
    if best_hits == 0:
        die("No column contained MITRE technique IDs (pattern T####[.###]).\n"
            "        Check the file, or add/rename a column holding the IDs.")

    print("  (Tip: type 'all' to scan every column - safest when IDs are scattered "
          "or the ID column is optional.)")
    chosen = ask("  Which column holds the technique IDs?", best_col)
    scan_all = chosen.strip().lower() in ("all", "*")
    if not scan_all and chosen not in cols:
        die(f"Column '{chosen}' not found. Available: {', '.join(cols)}. "
            f"(Or type 'all'.)")

    # Optional coverage/status filter (e.g. only rows marked Implemented count as covered).
    status_col = ask("  Optional status column to filter 'covered' rows (blank = every row counts)", "")
    keep_values: set[str] = set()
    if status_col:
        if status_col not in cols:
            die(f"Status column '{status_col}' not found.")
        seen = sorted({str(r.get(status_col, "")).strip() for r in rows if str(r.get(status_col, "")).strip()})
        print(f"    Values seen in '{status_col}': {', '.join(seen)}")
        wanted = ask("    Comma-separated values that mean COVERED", ",".join(seen))
        keep_values = {v.strip().lower() for v in wanted.split(",") if v.strip()}

    raw_ids: set[str] = set()
    for r in rows:
        if status_col and str(r.get(status_col, "")).strip().lower() not in keep_values:
            continue
        text = " ".join(str(v) for v in r.values()) if scan_all else str(r.get(chosen, ""))
        for m in TECHNIQUE_RE.findall(text):
            raw_ids.add(m.upper())      # normalise e.g. 't1087.004' -> 'T1087.004'

    # Translate retired/renumbered IDs forward to their current equivalents, so
    # coverage recorded against an older ATT&CK version still counts.
    covered: set[str] = set()
    translated: list[tuple[str, str]] = []
    for tid in sorted(raw_ids):
        new = ID_REMAP.get(tid)
        if new and new != tid:
            translated.append((tid, new))
            covered.add(new)
        else:
            covered.add(tid)

    print(f"  Detected {len(covered)} covered technique IDs.")
    if translated:
        print(f"  Translated {len(translated)} retired ID(s) to current ATT&CK numbering:")
        for old, new in translated[:12]:
            print(f"      {old} -> {new}")
        if len(translated) > 12:
            print(f"      ... and {len(translated) - 12} more")
        print("    (These would otherwise have been counted as gaps.)")
    return covered


# ---------------------------------------------------------------------------
# 3. Gap diff
# ---------------------------------------------------------------------------
def compute_gaps(techniques: list[dict], covered: set[str], include_subs: bool) -> list[dict]:
    gaps = []
    for t in techniques:
        if not include_subs and t["sub"]:
            continue
        if t["id"] in covered:
            continue
        # If a parent is covered wholesale, treat its sub-techniques as covered too
        # only when the operator opted to include subs but the parent is in the set.
        parent = t["id"].split(".")[0]
        if t["sub"] and parent in covered:
            continue
        gaps.append(t)
    return gaps


# ---------------------------------------------------------------------------
# 3b. Prioritization (generate high-incident techniques first)
# ---------------------------------------------------------------------------
def load_priority() -> dict | None:
    """Load the priority tier config, if present."""
    p = Path(PRIORITY_FILE).expanduser()
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  (Could not read {p}: {e} - continuing without prioritization.)")
        return None


def build_priority_index(cfg: dict) -> dict[str, tuple[int, str]]:
    """Map every technique ID (and sub-technique prefix) to (rank, tier label)."""
    idx: dict[str, tuple[int, str]] = {}
    for tier in cfg.get("tiers", []):
        rank = int(tier.get("rank", 999))
        label = tier.get("label", f"Tier {rank}")
        for tid in tier.get("ids", []):
            idx[tid.upper()] = (rank, label)
    return idx


def rank_of(tid: str, idx: dict[str, tuple[int, str]]) -> tuple[int, str]:
    """Rank a technique: exact match first, then its parent (subs inherit rank)."""
    tid = tid.upper()
    if tid in idx:
        return idx[tid]
    parent = tid.split(".")[0]
    if parent in idx:
        return idx[parent]
    return (999, "Unprioritized (long tail)")


def prioritize_gaps(gaps: list[dict], idx: dict[str, tuple[int, str]]) -> list[dict]:
    """Order gaps by priority tier, then numerically within each tier."""
    def key(t: dict):
        rank, _ = rank_of(t["id"], idx)
        return (rank, t["id"].split(".")[0], t["id"])
    return sorted(gaps, key=key)


def already_generated(language_key: str) -> set[str]:
    """Scan previous run folders for rules already produced for this language.

    Lets a large job be run in batches without regenerating earlier work.
    """
    ext = ".kql" if language_key == "kql" else ".yaral"
    found: set[str] = set()
    if not OUTPUT_DIR.is_dir():
        return found
    for f in OUTPUT_DIR.rglob(f"*{ext}"):
        stem = f.stem.upper()                 # e.g. 'T1059_001_V2_LINEAGE'
        m = re.match(r"^(T\d{4}(?:_\d{3})?)(?:_V(\d+))?", stem)
        if m:
            tid = m.group(1).replace("_", ".")
            variant = m.group(2) or "1"
            found.add(f"{tid}#{variant}")
            found.add(tid)                    # also record bare id (older runs)
    return found


def summarize_priority(gaps: list[dict], idx: dict[str, tuple[int, str]]) -> None:
    """Print how the gap list breaks down across priority tiers."""
    counts: dict[tuple[int, str], int] = {}
    for t in gaps:
        counts[rank_of(t["id"], idx)] = counts.get(rank_of(t["id"], idx), 0) + 1
    print("\n  Gap breakdown by priority tier:")
    for (rank, label), n in sorted(counts.items()):
        tag = f"  {rank:>2}." if rank != 999 else "   -"
        print(f"   {tag} {label:<44} {n:>4} gap(s)")
    top = sum(n for (r, _), n in counts.items() if r != 999)
    print(f"        {'TOTAL in priority tiers':<47} {top:>4}")
    print(f"        {'TOTAL long tail':<47} {len(gaps) - top:>4}")


# ---------------------------------------------------------------------------
# 4. Rule specs, pivots, and prompt construction
#
# Design follows the Fuel iX design consultation:
#   - "Top 10 heavy": more rules per high-incident technique, via differentiated
#     pivots rather than near-duplicates.
#   - ~80% single-event / ~20% correlation (correlation rules are stateful and
#     expensive in Chronicle at scale).
#   - Behavioral and durable only: no hashes, IPs, domains, tool names, CVE
#     payload strings, or hardcoded users/hosts.
# ---------------------------------------------------------------------------

# Conservative allowlist of UDM event types. Deliberately excludes types that
# could not be verified against Google's documentation (e.g. API_CALL,
# SERVICE_STATE_CHANGE, SOFTWARE_EXECUTION) - inventing a field name propagates
# the same error across every generated rule.
UDM_EVENT_TYPES = [
    "PROCESS_LAUNCH", "PROCESS_OPEN", "PROCESS_INJECTION", "PROCESS_TERMINATION",
    "PROCESS_MODULE_LOAD",
    "FILE_CREATION", "FILE_MODIFICATION", "FILE_DELETION", "FILE_READ", "FILE_MOVE",
    "REGISTRY_CREATION", "REGISTRY_MODIFICATION", "REGISTRY_DELETION",
    "NETWORK_CONNECTION", "NETWORK_DNS", "NETWORK_HTTP", "NETWORK_FLOW",
    "USER_LOGIN", "USER_LOGOUT", "USER_CREATION", "USER_CHANGE_PASSWORD",
    "USER_CHANGE_PERMISSIONS", "USER_RESOURCE_ACCESS", "USER_RESOURCE_CREATION",
    "USER_RESOURCE_DELETION", "USER_RESOURCE_UPDATE_CONTENT",
    "SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_MODIFICATION", "SCHEDULED_TASK_DELETION",
    "SETTING_CREATION", "SETTING_MODIFICATION", "SETTING_DELETION",
    "RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_PERMISSIONS_CHANGE",
    "GROUP_MODIFICATION", "EMAIL_TRANSACTION", "MUTEX_CREATION",
]


# ---------------------------------------------------------------------------
# Platform / log-source targeting
#
# Without this, models default to Windows for almost everything - even for
# techniques MITRE lists as Linux/cloud/network-only. Each rule spec is now
# assigned a concrete target platform drawn from the technique's real ATT&CK
# platform list, and the prompt receives the matching log-source guidance.
# ---------------------------------------------------------------------------

# Preference order when a technique supports several platforms. Reflects MSSP
# reality (what customers actually forward) rather than raw ATT&CK counts:
# endpoint + identity + cloud first, niche platforms last.
PLATFORM_PRIORITY = [
    "Windows", "Linux", "Identity Provider", "Office Suite", "SaaS", "IaaS",
    "Containers", "Network Devices", "macOS", "ESXi", "PRE",
]

# Platform -> the log sources and UDM shapes a rule for that platform should use.
PLATFORM_GUIDANCE = {
    "Windows": ("EDR process telemetry / Sysmon-equivalent, Windows Security event log, "
                "PowerShell script-block logging. Typical UDM: PROCESS_LAUNCH, "
                "REGISTRY_MODIFICATION, FILE_CREATION, USER_LOGIN."),
    "Linux": ("Linux EDR or auditd, syslog. Use Linux path conventions "
              "(/etc, /var, /tmp, /proc, cron paths, systemd units) - never Windows paths. "
              "Typical UDM: PROCESS_LAUNCH, FILE_CREATION, FILE_MODIFICATION."),
    "macOS": ("macOS EDR or unified log. Use macOS conventions (launchd plists, "
              "/Library, /Users/*/Library, osascript). Typical UDM: PROCESS_LAUNCH, "
              "FILE_CREATION."),
    "IaaS": ("Cloud provider audit logs (AWS CloudTrail, Azure Activity, GCP Audit). "
             "Typical UDM: USER_RESOURCE_ACCESS, RESOURCE_CREATION, "
             "RESOURCE_PERMISSIONS_CHANGE, USER_LOGIN. No endpoint process fields."),
    "SaaS": ("SaaS application audit logs. Typical UDM: USER_RESOURCE_ACCESS, "
             "USER_LOGIN, USER_RESOURCE_UPDATE_CONTENT. No endpoint process fields."),
    "Office Suite": ("Microsoft 365 / Google Workspace unified audit logs. Typical UDM: "
                     "USER_LOGIN, USER_RESOURCE_ACCESS, EMAIL_TRANSACTION, "
                     "SETTING_MODIFICATION. No endpoint process fields."),
    "Identity Provider": ("Identity provider sign-in and directory audit logs (Entra ID, "
                          "Okta, ADFS). Typical UDM: USER_LOGIN, USER_CHANGE_PERMISSIONS, "
                          "USER_CREATION, GROUP_MODIFICATION. No endpoint process fields."),
    "Containers": ("Container runtime and Kubernetes audit logs. Typical UDM: "
                   "PROCESS_LAUNCH (in-container), RESOURCE_CREATION, "
                   "USER_RESOURCE_ACCESS."),
    "Network Devices": ("Network device syslog / management-plane logs and flow records. "
                        "Typical UDM: USER_LOGIN, SETTING_MODIFICATION, NETWORK_FLOW, "
                        "NETWORK_CONNECTION. No endpoint process fields."),
    "ESXi": ("ESXi host logs (hostd, vmkernel, shell). Typical UDM: USER_LOGIN, "
             "PROCESS_LAUNCH, SETTING_MODIFICATION."),
    "PRE": ("Pre-compromise / external-facing telemetry only (scanning, DNS, web logs). "
            "Typical UDM: NETWORK_DNS, NETWORK_HTTP, NETWORK_CONNECTION."),
}


def choose_platforms(tech: dict, n: int, allowed: list[str] | None = None,
                     balance: bool = True) -> list[str]:
    """Pick a target platform for each of n variants of a technique.

    Respects the technique's real ATT&CK platforms (so a Linux-only technique
    never yields a Windows rule) and rotates through them so multi-platform
    techniques produce genuine diversity instead of n Windows rules.

    With balance=True, the starting point rotates deterministically per
    technique. Without it, every single-rule technique would land on the same
    top-priority platform (Windows), which is how a 500-rule set ends up ~70%
    Windows even though most techniques are multi-platform.
    """
    plats = [p for p in PLATFORM_PRIORITY if p in (tech.get("platforms") or [])]
    if allowed:
        filtered = [p for p in plats if p in allowed]
        plats = filtered or plats          # never leave a technique with nothing
    if not plats:
        plats = ["Windows"]                # ATT&CK listed none - safe default
    offset = 0
    if balance and len(plats) > 1:
        # Stable per-technique rotation (not random - same input, same output).
        offset = sum(ord(c) for c in tech.get("id", "")) % len(plats)
    return [plats[(i + offset) % len(plats)] for i in range(n)]



# ---------------------------------------------------------------------------
# Log-source families (library mix)
#
# The supervisor's model: the shared library is weighted mostly firewall /
# Windows / Linux with coverage of commonly-seen sources, and a later per-client
# step selects from it based on that client's log-source profile. Every rule is
# therefore stamped with a machine-readable log_source so selection is possible
# without parsing prose.
#
# Taxonomy and weights live in log_sources.json - edit that, not this file.
# ---------------------------------------------------------------------------
LOG_SOURCES: list[dict] = []


def load_log_sources() -> list[dict]:
    """Load the log-source taxonomy; empty list disables log-source targeting."""
    lp = Path(LOG_SOURCE_FILE).expanduser()
    if not lp.is_file():
        return []
    try:
        fams = json.loads(lp.read_text(encoding="utf-8")).get("families", [])
    except Exception as e:
        print(f"  (Could not read {lp}: {e} - continuing without log-source targeting.)")
        return []
    # Compatibility guard: without 'tactics' the eligibility check degrades to
    # "any platform match", which produces impossible pairings (e.g. Windows
    # registry persistence assigned to firewall logs) and mass model refusals.
    missing = [f.get("id", "?") for f in fams if "tactics" not in f]
    if missing:
        print("\n  " + "!" * 68)
        print("  OUTDATED log_sources.json - these families have no 'tactics' field:")
        print("    " + ", ".join(missing))
        print("  Without it, techniques get assigned to log sources that cannot")
        print("  possibly observe them, and the model will refuse most rules.")
        print("  Download the current log_sources.json before running a batch.")
        print("  " + "!" * 68 + "\n")
        if not ask("  Continue anyway? (y/n)", "n").lower().startswith("y"):
            die("Update log_sources.json, then re-run.")
    return fams


def families_for(tech: dict) -> list[dict]:
    """Families this technique can plausibly be detected through.

    Requires BOTH a platform match and a tactic match. Platform alone is far too
    loose - it would make every Windows technique 'eligible' for firewall logs,
    including registry persistence, which cannot be detected there at all. Those
    impossible pairings make the model refuse the rule outright.
    """
    plats = set(tech.get("platforms") or [])
    tacts = set(tech.get("tactics") or [])

    # PRIMARY signal: MITRE's own analytics name the log sources that can detect
    # each technique. This is ground truth - tactic-based guessing produced
    # impossible pairings (registry persistence assigned to identity logs).
    declared = tech.get("log_families")
    if declared:
        out = [f for f in LOG_SOURCES if f["id"] in declared]
        if out:
            return out

    # Fallback for techniques with no MITRE analytics: platform + tactic match.
    out = []
    for f in LOG_SOURCES:
        if not (plats & set(f.get("platforms", []))):
            continue
        ftacts = f.get("tactics", ["*"])
        if "*" in ftacts or (tacts & set(ftacts)):
            out.append(f)
    if out:
        return out
    # Fallback 1: prefer a dedicated endpoint/control-plane family for the platform.
    for fid in ("windows_endpoint", "linux_endpoint", "macos_endpoint",
                "cloud_audit", "vmware_esxi", "container"):
        f = next((x for x in LOG_SOURCES if x["id"] == fid), None)
        if f and plats & set(f.get("platforms", [])):
            return [f]
    # Fallback 2: any family that at least serves this platform (ignore tactic).
    byplat = [f for f in LOG_SOURCES if plats & set(f.get("platforms", []))]
    if byplat:
        return byplat
    # Nothing can observe this technique - caller skips it rather than assigning
    # an impossible log source.
    return []


def assign_log_sources(specs: list[dict]) -> None:
    """Assign a log-source family to every spec, steering the overall mix toward
    the configured weights while only ever choosing families the technique can
    actually support. Deterministic: same inputs, same assignment."""
    if not LOG_SOURCES:
        return
    weights = {f["id"]: max(0.001, float(f.get("weight", 1))) for f in LOG_SOURCES}
    assigned: dict[str, int] = {f["id"]: 0 for f in LOG_SOURCES}
    total_w = sum(weights.values())

    # Order deterministically, then greedily pick the eligible family that is
    # furthest below its target share so far.
    for n, spec in enumerate(sorted(specs, key=lambda s: (s["id"], s["variant"])), 1):
        elig = families_for(spec["technique"])
        if not elig:
            spec["no_log_source"] = True
            continue
        # A rule already pinned to a platform should stay consistent with it.
        plat = spec.get("platform")
        if plat:
            pref = [f for f in elig if plat in f.get("platforms", [])]
            elig = pref or elig
        best, best_gap = elig[0], -9e9
        for f in elig:
            target = weights[f["id"]] / total_w * n
            gap = target - assigned[f["id"]]
            if gap > best_gap:
                best, best_gap = f, gap
        assigned[best["id"]] += 1
        # The 'telemetry' pivot is explicitly endpoint-centric (registry, file,
        # process handle). On a network/identity log source it contradicts the
        # log-source requirement, so switch to a compatible angle.
        NON_ENDPOINT = {"firewall", "ips", "dns"}
        if best["id"] in NON_ENDPOINT and spec.get("pivot") in ("telemetry", "lineage"):
            spec["pivot"] = "network"
            spec["pivot_label"] = PIVOTS["network"]["label"]
        spec["log_source"] = best["id"]
        spec["log_source_label"] = best["label"]
        spec["log_source_guidance"] = best.get("guidance", "")
        spec["log_source_events"] = best.get("udm_events", [])


def summarize_log_sources(specs: list[dict]) -> None:
    if not LOG_SOURCES or not any(s.get("log_source") for s in specs):
        return
    import collections
    c = collections.Counter(s.get("log_source", "?") for s in specs)
    tot = max(len(specs), 1)
    targets = {f["id"]: f.get("weight", 0) for f in LOG_SOURCES}
    tw = sum(targets.values()) or 1
    print("\n  By log source family (actual vs target mix):")
    for f in LOG_SOURCES:
        n = c.get(f["id"], 0)
        print(f"      {n:>5}  {f['label'][:44]:<46} "
              f"{100*n/tot:>3.0f}%  (target {100*targets[f['id']]/tw:>3.0f}%)")


# The five differentiation pivots. Each produces a genuinely different rule for
# the same technique instead of another regex over the same telemetry.
PIVOTS = {
    "telemetry": {
        "label": "Telemetry abstraction level",
        "instruction": (
            "Pivot on the LEVEL of telemetry. Do NOT write a command-line/process-creation "
            "rule. Instead detect this technique at a different abstraction layer: the "
            "resulting file artifact (FILE_CREATION / FILE_MODIFICATION), a registry state "
            "change (REGISTRY_MODIFICATION), a process handle request (PROCESS_OPEN), or a "
            "configuration change (SETTING_MODIFICATION). Attackers can evade command-line "
            "logging far more easily than the state change their action produces."
        ),
    },
    "platform": {
        "label": "Alternate platform",
        "instruction": (
            "Pivot on PLATFORM. Assume Windows coverage already exists. Write this rule for "
            "Linux, macOS, or a cloud/SaaS control plane instead, using the mechanisms native "
            "to that platform (cron/systemd paths, launchd, cloud audit events). State the "
            "platform in meta.platform."
        ),
    },
    "lineage": {
        "label": "Parent-child lineage anomaly",
        "instruction": (
            "Pivot on PROCESS LINEAGE. Rather than detecting the action itself, detect it "
            "originating from an unexpected parent process (for example an Office application, "
            "a web server process, a print spooler, or a database service spawning a shell or "
            "script interpreter). Use principal.process.file.full_path for the parent and "
            "target.process.file.full_path for the child."
        ),
    },
    "network": {
        "label": "Network-side observation",
        "instruction": (
            "Pivot to the NETWORK side. Assume endpoint coverage exists. Detect the network "
            "behaviour characteristic of this technique using NETWORK_CONNECTION, NETWORK_DNS, "
            "or NETWORK_HTTP. Exclude internal address space via a reference list rather than "
            "hardcoding ranges."
        ),
    },
    "sequence": {
        "label": "Multi-event sequence (correlation)",
        "instruction": (
            "Write a CORRELATION rule: two events joined over a time window. Follow the "
            "correlation requirements in the system prompt exactly (shared placeholder "
            "variable, that variable declared in match, explicit chronological ordering, "
            "aggregation functions in outcome). Pre-filter BOTH events narrowly so the join "
            "cannot produce a Cartesian explosion."
        ),
    },
    "baseline": {
        "label": "Primary behavioral detection",
        "instruction": (
            "Write the primary, highest-fidelity single-event detection for this technique - "
            "the most direct behavioral signal, targeting the OS mechanism the technique "
            "depends on."
        ),
    },
    "threshold": {
        "label": "Threshold / aggregation",
        "instruction": (
            "Write a THRESHOLD rule: the individual event is benign, the volume is not. "
            "Aggregate over a time window, group by the NARROWEST entity (a single user or a "
            "single source host - never the whole tenant), and use a count condition. Set a "
            "conservative count and scale severity in outcome rather than making the "
            "threshold aggressive."
        ),
    },
}

# Time window defaults by technique family (per consultation guidance).
FAST_TECHNIQUES = ("T1055", "T1059", "T1071", "T1105", "T1027", "T1140")
SLOW_TECHNIQUES = ("T1078", "T1486", "T1041", "T1053", "T1530")


def default_window(tech_id: str, rule_type: str) -> str:
    """Pick a correlation/aggregation window appropriate to the technique."""
    parent = tech_id.split(".")[0]
    if rule_type == "threshold":
        return "1h" if parent in SLOW_TECHNIQUES else "10m"
    if parent in FAST_TECHNIQUES:
        return "5m"
    if parent in SLOW_TECHNIQUES:
        return "1h"
    return "10m"


# ---------------------------------------------------------------------------
# Rule spec allocation ("Top 10 heavy")
# ---------------------------------------------------------------------------
def build_rule_specs(techniques: list[dict], covered: set[str],
                     pidx: dict[str, tuple[int, str]], include_subs: bool,
                     depth_priority: int, depth_gap: int, depth_tail: int,
                     max_per_technique: int = 8,
                     allowed_platforms: list[str] | None = None,
                     balance_platforms: bool = True) -> list[dict]:
    """Expand techniques into individual rule specs.

    Three populations, each with its own rule count:
      - priority-tier techniques ALREADY covered -> `depth_priority` rules each
        (this is what makes the run "Top 10 heavy" - existing coverage means
        gap-filling alone can never reach the target)
      - priority-tier techniques NOT covered      -> `depth_gap` rules each
      - long-tail techniques NOT covered          -> `depth_tail` rules each
    """
    specs: list[dict] = []

    # Pivot sequences, ordered so the most valuable angle comes first when a
    # technique gets fewer rules than the full set.
    covered_pivots = ["telemetry", "sequence", "lineage", "network", "platform"]
    gap_pivots     = ["baseline", "sequence", "threshold", "telemetry", "lineage"]
    tail_pivots    = ["baseline", "telemetry", "lineage"]

    for t in techniques:
        if not include_subs and t["sub"]:
            continue
        tid = t["id"]
        # Respect platform scope: a technique that exists only on excluded
        # platforms (e.g. macOS-only when macOS is out of scope) is skipped
        # entirely rather than forced onto an unrelated log source.
        if allowed_platforms and t.get("platforms"):
            if not (set(t["platforms"]) & set(allowed_platforms)):
                continue
        rank, tier = rank_of(tid, pidx)
        is_priority = rank != 999
        parent_covered = tid.split(".")[0] in covered
        is_covered = tid in covered or (t["sub"] and parent_covered)

        if is_priority and is_covered:
            n, pivots, population = depth_priority, covered_pivots, "priority-covered (depth)"
        elif is_priority and not is_covered:
            n, pivots, population = depth_gap, gap_pivots, "priority-gap"
        elif not is_covered:
            n, pivots, population = depth_tail, tail_pivots, "long-tail gap"
        else:
            continue        # covered, not a priority technique -> skip

        n = min(n, max_per_technique, len(pivots))
        plats = choose_platforms(t, n, allowed_platforms, balance_platforms)
        for i in range(n):
            pivot = pivots[i]
            rule_type = ("correlation" if pivot == "sequence"
                         else "threshold" if pivot == "threshold"
                         else "single-event")
            specs.append({
                "technique": t, "id": tid, "pivot": pivot,
                "pivot_label": PIVOTS[pivot]["label"],
                "rule_type": rule_type,
                "window": default_window(tid, rule_type),
                "variant": i + 1, "of": n,
                "priority_tier": rank, "priority_label": tier,
                "population": population,
                "already_covered": is_covered,
                "platform": plats[i],
            })
    return specs


def manual_specs(techniques: list[dict], covered: set[str],
                 pidx: dict[str, tuple[int, str]]) -> list[dict]:
    """Interactive manual mode: the operator names specific techniques and how
    many rules each should get. Useful for ad-hoc requests ('give me 5 rules
    for T1078') without running the full allocation."""
    by_id = {t["id"]: t for t in techniques}
    by_parent: dict[str, list[dict]] = {}
    for t in techniques:
        by_parent.setdefault(t["id"].split(".")[0], []).append(t)

    print("\nManual mode. Enter technique IDs (e.g. T1078), separated by commas.")
    print("  - A parent ID includes its sub-techniques unless you decline.")
    print("  - Type part of a name to search (e.g. 'phishing').")
    raw = ask("Technique ID(s) or search term")
    if not raw.strip():
        return []

    # Resolve each token: exact ID, retired ID (remapped), or name search.
    chosen: list[dict] = []
    for token in [x.strip() for x in raw.split(",") if x.strip()]:
        tid = token.upper()
        tid = ID_REMAP.get(tid, tid)
        if tid in by_id:
            t = by_id[tid]
            subs = [s for s in by_parent.get(tid, []) if s["sub"]] if "." not in tid else []
            chosen.append(t)
            if subs:
                if ask(f"  {tid} has {len(subs)} sub-technique(s). Include them? (y/n)",
                       "y").lower().startswith("y"):
                    chosen.extend(subs)
            continue
        # Name search fallback
        matches = [t for t in techniques if token.lower() in t["name"].lower()]
        if not matches:
            print(f"  '{token}' not found (no ID or name match). Skipping.")
            continue
        print(f"  Matches for '{token}':")
        for i, m in enumerate(matches[:15], 1):
            cov = "covered" if m["id"] in covered else "GAP"
            print(f"    {i:>2}. {m['id']:<12} {m['name'][:48]:<50} [{cov}]")
        sel = ask("  Pick numbers (comma-separated), or Enter to skip", "")
        for s in sel.split(","):
            s = s.strip()
            if s.isdigit() and 1 <= int(s) <= min(len(matches), 15):
                chosen.append(matches[int(s) - 1])

    # De-duplicate, preserve order
    seen: set[str] = set()
    chosen = [t for t in chosen if not (t["id"] in seen or seen.add(t["id"]))]
    if not chosen:
        return []

    print(f"\n  Selected {len(chosen)} technique(s):")
    for t in chosen:
        cov = "already covered" if t["id"] in covered else "GAP (uncovered)"
        print(f"    {t['id']:<12} {t['name'][:50]:<52} [{cov}]")

    # Rules per technique + pivot order
    n = int(ask(f"\nRules per technique (max {min(8, len(PIVOTS)-0)})", "3") or 3)
    n = max(1, min(n, 8))

    print("\nAngle order (each rule takes the next angle in sequence):")
    default_order = ["baseline", "telemetry", "sequence", "lineage", "network",
                     "platform", "threshold"]
    for i, p in enumerate(default_order, 1):
        print(f"    {i}. {p:<10} - {PIVOTS[p]['label']}")
    order_raw = ask("Custom order as comma-separated numbers, or Enter for default", "")
    if order_raw.strip():
        try:
            order = [default_order[int(x) - 1] for x in order_raw.split(",")
                     if x.strip().isdigit()]
        except IndexError:
            print("  Invalid order - using default.")
            order = default_order
    else:
        order = default_order

    specs: list[dict] = []
    for t in chosen:
        is_covered = t["id"] in covered or t["id"].split(".")[0] in covered
        rank, tier = rank_of(t["id"], pidx)
        take = order[:n] if n <= len(order) else order
        plats = choose_platforms(t, len(take))
        for i, pivot in enumerate(take, 1):
            rule_type = ("correlation" if pivot == "sequence"
                         else "threshold" if pivot == "threshold"
                         else "single-event")
            specs.append({
                "technique": t, "id": t["id"], "pivot": pivot,
                "pivot_label": PIVOTS[pivot]["label"],
                "rule_type": rule_type,
                "window": default_window(t["id"], rule_type),
                "variant": i, "of": len(take),
                "priority_tier": rank, "priority_label": tier,
                "population": "manual selection",
                "already_covered": is_covered,
                "platform": plats[i - 1],
            })
    print(f"\n  Planned: {len(specs)} rule(s) across {len(chosen)} technique(s).")
    return specs


def summarize_specs(specs: list[dict]) -> None:
    """Report the planned allocation before spending any tokens."""
    import collections
    by_pop = collections.Counter(s["population"] for s in specs)
    by_type = collections.Counter(s["rule_type"] for s in specs)
    print("\n  Planned rule allocation:")
    for k, v in sorted(by_pop.items()):
        print(f"      {v:>5}  {k}")
    print(f"      {'-' * 40}")
    print(f"      {len(specs):>5}  TOTAL rules")
    print("\n  By rule type:")
    total = max(len(specs), 1)
    for k, v in sorted(by_type.items()):
        print(f"      {v:>5}  {k:<14} ({100 * v / total:.0f}%)")
    corr = by_type.get("correlation", 0) + by_type.get("threshold", 0)
    print(f"    (Consultation guidance: keep stateful rules near 20%; "
          f"currently {100 * corr / total:.0f}%)")
    by_plat = collections.Counter(s.get("platform", "?") for s in specs)
    print("\n  By target platform / log source family:")
    for k, v in by_plat.most_common():
        print(f"      {v:>5}  {k:<20} ({100 * v / total:.0f}%)")
    win = 100 * by_plat.get("Windows", 0) / total
    if win > 70:
        print(f"    WARNING: {win:.0f}% Windows - consider raising depth so multi-platform")
        print("             techniques get non-Windows variants, or restrict platforms.")


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
BANNED_SUMMARY = (
    "PROHIBITED (the rule will be rejected):\n"
    "  - File hashes (file.md5 / file.sha1 / file.sha256) as detection logic\n"
    "  - Hardcoded IP addresses, domains, or URLs\n"
    "  - Named attacker tool filenames (attackers rename binaries immediately)\n"
    "  - Exact CVE payload strings - detect the RESULT of exploitation instead\n"
    "  - Hardcoded usernames, hostnames, or tenant-specific values\n"
    "  - Absolute user directory paths (use regex with a wildcard for the username)\n"
    "  - metadata.vendor_name or metadata.product_name (breaks vendor portability)\n"
)

DURABILITY_CHECKLIST = (
    "Before returning the rule, verify it passes ALL of these:\n"
    "  [ ] Rename test: still fires if the attacker renames their tool.\n"
    "  [ ] Recompile test: still fires if the file hash changes.\n"
    "  [ ] Infrastructure test: still fires if the attacker changes hosting/C2.\n"
    "  [ ] OS mechanism test: targets a fundamental OS behaviour (registry, service,\n"
    "      process handle, process lineage, scheduled task, auth event).\n"
    "  [ ] LOLBin test: if targeting a built-in binary, matches the COMBINATION of\n"
    "      malicious flags rather than a specific payload path.\n"
    "  [ ] Abstraction test: uses regex with `nocase` rather than exact strings.\n"
)

YARAL_EXAMPLE = r"""
rule MSSP_T1053_005_Scheduled_Task_System_Privilege {
  meta:
    author = "TELUS Automated Detection Pipeline"
    rule_type = "Single-Event"
    severity = "High"
    description = "Detects creation of a scheduled task configured to run with SYSTEM privileges."
    mitre_tactic = "Execution, Persistence, Privilege Escalation"
    mitre_technique = "T1053.005"
    mitre_technique_name = "Scheduled Task/Job: Scheduled Task"
    log_prerequisites = "Requires EDR process telemetry or Windows Event 4688."
    platform = "Windows"
    false_positives = "RMM tools, software deployment agents, authorized admin scripts."
    tuning_guidance = "Add the parent process path to %global_allowed_task_creators."

  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /\\schtasks\.exe$/ nocase
    $proc.target.process.command_line = /create/ nocase
    $proc.target.process.command_line = /\/ru\s+system/ nocase
    not $proc.principal.process.file.full_path in %global_allowed_task_creators

  outcome:
    $risk_score = max(75)
    $mitre_technique_id = array_distinct("T1053.005")
    $primary_entity = array_distinct($proc.principal.hostname)

  condition:
    $proc
}
"""

YARAL_CORRELATION_EXAMPLE = r"""
rule MSSP_T1105_Office_Spawns_Shell_Then_Network {
  meta:
    author = "TELUS Automated Detection Pipeline"
    rule_type = "Sequence"
    severity = "Critical"
    description = "Office application spawns a shell which then makes an external connection."
    mitre_tactic = "Command and Control"
    mitre_technique = "T1105"
    mitre_technique_name = "Ingress Tool Transfer"
    log_prerequisites = "Requires EDR process and network telemetry."
    platform = "Windows"
    false_positives = "Office add-ins retrieving external data; RMM tooling."
    tuning_guidance = "Add approved destinations to %global_allowed_office_destinations."

  events:
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.principal.process.file.full_path = /\\(winword|excel|powerpnt)\.exe$/ nocase
    $proc.target.process.file.full_path = /\\(cmd|powershell|pwsh)\.exe$/ nocase
    $proc.principal.hostname = $hostname

    $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.principal.process.file.full_path = /\\(cmd|powershell|pwsh)\.exe$/ nocase
    not $net.target.ip in %rfc1918_internal
    $net.principal.hostname = $hostname

    $proc.metadata.event_timestamp.seconds <= $net.metadata.event_timestamp.seconds

  match:
    $hostname over 5m

  outcome:
    $risk_score = max(90)
    $mitre_technique_id = array_distinct("T1105")
    $primary_entity = array_distinct($net.principal.hostname)
    $destination_ips = array_distinct($net.target.ip)

  condition:
    $proc and $net
}
"""


def system_prompt(language_key: str) -> str:
    if language_key == "kql":
        return (
            "You are a senior detection engineer at a managed security services provider "
            "writing production analytics rules for Microsoft Sentinel in KQL.\n\n"
            "Requirements:\n"
            "- Valid KQL, deployable as a Sentinel Scheduled Analytics Rule.\n"
            "- Use only real Sentinel/Defender tables and columns. NEVER invent a column "
            "name. If unsure whether a column exists, choose a different approach.\n"
            "- Commented header with technique, tactic, severity, data-source prerequisites, "
            "and false-positive notes.\n"
            "- Behavioral and durable logic only.\n\n"
            + BANNED_SUMMARY + "\n" + DURABILITY_CHECKLIST + "\n"
            "Return ONLY the KQL. No prose, no markdown fences."
        )

    return (
        "You are an expert Google SecOps (Chronicle) detection engineer at a "
        "multi-client managed security services provider, writing production YARA-L 2.0 "
        "rules.\n\n"
        "=== STRUCTURE ===\n"
        "Sections in order: rule <name> { meta: events: [match:] [outcome:] condition: }\n"
        "Rule name format: MSSP_<TECHNIQUE_ID_WITH_UNDERSCORES>_<ShortDescriptor>\n\n"
        "=== MANDATORY meta: FIELDS ===\n"
        "author, rule_type (\"Single-Event\" | \"Sequence\" | \"Threshold\"), severity, "
        "description, mitre_tactic, mitre_technique, mitre_technique_name, "
        "log_prerequisites, platform, log_source, false_positives, tuning_guidance.\n"
        "log_source must be the exact identifier given in the user message - a "
        "downstream tool matches rules to client log sources using it.\n\n"
        "=== MANDATORY outcome: VARIABLES (every rule) ===\n"
        "$risk_score (integer 1-100), $mitre_technique_id, $primary_entity.\n"
        "Downstream SOAR playbooks parse these by name, so the names must be exact.\n\n"
        "=== EVENT VARIABLE NAMING ===\n"
        "Use short, descriptive lowercase event variable names that reflect the event "
        "($proc, $net, $file, $reg, $auth, $cloud, $open, $inj). Never use generic "
        "names like $e, $event, or $e1.\n\n"
        "=== REGEX SYNTAX ===\n"
        "YARA-L regex literals do NOT support suffix flags. NEVER write /pattern/i "
        "or /pattern/gi - Chronicle rejects them at compile time. For case-"
        "insensitivity use the nocase keyword after the closing slash: "
        "/pattern/ nocase\n\n"
        "=== UDM DISCIPLINE ===\n"
        "Use ONLY these metadata.event_type values:\n  "
        + ", ".join(UDM_EVENT_TYPES) + "\n"
        "Rely on well-populated UDM fields: metadata.event_type, principal.hostname, "
        "target.hostname, principal.user.userid, target.process.command_line, "
        "principal.process.file.full_path (parent), target.process.file.full_path (child), "
        "target.ip, target.port, target.file.full_path, target.registry.registry_key, "
        "target.registry.registry_value_name.\n"
        "AVOID as core logic (frequently unpopulated): file hashes, principal.mac, "
        "security_result.action, deeply nested cloud field guesses.\n"
        "Each single-event rule targets EXACTLY ONE event type. Never OR across different "
        "event types - the nested field paths differ and the rule will not evaluate.\n\n"
        "=== CORRELATION RULES (only when asked) ===\n"
        "1. Join events with a shared placeholder variable "
        "($proc.principal.hostname = $hostname and $net.principal.hostname = $hostname). "
        "Omitting the join causes a Cartesian explosion and Chronicle will disable the rule.\n"
        "2. Every placeholder used to join events MUST appear in the match block.\n"
        "3. State chronological order explicitly: "
        "$proc.metadata.event_timestamp.seconds <= $net.metadata.event_timestamp.seconds\n"
        "4. In outcome, wrap all aggregated values in array_distinct(), max(), min(), "
        "or count(). Bare field references are invalid in a multi-event rule.\n"
        "5. Pre-filter BOTH sides narrowly. Never join unfiltered high-volume event types.\n"
        "6. condition must name the variables explicitly ($proc and $net). Never use "
        "'any of them' or 'all of them'.\n"
        "7. Aggregation functions belong in outcome only - never in events or match.\n\n"
        "=== MULTI-TENANT (MSSP) ===\n"
        "Rules run across many customers. Include at least one reference-list exclusion for "
        "tuning, e.g. not $proc.principal.process.file.full_path in %global_allowed_admin_tools. "
        "Reference lists use 'in' / 'not in', never '='. Threshold rules group by the "
        "narrowest entity (single user or host), not the tenant.\n\n"
        + BANNED_SUMMARY + "\n" + DURABILITY_CHECKLIST + "\n"
        "=== IF YOU CANNOT COMPLY ===\n"
        "If this technique cannot be detected behaviorally with the allowed event types and "
        "fields without hardcoding an indicator, do NOT invent logic. Return exactly:\n"
        "ERROR: CANNOT_TRANSLATE_BEHAVIORALLY\n\n"
        "=== REFERENCE EXAMPLES ===\n"
        "Single-event:\n" + YARAL_EXAMPLE + "\nCorrelation:\n" + YARAL_CORRELATION_EXAMPLE +
        "\nReturn ONLY the YARA-L rule. No prose, no markdown fences."
    )


def user_prompt(spec: dict, language_key: str) -> str:
    tech = spec["technique"]
    tactics = ", ".join(tactic_label(x) for x in tech["tactics"]) or "Unspecified"
    platforms = ", ".join(tech["platforms"]) or "Unspecified"
    desc = (tech.get("description") or "")[:1400]
    guidance = (tech.get("detection") or "").strip()[:900]
    target = "Microsoft Sentinel (KQL)" if language_key == "kql" else "Google SecOps YARA-L 2.0"
    pivot = PIVOTS[spec["pivot"]]

    plat = spec.get("platform", "Windows")
    parts = [
        f"Write ONE {target} detection rule.\n",
        f"MITRE technique : {tech['id']} - {tech['name']}",
        f"Tactic(s)       : {tactics}",
        f"ATT&CK platforms: {platforms}",
        f"TARGET PLATFORM : {plat}   <-- write the rule for THIS platform only",
        f"Rule type       : {spec['rule_type']}",
    ]
    if spec["rule_type"] in ("correlation", "threshold"):
        parts.append(f"Time window     : {spec['window']} (use this in the match block)")
    parts.append(f"Variant         : {spec['variant']} of {spec['of']} for this technique\n")

    parts.append(f"REQUIRED ANGLE - {pivot['label']}:\n{pivot['instruction']}\n")

    guidance = PLATFORM_GUIDANCE.get(plat, "")
    parts.append(
        f"PLATFORM REQUIREMENT ({plat}) - this is mandatory:\n"
        f"  {guidance}\n"
        f"  Set meta.platform = \"{plat}\". Use only file paths, process names, field\n"
        f"  values, and log sources that genuinely exist on {plat}. Do NOT write a\n"
        f"  Windows-style rule for a non-Windows platform - no C:\\ paths, .exe names,\n"
        f"  or registry keys unless the target platform is Windows.\n")

    if spec.get("log_source"):
        events = ", ".join(spec.get("log_source_events") or [])
        parts.append(
            f"LOG SOURCE REQUIREMENT ({spec['log_source_label']}) - mandatory:\n"
            f"  {spec.get('log_source_guidance','')}\n"
            f"  Prefer these UDM event types: {events}\n"
            f"  Add this line to meta so the rule can be matched to client log\n"
            f"  sources later:  log_source = \"{spec['log_source']}\"\n"
            f"  Write the rule using ONLY telemetry this log source actually\n"
            f"  produces. Never name a specific vendor product - Chronicle's UDM\n"
            f"  normalises vendors, so vendor names break portability.\n")

    if spec["already_covered"]:
        parts.append(
            "IMPORTANT: we ALREADY have at least one detection for this technique, and it is "
            "almost certainly a process-creation / command-line rule. A rule based on "
            "PROCESS_LAUNCH command-line matching would be a duplicate and will be rejected. "
            "You must deliver genuinely additive coverage via the required angle above.\n"
        )

    parts.append(f"Technique description (MITRE):\n{desc}\n")
    if guidance:
        parts.append(f"MITRE detection guidance:\n{guidance}\n")

    parts.append(
        "Deliver a rule that is deployable across multiple customer environments with "
        "minimal tuning, and name the realistic false-positive sources."
    )
    return "\n".join(parts)



# ---------------------------------------------------------------------------
# 5. Fuel iX client
# ---------------------------------------------------------------------------
def _fuelix_request(path: str, payload: dict | None = None, method: str = "POST") -> dict:
    url = f"{FUELIX_BASE_URL}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {FUELIX_API_KEY}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def list_models() -> list[str]:
    try:
        resp = _fuelix_request("/v1/models", method="GET")
        data = resp.get("data", resp if isinstance(resp, list) else [])
        return [m.get("id") for m in data if isinstance(m, dict) and m.get("id")]
    except Exception as e:
        print(f"  (Could not list models via /v1/models: {e})")
        return []


def choose_model() -> str:
    if FUELIX_MODEL_ENV:
        print(f"  Using model from .env: {FUELIX_MODEL_ENV}")
        return FUELIX_MODEL_ENV
    models = list_models()
    if not models:
        return ask("  Enter the Fuel iX model id to use", "claude-haiku-4-5")
    print("\n  Available Fuel iX models:")
    for i, m in enumerate(models, 1):
        print(f"    {i:>2}. {m}")
    sel = ask("  Pick a model number (small models are cheapest for batch runs)", "1")
    try:
        return models[int(sel) - 1]
    except (ValueError, IndexError):
        die("Invalid model selection.")


def generate_rule(model: str, spec: dict, language_key: str, retries: int = 2) -> str:
    payload = {
        "model": model,
        "temperature": REQUEST_TEMP,
        "messages": [
            {"role": "system", "content": system_prompt(language_key)},
            {"role": "user",   "content": user_prompt(spec, language_key)},
        ],
    }
    last_err = None
    for attempt in range(retries + 1):
        try:
            resp = _fuelix_request("/v1/chat/completions", payload)
            content = resp["choices"][0]["message"]["content"].strip()
            return _strip_fences(content)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="ignore")[:300]
            last_err = f"HTTP {e.code}: {body}"
        except Exception as e:
            last_err = str(e)
        if attempt < retries:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(last_err or "unknown error")


def fix_regex_suffix_flags(rule: str) -> tuple[str, int]:
    """Auto-repair Perl/JS-style regex suffix flags (/pattern/i), which are not
    valid YARA-L. Deterministic: drop the flags; if 'i' was present and the
    literal isn't already followed by nocase, append ' nocase'. Returns
    (fixed_rule, number_of_fixes)."""
    fixes = 0

    def _repl(m: re.Match) -> str:
        nonlocal fixes
        fixes += 1
        flags, trailing = m.group(1), m.group(2) or ""
        needs_nocase = "i" in flags and "nocase" not in trailing
        return "/" + (" nocase" if needs_nocase else "") + trailing

    # A closing '/' (not an escaped \/) followed by 1-3 flag letters, ending at
    # whitespace, a delimiter, or end of line.
    fixed = re.sub(r"(?<!\\)/([gimsx]{1,3})(\s+nocase)?(?=[\s,)\]]|$)",
                   _repl, rule, flags=re.M)
    return fixed, fixes


def _strip_fences(text: str) -> str:
    """Small models sometimes wrap output in ```...``` despite instructions."""
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", t)
        t = re.sub(r"\n```$", "", t)
    return t.strip()


# ---------------------------------------------------------------------------
# Light output validation (small models slip on YARA-L especially)
# ---------------------------------------------------------------------------
# Output validation
#
# Two layers:
#   1. validate_rule()  - structural + banned-pattern checks (regex based).
#   2. rule_fingerprint() - semantic dedup, so two rules that query the same
#      telemetry with different regexes are caught as redundant.
#
# NOTE: this is static checking only. It cannot confirm that a UDM field or
# Sentinel column actually exists. Chronicle's verifyRuleText API is the
# authoritative syntax check - see README.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# UDM field-path checking
#
# The failure this exists to catch: a rule that references a field which does
# not exist. It passes every structural check, then silently never fires. This
# is what happened with an early KQL rule that used a byte-count column on a
# table that has no such column.
#
# Offline checking cannot be exhaustive - the UDM schema is large. So we do two
# things: hard-flag paths whose top-level noun is not part of UDM at all (those
# are certainly wrong), and separately list paths we cannot confirm so a
# reviewer can spot-check them. Unconfirmed != wrong.
# ---------------------------------------------------------------------------

# Valid UDM top-level nouns. Anything else is not a UDM path.
UDM_NOUNS = {
    "metadata", "principal", "target", "src", "observer", "intermediary",
    "about", "network", "security_result", "additional", "extensions",
}

# Field paths we are confident exist and are commonly populated. Used to
# separate "known good" from "needs a look" - not an exhaustive schema.
UDM_KNOWN_PATHS = {
    # metadata
    "metadata.event_type", "metadata.event_timestamp", "metadata.event_timestamp.seconds",
    "metadata.product_event_type", "metadata.description", "metadata.url_back_to_product",
    "metadata.ingested_timestamp", "metadata.collected_timestamp", "metadata.id",
    # principal / target / src identity + host
    "hostname", "asset_id", "ip", "port", "mac", "namespace", "url", "domain.name",
    "administrative_domain", "natural_language_description",
    "user.userid", "user.user_display_name", "user.email_addresses",
    "user.windows_sid", "user.group_identifiers", "user.employee_id",
    "user.attribute.roles", "user.attribute.labels", "user.department",
    "user.title", "user.first_name", "user.last_name", "user.phone_numbers",
    "user.product_object_id", "user.account_type", "user.userid_alias",
    # process
    "process.pid", "process.command_line", "process.command_line_history",
    "process.file.full_path", "process.file.names", "process.file.md5",
    "process.file.sha256", "process.file.sha1", "process.file.size",
    "process.parent_process.pid", "process.parent_process.command_line",
    "process.parent_process.file.full_path", "process.product_specific_process_id",
    "process.access_mask", "process.integrity_level_rid", "process.token.elevation",
    # file
    "file.full_path", "file.names", "file.md5", "file.sha256", "file.sha1",
    "file.size", "file.mime_type", "file.file_type", "file.exif_info",
    # registry
    "registry.registry_key", "registry.registry_value_name",
    "registry.registry_value_data", "registry.registry_key_type",
    # resource / cloud
    "resource.name", "resource.resource_type", "resource.resource_subtype",
    "resource.id", "resource.parent", "resource.attribute.labels",
    "cloud.environment", "cloud.project.name", "cloud.availability_zone",
    "application", "labels", "asset.hostname", "asset.ip", "asset.asset_id",
    "asset.platform_software.platform", "location.name", "location.country_or_region",
    # network
    "network.application_protocol", "network.direction", "network.ip_protocol",
    "network.sent_bytes", "network.received_bytes", "network.session_duration",
    "network.session_id", "network.http.method", "network.http.response_code",
    "network.http.user_agent", "network.http.referral_url",
    "network.dns.questions.name", "network.dns.questions.type",
    "network.dns.answers.name", "network.dns.answers.data", "network.dns.response_code",
    "network.email.from", "network.email.to", "network.email.subject",
    "network.tls.client.ja3", "network.tls.server.certificate.issuer",
    # security_result
    "security_result.action", "security_result.action_details",
    "security_result.category", "security_result.severity", "security_result.summary",
    "security_result.rule_name", "security_result.rule_id", "security_result.description",
    "security_result.threat_name", "security_result.confidence",
    # Confirmed present in real generated rules - added so they stop being
    # reported as unverified.
    "resource.type", "resource.attribute.labels", "resource.attribute.labels.key",
    "resource.attribute.labels.value", "resource.attribute.creation_time",
    "resource.product_object_id", "resource.resource_namespace",
    "user.role_name", "user.attribute.permissions", "user.personal_address.country_or_region",
    "group.group_display_name", "group.product_object_id", "group.email_addresses",
    "group.attribute.labels",
    "network.http.request_url", "network.http.parsed_user_agent",
    "network.dns_domain", "network.parent_session_id", "network.asn",
    "process.file.ancestry", "process.parent_process.product_specific_process_id",
    "file.ancestry", "file.capabilities_tags", "file.signature_info.sigcheck.verified",
    "registry.registry_value_type",
    "cloud.project.id", "cloud.vendor_name", "cloud.machine_type",
    "location.state", "location.city", "asset.attribute.labels",
    "asset.software", "asset.platform_software.platform_version",
    "labels.key", "labels.value",
}

# Paths that look plausible but do not exist / are unreliable - hard-flag these.
UDM_BAD_PATHS = {
    "process.name": "use process.file.full_path or process.file.names",
    "process.path": "use process.file.full_path",
    "process.parent.command_line": "use process.parent_process.command_line",
    "process.parent.file.full_path": "use process.parent_process.file.full_path",
    "user.name": "use user.userid or user.user_display_name",
    "user.username": "use user.userid",
    "file.path": "use file.full_path",
    "file.name": "use file.names",
    "registry.key": "use registry.registry_key",
    "registry.value": "use registry.registry_value_name / registry_value_data",
    "hostname.name": "use hostname",
    "network.bytes_sent": "use network.sent_bytes",
    "network.bytes_received": "use network.received_bytes",
    "metadata.timestamp": "use metadata.event_timestamp",
    "metadata.eventtype": "use metadata.event_type",
    "command_line": "must be qualified, e.g. target.process.command_line",
}


# Optional: a real UDM schema file gives far better coverage than the curated
# list above. Drop `udm_field_schema.json` (from the MSS SIEM Rule Translator
# repo, re-exported from pySigma-backend-secops, LGPL-3.0) beside this script
# and it will be used automatically.
UDM_SCHEMA_FILE = os.getenv("UDM_SCHEMA_FILE", "udm_field_schema.json")
_udm_schema: dict = {}
_udm_valid_paths: set[str] = set()
_udm_event_types: set[str] = set()
_udm_valid_roots: set[str] = set()


def load_udm_schema() -> bool:
    """Load a real UDM schema if present. Returns True when loaded.

    Expansion mirrors the MSS SIEM Rule Translator's udm_schema.py: nouns route
    through the shared TopLevelFields["noun"] template, subtype references may be
    bare or @-prefixed, enum leaves terminate, and a per-branch repeat cap stops
    self-referencing types (parent_process -> @process) from recursing forever.
    """
    global _udm_schema, _udm_valid_paths, _udm_event_types, _udm_valid_roots
    f = Path(UDM_SCHEMA_FILE).expanduser()
    if not f.is_file():
        return False
    try:
        _udm_schema = json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  (could not read {f}: {e})")
        return False

    nouns = set(_udm_schema.get("Nouns", []))
    subtypes = _udm_schema.get("Subtypes", {})
    enums = _udm_schema.get("Enums", {})
    toplevel = _udm_schema.get("TopLevelFields", {})
    noun_template = toplevel.get("noun", {})
    _udm_event_types = set(enums.get("metadata.event_type", []))

    known: set[str] = set()
    REPEAT_CAP = 2

    def ref_target(value) -> str | None:
        if not isinstance(value, str) or value.startswith("@enum:"):
            return None
        name = value[1:] if value.startswith("@") else value
        return name if name in subtypes else None

    def walk(prefix: str, obj: dict, seen: dict) -> None:
        if not isinstance(obj, dict):
            return
        for fname, value in obj.items():
            path = f"{prefix}.{fname}" if prefix else fname
            known.add(path)
            if isinstance(value, str):
                if value.startswith("@enum:"):
                    continue
                bare = value[1:] if value.startswith("@") else value
                if bare in enums:
                    continue
            tgt = ref_target(value)
            if tgt is not None and seen.get(tgt, 0) < REPEAT_CAP:
                walk(path, subtypes[tgt], {**seen, tgt: seen.get(tgt, 0) + 1})

    for root, body in toplevel.items():
        if root == "noun" or root in nouns:
            continue
        if isinstance(body, dict) and body:
            walk(root, body, {})
    for noun in nouns:
        walk(noun, noun_template, {})

    _udm_valid_paths = known
    _udm_valid_roots = (set(toplevel) | nouns) - {"noun"}
    return bool(known)


def check_udm_fields(events: str) -> tuple[list[str], list[str]]:
    """Inspect UDM paths in an events block.

    Returns (hard_errors, unconfirmed_paths).
    """
    errors: list[str] = []
    unconfirmed: list[str] = []
    seen: set[str] = set()

    for m in re.finditer(r"\$[a-z_][a-z0-9_]*\.([a-z0-9_.]+)", events, re.IGNORECASE):
        path = m.group(1).rstrip(".")
        if path in seen:
            continue
        seen.add(path)

        # Explicit known-wrong paths first - these carry a corrective hint.
        _rel = ".".join(path.split(".")[1:]) if path.split(".")[0] in (
            "principal", "target", "src", "observer", "intermediary", "about") else path
        if _rel in UDM_BAD_PATHS or path in UDM_BAD_PATHS:
            hint = UDM_BAD_PATHS.get(_rel) or UDM_BAD_PATHS[path]
            errors.append(f"UDM: '{path}' is not a valid field - {hint}")
            continue

        # Schema-driven check when a real UDM schema is loaded. Fails OPEN:
        # an unrecognised path under a valid root is reported as unconfirmed
        # rather than wrong, since parts of the tree are intentionally opaque.
        if _udm_valid_paths:
            root = path.split(".")[0]
            if root not in (_udm_valid_roots or UDM_NOUNS):
                errors.append(f"UDM: '{path}' does not start with a valid UDM root")
            elif path in _udm_valid_paths:
                pass
            elif root in ("additional", "extensions"):
                pass
            else:
                rel = ".".join(path.split(".")[1:])
                known_leaf = any(k.endswith("." + rel) for k in _udm_valid_paths) \
                             if rel else False
                if not known_leaf:
                    unconfirmed.append(path)
            continue

        noun = path.split(".")[0]
        if noun not in UDM_NOUNS:
            errors.append(f"UDM: '{path}' does not start with a UDM noun "
                          f"({'/'.join(sorted(UDM_NOUNS))[:60]}...)")
            continue

        # strip the entity prefix so principal.process.pid == target.process.pid
        rest = ".".join(path.split(".")[1:]) if noun in (
            "principal", "target", "src", "observer", "intermediary", "about") else path

        if rest in UDM_BAD_PATHS:
            errors.append(f"UDM: '{path}' is not a valid field - {UDM_BAD_PATHS[rest]}")
        elif path in UDM_BAD_PATHS:
            errors.append(f"UDM: '{path}' is not a valid field - {UDM_BAD_PATHS[path]}")
        elif rest in UDM_KNOWN_PATHS or path in UDM_KNOWN_PATHS:
            continue
        elif noun == "additional" or noun == "extensions":
            continue                      # free-form by design
        else:
            unconfirmed.append(path)
    return errors, unconfirmed


# ---------------------------------------------------------------------------
# Chronicle / Google SecOps rule verification
#
# Uses the documented endpoint:
#   POST https://{endpoint}/v1alpha/{instance}:verifyRuleText
#   instance = projects/{project}/locations/{location}/instances/{instance}
#   body     = {"ruleText": "..."}
#   response = {"success": bool, "compilationDiagnostics": [...]}
# Requires OAuth scope cloud-platform (or chronicle) and IAM permission
# chronicle.rules.verifyRuleText on the instance.
#
# Configure EITHER the full URL, or the four parts, in .env:
#   CHRONICLE_VERIFY_URL=https://us-chronicle.googleapis.com/v1alpha/projects/P/locations/L/instances/I:verifyRuleText
# or
#   CHRONICLE_ENDPOINT=us-chronicle.googleapis.com
#   CHRONICLE_PROJECT=<gcp project number>
#   CHRONICLE_LOCATION=us
#   CHRONICLE_INSTANCE=<customer id>
#
# Token: access tokens expire (~1 hour), and a full library run takes longer.
# Prefer CHRONICLE_TOKEN_CMD so the script can mint a fresh one when needed:
#   CHRONICLE_TOKEN_CMD=gcloud auth print-access-token
# A static CHRONICLE_TOKEN also works for short runs.
# ---------------------------------------------------------------------------
_token_cache: dict[str, float | str] = {"value": "", "at": 0.0}


def chronicle_url() -> str:
    """Full verifyRuleText URL, from the explicit setting or assembled parts."""
    if CHRONICLE_VERIFY_URL:
        return CHRONICLE_VERIFY_URL
    if CHRONICLE_ENDPOINT and CHRONICLE_PROJECT and CHRONICLE_INSTANCE:
        loc = CHRONICLE_LOCATION or "us"
        return (f"https://{CHRONICLE_ENDPOINT}/v1alpha/projects/{CHRONICLE_PROJECT}"
                f"/locations/{loc}/instances/{CHRONICLE_INSTANCE}:verifyRuleText")
    return ""


def chronicle_token(force: bool = False) -> str:
    """Return an access token.

    Three sources, in priority order:
      1. CHRONICLE_SA_KEY - path to a service account JSON key. Best option:
         tokens are minted and refreshed automatically, no expiry problems.
         Requires the google-auth package.
      2. CHRONICLE_TOKEN_CMD - a shell command that prints a token
         (e.g. 'gcloud auth print-access-token').
      3. CHRONICLE_TOKEN - a static token; expires in ~1 hour.
    """
    import subprocess
    age = time.time() - float(_token_cache["at"] or 0)
    if not force and _token_cache["value"] and age < 2700:      # 45 min
        return str(_token_cache["value"])

    # 1. Service account key (preferred)
    if CHRONICLE_SA_KEY:
        key_path = Path(CHRONICLE_SA_KEY).expanduser()
        if not key_path.is_file():
            print(f"  (CHRONICLE_SA_KEY not found: {key_path})")
        else:
            try:
                from google.oauth2 import service_account
                from google.auth.transport.requests import Request as _GReq
                creds = service_account.Credentials.from_service_account_file(
                    str(key_path),
                    scopes=["https://www.googleapis.com/auth/cloud-platform"])
                creds.refresh(_GReq())
                _token_cache.update({"value": creds.token, "at": time.time()})
                return creds.token
            except ImportError:
                print("  (google-auth not installed - run:")
                print("     python -m pip install --proxy $FUELIX_PROXY google-auth)")
            except Exception as e:
                print(f"  (service account auth failed: {e})")
    if CHRONICLE_TOKEN_CMD:
        try:
            out = subprocess.run(CHRONICLE_TOKEN_CMD, shell=True, capture_output=True,
                                 text=True, timeout=90)
            tok = (out.stdout or "").strip().splitlines()[-1] if out.stdout.strip() else ""
            if tok:
                _token_cache.update({"value": tok, "at": time.time()})
                return tok
            print(f"  (token command produced no output)")
            print(f"     command: {CHRONICLE_TOKEN_CMD[:110]}")
            if out.stderr.strip():
                print(f"     stderr : {out.stderr.strip()[:160]}")
        except Exception as e:
            print(f"  (token command failed: {e})")
    if CHRONICLE_TOKEN:
        _token_cache.update({"value": CHRONICLE_TOKEN, "at": time.time()})
        return CHRONICLE_TOKEN
    return ""


def chronicle_configured() -> bool:
    return bool(chronicle_url() and
                (CHRONICLE_TOKEN or CHRONICLE_TOKEN_CMD or CHRONICLE_SA_KEY))


def chronicle_verify(rule: str, _retry: bool = True) -> tuple[bool | None, str]:
    """Submit a rule to Chronicle's verifier.

    Returns (ok, detail); ok is None when verification isn't configured or the
    verifier is unreachable (so a network problem never marks rules as broken).
    """
    url = chronicle_url()
    if not url:
        return None, "not configured"
    tok = chronicle_token()
    if not tok:
        return None, "no token available"
    try:
        req = urllib.request.Request(
            url, data=json.dumps({"ruleText": rule}).encode(), method="POST")
        req.add_header("Authorization", f"Bearer {tok}")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=60) as r:
            resp = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")[:300]
        if e.code in (401, 403) and _retry:
            # Token likely expired mid-run - mint a fresh one and try once more.
            chronicle_token(force=True)
            return chronicle_verify(rule, _retry=False)
        if e.code in (401, 403):
            return None, f"auth failed (HTTP {e.code}): {body[:160]}"
        return False, f"HTTP {e.code}: {body[:160]}"
    except Exception as e:
        return None, f"verifier unreachable: {e}"

    diags = resp.get("compilationDiagnostics") or []
    if resp.get("success") is True:
        # success can still carry warnings; surface the first if present.
        warn = next((d for d in diags
                     if str(d.get("severity", "")).upper().startswith("WARN")), None)
        if warn:
            return True, ("compiles (warning: "
                          + str(warn.get("message", ""))[:120] + ")")
        return True, "compiles"
    if not diags:
        return False, "verification failed (no diagnostics returned)"
    d = diags[0]
    msg = d.get("message") if isinstance(d, dict) else str(d)
    pos = ""
    if isinstance(d, dict) and d.get("position"):
        sl = d["position"].get("startLine")
        if sl:
            pos = f" (line {sl})"
        return False, f"{str(msg)[:180]}{pos}"
    return False, str(msg)[:180]


def verify_setup() -> None:
    """Self-test for Chronicle verification (run with --verify-setup).

    Submits a known-good and a known-bad rule so you can confirm the verifier is
    actually working before committing to a long run.
    """
    hr("=")
    print(" Chronicle rule verification - setup test")
    hr("=")
    print(f"  URL       : {chronicle_url() or '(not configured)'}")
    src = ("CHRONICLE_SA_KEY (service account)" if CHRONICLE_SA_KEY
           else "CHRONICLE_TOKEN_CMD" if CHRONICLE_TOKEN_CMD
           else "CHRONICLE_TOKEN (static)" if CHRONICLE_TOKEN else "(none)")
    print(f"  Token src : {src}")
    if not chronicle_url():
        print("\n  Set CHRONICLE_VERIFY_URL, or the four CHRONICLE_* parts, in .env.")
        hr(); return
    tok = chronicle_token(force=True)
    print(f"  Token     : {'obtained (' + str(len(tok)) + ' chars)' if tok else 'NOT OBTAINED'}")
    if not tok:
        print("\n  Could not get a token. Options:")
        print("    - service account key: set CHRONICLE_SA_KEY=/path/to/key.json")
        print("      (needs google-auth: pip install --proxy <your proxy> google-auth)")
        print("    - gcloud: install the Cloud SDK, run 'gcloud auth login'")
        print("    - static token: set CHRONICLE_TOKEN=<token> (expires ~1h)")
        hr(); return

    good = ('rule setup_test_valid {\n'
            '  meta:\n    author = "setup test"\n    severity = "Low"\n'
            '  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
            '  condition:\n    $e\n}')
    bad = ('rule setup_test_invalid {\n'
           '  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
           '    $e.target.process.command_line = /powershell/i\n'
           '  condition:\n    $e\n}')

    print("\n  [1] valid rule   ->", end=" ")
    ok, detail = chronicle_verify(good)
    print(f"{ok} - {detail}")
    print("  [2] invalid rule ->", end=" ")
    ok2, detail2 = chronicle_verify(bad)
    print(f"{ok2} - {detail2}")

    print()
    if ok is True and ok2 is False:
        print("  WORKING: valid rules pass, invalid rules are rejected.")
        print("  Verification will now run on every generated rule.")
    elif ok is None or ok2 is None:
        print("  NOT REACHABLE. Check the proxy allows *.googleapis.com, that you are")
        print("  on VPN, and that the instance path is correct.")
    elif ok is True and ok2 is True:
        print("  SUSPICIOUS: the deliberately-invalid rule also passed. Verify the")
        print("  URL points at verifyRuleText and not another method.")
    else:
        print("  Valid rule was rejected - the instance path or rule format may be wrong.")
        print(f"  Detail: {detail}")
    hr()


CANNOT_TRANSLATE = "CANNOT_TRANSLATE_BEHAVIORALLY"

# Banned indicator patterns (the "no IOC one-offs" constraint).
BANNED_PATTERNS = [
    (r"\b(md5|sha1|sha256)\s*=\s*[\"']", "hardcoded file hash"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "hardcoded IP address"),
    (r"https?://[^\s\"'/]+\.[a-z]{2,}", "hardcoded URL"),
    (r"metadata\.(vendor_name|product_name)", "vendor/product lock-in"),
    (r"\bCVE-\d{4}-\d{4,}", "CVE-specific artifact"),
    (r"C:\\\\?Users\\\\?[A-Za-z][A-Za-z0-9._-]*\\\\", "hardcoded user directory path"),
]

# Well-known offensive tool names that should not appear as detection logic.
BANNED_TOOL_NAMES = [
    "mimikatz", "psexec", "rubeus", "bloodhound", "sharphound", "covenant",
    "sliver", "cobaltstrike", "cobalt_strike", "metasploit", "meterpreter",
    "impacket", "secretsdump", "procdump", "lazagne", "rclone", "winpeas",
    "seatbelt", "certipy", "kerbrute", "responder", "chisel", "ligolo",
]

# IP-literal exceptions: private ranges used in exclusions are acceptable.
_IP_ALLOWED = re.compile(r"(10\.0\.0\.0|172\.16\.0\.0|192\.168\.0\.0|127\.0\.0\.1|0\.0\.0\.0)")


def _strip_comments(rule: str) -> str:
    """Remove comments so banned-pattern checks look at logic, not prose."""
    rule = re.sub(r"/\*.*?\*/", "", rule, flags=re.S)   # /* block comments */
    out = []
    for line in rule.splitlines():
        s = line.strip()
        if s.startswith("//") or s.startswith("#"):
            continue
        out.append(line.split("//")[0])                  # trailing // comments
    return "\n".join(out)


def _meta_block(rule: str) -> str:
    m = re.search(r"meta:(.*?)(?:events:|$)", rule, re.S)
    return m.group(1) if m else ""


def _events_block(rule: str) -> str:
    m = re.search(r"events:(.*?)(?:match:|outcome:|condition:|$)", rule, re.S)
    return m.group(1) if m else ""


def validate_rule(rule: str, language_key: str, spec: dict | None = None) -> list[str]:
    """Return a list of warnings. Empty list = passed all static checks."""
    warns: list[str] = []
    if not rule.strip():
        return ["empty output"]
    if CANNOT_TRANSLATE in rule:
        return ["model declined: cannot translate behaviorally"]

    logic = _strip_comments(rule)

    # --- banned indicator patterns (apply to both languages) ---
    for pat, label in BANNED_PATTERNS:
        for m in re.finditer(pat, logic, re.IGNORECASE):
            if label == "hardcoded IP address" and _IP_ALLOWED.search(m.group(0)):
                continue
            # An IP inside a reference-list exclusion line is acceptable.
            line = logic[max(0, m.start() - 120):m.end() + 40]
            if "%" in line and ("not in" in line or " in " in line):
                continue
            warns.append(f"BANNED: {label} ({m.group(0)[:40]})")
            break

    # Tool names are banned in DETECTION LOGIC only. Mentioning a tool in meta
    # prose (description, false_positives) is legitimate documentation.
    ev_logic = _strip_comments(_events_block(rule)).lower()
    for tool in BANNED_TOOL_NAMES:
        if tool in ev_logic:
            warns.append(f"BANNED: named attacker tool '{tool}' in detection logic")
            break

    if language_key == "kql":
        if "|" not in rule:
            warns.append("no KQL pipe operator found")
        return warns

    # --- YARA-L structural checks ---
    for section in ("rule ", "meta:", "events:", "condition:"):
        if section not in rule:
            warns.append(f"missing '{section.strip()}' section")

    meta = _meta_block(rule)
    for field in ("author", "rule_type", "severity", "description", "mitre_tactic",
                  "mitre_technique", "log_prerequisites", "platform",
                  "false_positives", "tuning_guidance"):
        if field not in meta:
            warns.append(f"meta missing '{field}'")

    if "outcome:" not in rule:
        warns.append("missing 'outcome:' section")
    else:
        outcome = rule.split("outcome:", 1)[1]
        for var in ("$risk_score", "$mitre_technique_id", "$primary_entity"):
            if var not in outcome:
                warns.append(f"outcome missing mandatory {var}")

    events = _events_block(rule)

    # Event variable naming: semantic lowercase names are fine ($proc, $open,
    # $inj). Only flag meaningless generic names that hurt readability.
    GENERIC_VAR = re.compile(r"^(e|ev|evt|event|e\d+|event\d+|x|var\d*)$")
    used_vars = set(re.findall(r"\$([a-z_][a-z0-9_]*)\.", events))
    for v in used_vars:
        if GENERIC_VAR.match(v):
            warns.append(f"generic event variable '${v}' - use a descriptive name "
                         f"($proc, $net, $open, ...)")

    # Event type must be on the allowlist
    valid_types = _udm_event_types or set(UDM_EVENT_TYPES)
    for et in re.findall(r'metadata\.event_type\s*=\s*"([A-Z_]+)"', events):
        if et not in valid_types:
            warns.append(f"unrecognised UDM event type '{et}'")

    # Reference lists must use in / not in
    for m in re.finditer(r"(=|!=)\s*%(\w+)", events):
        warns.append(f"reference list '%{m.group(2)}' used with '{m.group(1)}' (must use in/not in)")

    # Multi-event (correlation) specific checks
    event_vars = used_vars
    is_multi = len(event_vars) > 1
    placeholders: set[str] = set()
    if is_multi:
        if "match:" not in rule:
            warns.append("multi-event rule has no match block")
        else:
            match_block = rule.split("match:", 1)[1].split("\n\n")[0]
            # Placeholders assigned in events (e.g. '= $hostname') must be in match
            placeholders = {p for p in re.findall(r"=\s*\$([a-z_][a-z0-9_]*)\s*$",
                                                  events, re.M)
                            if p not in used_vars}
            for ph in placeholders:
                if ph not in match_block:
                    warns.append(f"join variable '${ph}' missing from match block "
                                 f"(Cartesian explosion risk)")
            if not re.search(r"over\s+\d+[smhd]", match_block):
                warns.append("match block missing 'over <window>'")
        if "event_timestamp" not in events:
            warns.append("multi-event rule missing explicit chronological ordering")
        if not placeholders and "match:" in rule:
            warns.append("multi-event rule has no shared join variable")

    # Aggregation functions must not appear outside outcome
    for fn in ("array_distinct(", "count(", "max(", "min("):
        if fn in events:
            warns.append(f"aggregation '{fn}' used in events block (belongs in outcome)")

    # Suffix flags after a regex literal (/foo/i, /foo/gi) are Perl/JS syntax,
    # NOT valid YARA-L - Chronicle will reject the rule at compile time.
    for line in events.splitlines():
        if re.search(r"=\s*(?:not\s+)?/.*/([gimsx]{1,3})(\s|$)", line.rstrip()):
            warns.append("INVALID: regex suffix flag (e.g. /pattern/i) is not "
                         "YARA-L syntax - use the 'nocase' keyword instead")
            break

    # Case-insensitivity on Windows path regexes. Accept YARA-L's `nocase`,
    # an inline RE2 `(?i)` flag, or manual character-class casing like [Cc].
    for line in events.splitlines():
        if not re.search(r"=\s*/[^\n]*(\\\\|\\.exe|\.exe)[^\n]*/", line):
            continue
        if "nocase" in line or "(?i)" in line:
            continue
        if re.search(r"\[[A-Za-z]{2}\]", line):     # manual [Cc] style casing
            continue
        warns.append("Windows path/exe regex without case-insensitivity "
                     "(add 'nocase' or '(?i)')")
        break

    # Multi-tenancy: expect at least one reference-list exclusion for tuning
    if "%" not in events:
        warns.append("no reference-list exclusion (needed for multi-tenant tuning)")

    if spec and spec.get("rule_type") == "correlation" and not is_multi:
        warns.append("correlation rule requested but only one event variable present")

    # UDM field-path checks: hard errors for fields that cannot exist.
    udm_errors, udm_unconfirmed = check_udm_fields(events)
    warns.extend(udm_errors)
    if udm_unconfirmed:
        # Surface separately at low severity - unconfirmed is not the same as wrong.
        warns.append("UDM-CHECK: unverified field path(s): "
                     + ", ".join(udm_unconfirmed[:5])
                     + (" ..." if len(udm_unconfirmed) > 5 else ""))

    # Log-source discipline: the machine-readable tag must be present and correct,
    # since per-client rule selection depends on it.
    if spec and spec.get("log_source"):
        got = re.search(r'log_source\s*=\s*"([^"]*)"', meta)
        if not got:
            warns.append("meta missing 'log_source' tag (needed for client matching)")
        elif got.group(1).strip() != spec["log_source"]:
            warns.append(f"log_source mismatch: requested {spec['log_source']}, "
                         f"rule declares '{got.group(1).strip()}'")

    # Platform discipline: declared platform should match what was requested, and a
    # non-Windows rule must not be full of Windows artifacts.
    if spec and spec.get("platform"):
        want = spec["platform"]
        declared = re.search(r'platform\s*=\s*"([^"]*)"', meta)
        got = declared.group(1).strip() if declared else ""
        if got and want.lower() not in got.lower() and got.lower() not in want.lower():
            warns.append(f"platform mismatch: requested {want}, rule declares '{got}'")
        if want not in ("Windows", "ESXi"):
            win_markers = re.findall(r"(C:\\\\|\.exe\b|registry\.registry_key|HKEY_|System32)",
                                     events, re.IGNORECASE)
            if win_markers:
                warns.append(f"Windows artifacts in a {want} rule "
                             f"(e.g. {win_markers[0]}) - wrong platform logic")

    return warns




def rule_fingerprint(rule: str, spec: dict) -> str:
    """Structural fingerprint for semantic dedup.

    Two rules that query the same event type with the same UDM fields on the
    same platform are redundant even if their regexes differ.
    """
    events = _events_block(rule)
    etypes = sorted(set(re.findall(r'metadata\.event_type\s*=\s*"([A-Z_]+)"', events)))
    fields = sorted({f for f in re.findall(
        r"\$[a-z_][a-z0-9_]*\.([a-z0-9_.]+)", events)
        if not f.startswith("metadata.event_timestamp")})
    meta = _meta_block(rule)
    plat = re.search(r'platform\s*=\s*"([^"]*)"', meta)
    platform = (plat.group(1) if plat else "").lower()
    return "|".join([spec["id"], ",".join(etypes), ",".join(fields[:8]), platform])



# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def test_connection() -> None:
    """Quick reachability check to Fuel iX (run with --test-connection)."""
    hr("=")
    print(" Fuel iX connection test")
    hr("=")
    print(f"  Base URL : {FUELIX_BASE_URL}")
    print(f"  Proxy    : {FUELIX_PROXY or '(none configured)'}")
    print(f"  API key  : {'set' if FUELIX_API_KEY else 'MISSING'}")
    if not FUELIX_API_KEY:
        die("FUELIX_API_KEY is not set in .env.")
    print("\n  Contacting /v1/models ...")
    try:
        models = list_models()
        if models:
            print(f"  SUCCESS - reachable. {len(models)} model(s) available.")
            print("  e.g.:", ", ".join(models[:5]))
        else:
            print("  Reached the server but got no model list back "
                  "(auth or endpoint issue - check the key).")
    except Exception as e:
        print(f"  FAILED - {e}")
        print("\n  If this is a timeout (WinError 10060): you're not reaching Fuel iX.")
        print("  - Confirm you're on the corporate network / VPN.")
        print("  - Set FUELIX_PROXY in .env to your company proxy and retry.")
    hr()


def diagnose() -> None:
    """Probe every network path to Fuel iX and classify what fails (run with --diagnose)."""
    import socket, ssl
    from urllib.parse import urlparse

    hr("=")
    print(" Fuel iX network diagnostic")
    hr("=")
    print(f"  FUELIX_BASE_URL : {FUELIX_BASE_URL}")
    print(f"  FUELIX_PROXY    : {FUELIX_PROXY or '(none)'}")
    print(f"  Python-detected proxies: {urllib.request.getproxies() or '{} (none)'}")

    api_host = urlparse(FUELIX_BASE_URL).hostname or "api.fuelix.ai"

    def tcp(host, port):
        try:
            socket.create_connection((host, port), timeout=8).close()
            return "OK - reachable"
        except Exception as e:
            return f"FAIL - {type(e).__name__}: {e}"

    print("\n  [1] Can Python open a TCP socket to the PROXY?")
    if FUELIX_PROXY:
        pu = urlparse(FUELIX_PROXY)
        print("      ", tcp(pu.hostname, pu.port or 8080))
    else:
        print("       (no proxy configured - skipped)")

    print(f"\n  [2] Can Python reach {api_host}:443 DIRECTLY (no proxy)?")
    print("      ", tcp(api_host, 443))

    def http_get(use_proxy: bool):
        try:
            if use_proxy and FUELIX_PROXY:
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": FUELIX_PROXY, "https": FUELIX_PROXY}))
            else:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            req = urllib.request.Request(f"{FUELIX_BASE_URL}/v1/models",
                                         headers={"Authorization": f"Bearer {FUELIX_API_KEY}"})
            opener.open(req, timeout=15)
            return "OK - HTTPS succeeded"
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code} (server answered - path works)"
        except ssl.SSLError as e:
            return f"SSL/CERTIFICATE error - proxy works but Python distrusts the cert: {e}"
        except Exception as e:
            return f"FAIL - {type(e).__name__}: {e}"

    print(f"\n  [3] HTTPS GET {api_host}/v1/models THROUGH the proxy:")
    print("      ", http_get(use_proxy=True))
    print(f"\n  [4] HTTPS GET {api_host}/v1/models DIRECT (no proxy):")
    print("      ", http_get(use_proxy=False))

    print("\n  How to read this:")
    print("   - [4] works (OK or HTTP 401/403) -> remove FUELIX_PROXY from .env; go direct.")
    print("   - [3] gives SSL/CERTIFICATE -> proxy is right; we add the corporate CA next.")
    print("   - [3] gives HTTP 407 -> proxy needs your login in the URL.")
    print("   - everything times out -> Fuel iX isn't reachable from this network path.")
    hr()


def main() -> None:
    hr("=")
    print(" MITRE ATT&CK Gap -> Detection Rule Generator (Fuel iX)")
    hr("=")
    if FUELIX_PROXY:
        print(f" Using proxy: {FUELIX_PROXY}")

    if not FUELIX_API_KEY:
        die("FUELIX_API_KEY is not set. Copy .env.example to .env and add your key.")

    if load_udm_schema():
        print(f" UDM schema: {len(_udm_valid_paths)} field paths, "
              f"{len(_udm_event_types)} event types ({UDM_SCHEMA_FILE})")
    else:
        print(f" UDM schema: using built-in curated list "
              f"(drop {UDM_SCHEMA_FILE} here for full coverage)")

    global LOG_SOURCES
    LOG_SOURCES = load_log_sources()
    if LOG_SOURCES:
        print(f" Log-source taxonomy: {len(LOG_SOURCES)} families from {LOG_SOURCE_FILE}")
    if chronicle_configured():
        print(" Chronicle compile verification: ENABLED")
    else:
        print(" Chronicle compile verification: off "
              "(run --verify-setup after adding CHRONICLE_* settings to .env)")

    # --- language choice (Jira spec: 1=KQL/Sentinel, 2=SecOps) ---
    print("\nTarget rule language:")
    print("  1 - KQL / Microsoft Sentinel")
    print("  2 - YARA-L 2.0 / Google SecOps")
    lang_sel = ask("Choose 1 or 2", "1")
    language_key = "kql" if lang_sel == "1" else "yaral" if lang_sel == "2" else None
    if language_key is None:
        die("Choose 1 or 2.")
    ext = ".kql" if language_key == "kql" else ".yaral"

    # --- coverage file ---
    print()
    path_str = ask("Path to TELUS coverage file (.csv or .json)")
    cov_path = Path(path_str).expanduser()
    if not cov_path.is_file():
        die(f"File not found: {cov_path}")

    # --- MITRE matrix ---
    print("\nLoading MITRE ATT&CK Enterprise matrix ...")
    version, techniques = load_mitre_techniques()
    print(f"  {len(techniques)} active techniques (v{version}).")

    include_subs = ask("Include sub-techniques in the gap analysis? (y/n)", "y").lower().startswith("y")

    # --- coverage + gaps ---
    covered = load_coverage(cov_path)
    gaps = compute_gaps(techniques, covered, include_subs)
    scope = "techniques + sub-techniques" if include_subs else "parent techniques only"
    print(f"\nGap analysis ({scope}): {len(gaps)} uncovered of "
          f"{sum(1 for t in techniques if include_subs or not t['sub'])} in scope.")
    if not gaps:
        print("No gaps found. Nothing to generate.")
        return

    # --- prioritization + "Top 10 heavy" rule allocation ---
    pcfg = load_priority()
    pidx: dict[str, tuple[int, str]] = {}
    if pcfg:
        pidx = build_priority_index(pcfg)
        print(f"\nPriority list loaded: {pcfg.get('name', PRIORITY_FILE)}")
        summarize_priority(gaps, pidx)
    else:
        print(f"\n(No priority file at '{PRIORITY_FILE}' - all techniques treated equally.)")

    print("\nGeneration mode:")
    print("  1 - Automatic ('Top 10 heavy' allocation across the whole matrix)")
    print("  2 - Manual (you name specific technique IDs)")
    mode = ask("Choose 1 or 2", "1")

    if mode == "2":
        specs = manual_specs(techniques, covered, pidx)
        if not specs:
            print("No rules to generate.")
            return
        assign_log_sources(specs)
        summarize_log_sources(specs)
    else:
        print("\nRule allocation ('Top 10 heavy'):")
        print("  Priority-tier techniques get multiple differentiated rules each - including")
        print("  ones already covered, since gap-filling alone cannot reach a 500-rule target.")
        dp = int(ask("  Rules per ALREADY-COVERED priority technique (depth)", "2") or 2)
        dg = int(ask("  Rules per UNCOVERED priority technique", "3") or 3)
        dt = int(ask("  Rules per UNCOVERED long-tail technique", "1") or 1)

        print("\n  Platform scope (controls log-source diversity):")
        print("    1 - All platforms ATT&CK lists (maximum diversity)")
        print("    2 - MSSP-common: Windows, Linux, Identity, Office, SaaS, IaaS,")
        print("        Containers, Network Devices, ESXi (excludes macOS)  [recommended]")
        print("    3 - Windows only")
        pscope = ask("  Choose 1-3", "2")
        allowed = (None if pscope == "1"
                   else ["Windows"] if pscope == "3"
                   else ["Windows", "Linux", "Identity Provider", "Office Suite",
                         "SaaS", "IaaS", "Containers", "Network Devices", "ESXi"])
        bal = ask("  Spread single-rule techniques across their platforms? "
                  "(n = Windows-first) (y/n)", "y").lower().startswith("y")

        specs = build_rule_specs(techniques, covered, pidx, include_subs, dp, dg, dt,
                                 allowed_platforms=allowed, balance_platforms=bal)
        if not specs:
            print("No rules to generate with these settings.")
            return
        specs.sort(key=lambda s: (s["priority_tier"], s["id"].split(".")[0],
                                  s["id"], s["variant"]))
        assign_log_sources(specs)
        summarize_specs(specs)
        summarize_log_sources(specs)

    # --- resume: skip specs already generated in earlier runs ---
    # (Not in manual mode - an explicit request means generate them regardless.)
    done = set() if mode == "2" else already_generated(language_key)
    if done:
        before = len(specs)
        remaining = [s for s in specs if f"{s['id']}#{s['variant']}" not in done]
        if len(remaining) < before:
            print(f"\nFound {len(done)} rule(s) already generated for "
                  f"{language_key.upper()} in '{OUTPUT_DIR}'.")
            print(f"  {before - len(remaining)} of the planned rules already exist.")
            if ask("  Skip those and continue where you left off? (y/n)",
                   "y").lower().startswith("y"):
                specs = remaining
                print(f"  {len(specs)} rule(s) remaining to generate.")
                if not specs:
                    print("Nothing left to generate. Done.")
                    return

    # --- use-case count (Jira spec: ask + enforce upper limit) ---
    print(f"\nUpper limit per run is {MAX_USE_CASES} (set via MAX_USE_CASES in .env).")
    n_str = ask(f"How many rules to generate this run? 1-{min(MAX_USE_CASES, len(specs))}",
                str(min(10, MAX_USE_CASES, len(specs))))
    try:
        n = int(n_str)
    except ValueError:
        die("Enter a number.")
    if n < 1:
        die("Must be >= 1.")
    if n > MAX_USE_CASES:
        print(f"  Capped to MAX_USE_CASES ({MAX_USE_CASES}).")
        n = MAX_USE_CASES
    n = min(n, len(specs))
    selected = specs[:n]
    gaps = specs          # so "remaining" reporting below stays accurate

    # --- model ---
    model = choose_model()

    # --- confirm before spending tokens ---
    print(f"\nAbout to generate {len(selected)} {language_key.upper()} rule(s) "
          f"using '{model}'.")
    print("First few targets:",
          ", ".join(f"{s['id']}v{s['variant']}({s['pivot']})" for s in selected[:5]),
          ("..." if len(selected) > 5 else ""))
    if not ask("Proceed? (y/n)", "y").lower().startswith("y"):
        print("Aborted.")
        return

    # --- generate ---
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = OUTPUT_DIR / f"{language_key}_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary_path = out_dir / "run_summary.json"
    started = time.time()
    consecutive_failures = 0
    seen_fingerprints: dict[str, str] = {}
    hr()
    for i, spec in enumerate(selected, 1):
        tech = spec["technique"]
        rank, tier = spec["priority_tier"], spec["priority_label"]
        tier_tag = f"[T{rank}]" if rank != 999 else "[--]"
        pct = 100 * i / len(selected)
        print(f"[{i}/{len(selected)} {pct:5.1f}%] {tier_tag} {spec['id']}"
              f" v{spec['variant']} {spec['pivot']:<9} {tech['name'][:34]}",
              "...", end=" ", flush=True)
        try:
            rule = generate_rule(model, spec, language_key)
            vtag = f"m{spec['variant']}" if spec.get("population") == "manual selection" \
                   else f"v{spec['variant']}"
            fname = f"{spec['id'].replace('.', '_')}_{vtag}_{spec['pivot']}{ext}"
            # Never overwrite an existing file - bump the tag until free.
            bump = spec['variant']
            while (out_dir / fname).exists():
                bump += 1
                fname = f"{spec['id'].replace('.', '_')}_{vtag[0]}{bump}_{spec['pivot']}{ext}"

            # Model declined (couldn't do it behaviorally) - record, don't write.
            if CANNOT_TRANSLATE in rule:
                print("DECLINED (not translatable behaviorally)")
                summary.append({"id": spec["id"], "name": tech["name"],
                                "variant": spec["variant"], "pivot": spec["pivot"],
                                "priority_tier": rank, "declined": True})
                consecutive_failures = 0
                time.sleep(REQUEST_PAUSE)
                continue

            # Deterministic auto-repairs (e.g. /pattern/i -> /pattern/ nocase)
            if language_key != "kql":
                rule, n_fixed = fix_regex_suffix_flags(rule)
            else:
                n_fixed = 0

            warns = validate_rule(rule, language_key, spec)

            # Authoritative compile check (skipped silently if not configured).
            compiles, detail = (chronicle_verify(rule) if language_key != "kql"
                                else (None, "n/a"))
            if compiles is False:
                warns.insert(0, f"CHRONICLE COMPILE FAILED: {detail}")

            # Semantic dedup: reject a rule that queries the same telemetry as an
            # earlier one for the same technique (different regex, same coverage).
            fp = rule_fingerprint(rule, spec)
            if fp in seen_fingerprints:
                warns.append(f"REDUNDANT: same telemetry fingerprint as "
                             f"{seen_fingerprints[fp]}")
            else:
                seen_fingerprints[fp] = fname

            header = _file_header(tech, language_key, model, version, spec)
            (out_dir / fname).write_text(header + rule + "\n", encoding="utf-8")
            fix_note = f" [auto-fixed {n_fixed}]" if n_fixed else ""
            if compiles is True:
                fix_note += " [compiles]"
            status = ("OK" if not warns
                      else f"WARN ({len(warns)}): {warns[0][:60]}") + fix_note
            print(status)
            summary.append({"id": spec["id"], "name": tech["name"],
                            "tactics": tech["tactics"], "variant": spec["variant"],
                            "pivot": spec["pivot"], "rule_type": spec["rule_type"],
                            "population": spec["population"],
                            "platform": spec.get("platform"),
                            "log_source": spec.get("log_source"),
                            "priority_tier": rank, "priority_label": tier,
                            "fingerprint": fp, "file": fname, "warnings": warns,
                            "auto_fixed": n_fixed,
                            "chronicle_verified": compiles})
            consecutive_failures = 0
        except Exception as e:
            print(f"FAILED - {e}")
            summary.append({"id": spec["id"], "name": tech["name"],
                            "variant": spec["variant"],
                            "priority_tier": rank, "error": str(e)})
            consecutive_failures += 1
            # Bail out rather than burn through hundreds of doomed calls (e.g. the
            # token expired mid-run, or the network dropped).
            if consecutive_failures >= 5:
                print("\n  5 consecutive failures - stopping early to avoid a wasted run.")
                print("  Check your connection/token, then re-run and choose 'skip' "
                      "at the resume prompt to continue where this left off.")
                break
        # Progress + ETA every 10 rules on longer runs.
        if len(selected) >= 20 and i % 10 == 0 and i < len(selected):
            elapsed = time.time() - started
            eta = (elapsed / i) * (len(selected) - i)
            ok = len([s for s in summary if "file" in s])
            print(f"      ... {ok} written, {len(summary) - ok} failed, "
                  f"~{eta / 60:.0f} min remaining")
        # Save after every rule so a crash or Ctrl+C never loses completed work.
        summary_path.write_text(json.dumps(
            {"run_id": run_id, "in_progress": i < len(selected),
             "completed": i, "planned": len(selected), "results": summary},
            indent=2), encoding="utf-8")
        time.sleep(REQUEST_PAUSE)

    # --- run summary ---
    elapsed = time.time() - started
    by_tier: dict[str, int] = {}
    plat_counts: dict[str, int] = {}
    for s in summary:
        if "file" in s:
            k = s.get("priority_label") or "Unprioritized (long tail)"
            by_tier[k] = by_tier.get(k, 0) + 1
            if s.get("platform"):
                plat_counts[s["platform"]] = plat_counts.get(s["platform"], 0) + 1
    meta = {
        "run_id": run_id, "attack_version": version, "model": model,
        "language": language_key, "coverage_file": str(cov_path),
        "covered_count": len(covered), "gap_count": len(gaps),
        "generated": len([s for s in summary if "file" in s]),
        "failed": len([s for s in summary if "error" in s]),
        "with_warnings": len([s for s in summary if s.get("warnings")]),
        "auto_fixed_total": sum(s.get("auto_fixed", 0) for s in summary),
        "chronicle_verified_ok": len([s for s in summary if s.get("chronicle_verified") is True]),
        "chronicle_verified_failed": len([s for s in summary if s.get("chronicle_verified") is False]),
        "elapsed_minutes": round(elapsed / 60, 1),
        "generated_by_priority_tier": by_tier,
        "generated_by_platform": plat_counts,
        "priority_list": (pcfg or {}).get("name"),
        "in_progress": False,
        "results": summary,
    }
    summary_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    hr()
    print(f"Done in {elapsed / 60:.1f} min. {meta['generated']} rule(s) written, "
          f"{meta['failed']} failed, {meta['with_warnings']} needing review, "
          f"{meta['auto_fixed_total']} issue(s) auto-repaired silently.")
    if by_tier:
        print("By priority tier:")
        for k, v in sorted(by_tier.items()):
            print(f"   {v:>4}  {k}")
    if plat_counts:
        print("By target platform:")
        for k, v in sorted(plat_counts.items(), key=lambda x: -x[1]):
            print(f"   {v:>4}  {k}")
    remaining = len(gaps) - len(selected)
    if remaining > 0:
        print(f"\n{remaining} gap(s) still ungenerated. Re-run and choose 'skip' at the "
              f"resume prompt to continue from here.")
    print(f"Output: {out_dir}")
    print(f"Summary: {summary_path}")


def _file_header(tech: dict, language_key: str, model: str, version: str,
                 spec: dict | None = None) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    tactics = ", ".join(tactic_label(x) for x in tech["tactics"])
    lines = [
        f"MITRE Technique : {tech['id']} - {tech['name']}",
        f"Tactic(s)       : {tactics}",
        f"ATT&CK version  : {version}",
        f"Generated by    : Fuel iX ({model}) via gap_ruleforge.py",
        f"Generated at    : {ts}",
        f"Reference       : {tech['url']}",
    ]
    if spec:
        lines[2:2] = [
            f"Rule variant    : {spec['variant']} of {spec['of']}  "
            f"(angle: {spec['pivot_label']})",
            f"Rule type       : {spec['rule_type']}"
            + (f", window {spec['window']}" if spec["rule_type"] != "single-event" else ""),
            f"Priority tier   : {spec['priority_label']}",
            f"Target platform : {spec.get('platform', 'n/a')}",
            f"Log source      : {spec.get('log_source_label', 'n/a')}",
        ]
    lines.append("NOTE: AI-generated. Review, tune, and test before production deployment.")
    lines.append("      Static checks only - verify UDM field names before deploying.")
    if language_key == "kql":
        return "".join(f"// {l}\n" for l in lines) + "\n"
    return "/*\n" + "".join(f"  {l}\n" for l in lines) + "*/\n\n"


if __name__ == "__main__":
    try:
        if "--verify-setup" in sys.argv:
            verify_setup()
        elif "--test-connection" in sys.argv:
            test_connection()
        elif "--diagnose" in sys.argv:
            diagnose()
        else:
            main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
