#!/usr/bin/env python3
"""
sentinel_collect.py — Query Microsoft Sentinel and produce normalized events JSON
──────────────────────────────────────────────────────────────────────────────────
Queries a Log Analytics workspace for all security-relevant event IDs/operations
and writes a normalized /tmp/sentinel_events.json for consumption by attack-heatmap.py.

Prerequisites:
    pip install azure-identity azure-monitor-query  (REST API mode)
    -- OR --
    az login && az extension add --name log-analytics  (CLI mode)

Usage:
    # Azure CLI mode (simplest)
    python sentinel_collect.py \
        --workspace-id <LOG_ANALYTICS_WORKSPACE_ID> \
        --days 30 \
        --output /tmp/sentinel_events.json

    # REST API mode (works in automation/CI)
    python sentinel_collect.py \
        --workspace-id <LOG_ANALYTICS_WORKSPACE_ID> \
        --mode api \
        --days 30 \
        --output /tmp/sentinel_events.json

    # Dry-run: print KQL queries without running them
    python sentinel_collect.py --workspace-id dummy --dry-run

Environment variables (REST API mode):
    AZURE_TENANT_ID       Azure tenant ID
    AZURE_CLIENT_ID       Service principal client ID
    AZURE_CLIENT_SECRET   Service principal client secret
    -- OR -- use DefaultAzureCredential (az login / managed identity)

Author: Adapted for Microsoft Sentinel from Anton Ovrutsky's #AIForBlueTeam Day 23
"""

import json
import argparse
import subprocess
import os
import sys
import time
from pathlib import Path
from datetime import timedelta, timezone, datetime


# ─────────────────────────────────────────────────────────────────────────────
# KQL Queries — one per relevant table
# Each returns columns: table, event_id, count
# ─────────────────────────────────────────────────────────────────────────────

def build_queries(days: int) -> dict:
    """Return dict of query_name → KQL string scoped to the lookback window."""
    timespan = f"P{days}D"  # ISO 8601 duration for REST API
    # Note: REST API accepts timespan; CLI uses --timespan flag

    queries = {

        # ── 1. Table Discovery ───────────────────────────────────────────────
        "discovery": """
union withsource=TableName *
| where TimeGenerated > ago({days}d)
| summarize EventCount=count() by TableName
| sort by EventCount desc
""".format(days=days),

        # ── 2. Windows Security Events ───────────────────────────────────────
        "security_events": """
SecurityEvent
| where TimeGenerated > ago({days}d)
| summarize count=count() by tostring(EventID)
| extend table="SecurityEvent", event_id=EventID
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 3. Sysmon via WindowsEvent ────────────────────────────────────────
        "sysmon_events": """
WindowsEvent
| where TimeGenerated > ago({days}d)
| where Channel == "Microsoft-Windows-Sysmon/Operational"
| summarize count=count() by tostring(EventID)
| extend table="WindowsEvent_Sysmon", event_id=EventID
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 4. PowerShell Script Block Logging ────────────────────────────────
        "powershell_events": """
WindowsEvent
| where TimeGenerated > ago({days}d)
| where Channel in (
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell"
  )
| summarize count=count() by tostring(EventID)
| extend table="WindowsEvent_PS", event_id=EventID
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 5. AppLocker ──────────────────────────────────────────────────────
        "applocker_events": """
WindowsEvent
| where TimeGenerated > ago({days}d)
| where Channel startswith "Microsoft-Windows-AppLocker"
| summarize count=count() by tostring(EventID)
| extend table="WindowsEvent_AppLocker", event_id=EventID
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 6. Azure Activity (ARM operations) ───────────────────────────────
        "azure_activity": """
AzureActivity
| where TimeGenerated > ago({days}d)
| extend op=tolower(OperationNameValue)
| summarize count=count() by op
| extend table="AzureActivity", event_id=op
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 7. Azure AD Audit Logs ────────────────────────────────────────────
        "audit_logs": """
AuditLogs
| where TimeGenerated > ago({days}d)
| extend op=tolower(OperationName)
| summarize count=count() by op
| extend table="AuditLogs", event_id=op
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 8. Azure AD Sign-in Logs ──────────────────────────────────────────
        "signin_logs": """
union SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs
| where TimeGenerated > ago({days}d)
| extend category = case(
    Type == "SigninLogs",                           "interactive",
    Type == "AADNonInteractiveUserSignInLogs",      "noninteractive",
    Type == "AADServicePrincipalSignInLogs",        "serviceprincipal",
    Type == "AADManagedIdentitySignInLogs",         "managedidentity",
    "unknown"
  )
| summarize count=count() by category
| extend table="SigninLogs", event_id=category
| project table, event_id, count
""".format(days=days),

        # ── 9. Office 365 Activity ────────────────────────────────────────────
        "office_activity": """
OfficeActivity
| where TimeGenerated > ago({days}d)
| extend op=tolower(Operation)
| summarize count=count() by op
| extend table="OfficeActivity", event_id=op
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 10. Linux Syslog ──────────────────────────────────────────────────
        "syslog": """
Syslog
| where TimeGenerated > ago({days}d)
| extend fac=tolower(Facility)
| summarize count=count() by fac
| extend table="Syslog", event_id=fac
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 11. Common Security Log (CEF) ─────────────────────────────────────
        "cef": """
CommonSecurityLog
| where TimeGenerated > ago({days}d)
| extend cat=tolower(coalesce(DeviceEventCategory, DeviceProduct, "network"))
| summarize count=count() by cat
| extend table="CommonSecurityLog", event_id=cat
| project table, event_id, count
| sort by count desc
""".format(days=days),

        # ── 12. MDE — DeviceProcessEvents ─────────────────────────────────────
        "mde_process": """
DeviceProcessEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceProcessEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),

        # ── 13. MDE — DeviceNetworkEvents ─────────────────────────────────────
        "mde_network": """
DeviceNetworkEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceNetworkEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),

        # ── 14. MDE — DeviceFileEvents ────────────────────────────────────────
        "mde_file": """
DeviceFileEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceFileEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),

        # ── 15. MDE — DeviceRegistryEvents ───────────────────────────────────
        "mde_registry": """
DeviceRegistryEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceRegistryEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),

        # ── 16. MDE — DeviceLogonEvents ───────────────────────────────────────
        "mde_logon": """
DeviceLogonEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceLogonEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),

        # ── 17. MDE — DeviceImageLoadEvents ──────────────────────────────────
        "mde_image_load": """
DeviceImageLoadEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceImageLoadEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),

        # ── 18. MDE — DeviceEvents (misc) ────────────────────────────────────
        "mde_events": """
DeviceEvents
| where TimeGenerated > ago({days}d)
| summarize count=count()
| extend table="DeviceEvents", event_id="_present"
| project table, event_id, count
""".format(days=days),
    }

    return queries


# ─────────────────────────────────────────────────────────────────────────────
# Azure CLI Backend
# ─────────────────────────────────────────────────────────────────────────────

def run_kql_cli(workspace_id: str, kql: str, days: int) -> list:
    """Run a KQL query via 'az monitor log-analytics query'. Returns list of row dicts."""
    cmd = [
        "az", "monitor", "log-analytics", "query",
        "--workspace", workspace_id,
        "--analytics-query", kql.strip(),
        "--timespan", f"P{days}D",
        "--output", "json",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            # Table might not exist — that's OK
            if "BadArgumentError" in result.stderr or "not found" in result.stderr.lower():
                return []
            print(f"    [warn] CLI error: {result.stderr.strip()[:200]}")
            return []
        data = json.loads(result.stdout)
        return data if isinstance(data, list) else []
    except subprocess.TimeoutExpired:
        print("    [warn] Query timed out")
        return []
    except Exception as e:
        print(f"    [warn] CLI exception: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Azure REST API Backend
# ─────────────────────────────────────────────────────────────────────────────

def run_kql_api(workspace_id: str, kql: str, days: int, token: str) -> list:
    """Run a KQL query via Log Analytics REST API. Returns list of row dicts."""
    import urllib.request
    import urllib.error

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    payload = json.dumps({
        "query": kql.strip(),
        "timespan": f"P{days}D",
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        if "BadArgumentError" in body or "not found" in body.lower():
            return []   # table doesn't exist in this workspace
        print(f"    [warn] API HTTP {e.code}: {body[:200]}")
        return []
    except Exception as e:
        print(f"    [warn] API exception: {e}")
        return []

    # Parse columnar response
    rows = []
    try:
        table = data["tables"][0]
        col_names = [c["name"] for c in table["columns"]]
        for row in table["rows"]:
            rows.append(dict(zip(col_names, row)))
    except (KeyError, IndexError):
        pass
    return rows


def get_api_token() -> str:
    """Acquire a token for Log Analytics API using azure-identity."""
    try:
        from azure.identity import DefaultAzureCredential
        cred  = DefaultAzureCredential()
        token = cred.get_token("https://api.loganalytics.io/.default")
        return token.token
    except ImportError:
        print("[!] azure-identity not installed. Run: pip install azure-identity")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Could not acquire token: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Normalization
# ─────────────────────────────────────────────────────────────────────────────

def normalize_rows(rows: list, expected_cols=("table", "event_id", "count")) -> list:
    """
    Accept rows from either the CLI or REST API backend.
    Both should return dicts with table/event_id/count if the KQL is correct.
    Handles minor column-name variations.
    """
    normalized = []
    for row in rows:
        # Column name aliasing
        table    = row.get("table")    or row.get("TableName")
        event_id = row.get("event_id") or row.get("EventID")  or row.get("op") or row.get("fac") or row.get("category")
        count    = row.get("count")    or row.get("EventCount") or row.get("count_", 0)

        if table and event_id is not None:
            normalized.append({
                "table":    str(table).strip(),
                "event_id": str(event_id).strip().lower(),
                "count":    int(count) if count else 0,
            })
    return normalized


# ─────────────────────────────────────────────────────────────────────────────
# Discovery + Filtering
# ─────────────────────────────────────────────────────────────────────────────

def discover_tables(run_fn) -> set:
    """Run the discovery query and return set of table names present in workspace."""
    queries = build_queries(30)
    rows    = run_fn(queries["discovery"])
    tables  = set()
    if rows:
        for row in rows:
            t = row.get("TableName") or row.get("table")
            if t:
                tables.add(t)
    print(f"[*] Discovered {len(tables)} tables in workspace")
    return tables


# ─────────────────────────────────────────────────────────────────────────────
# Main Collection
# ─────────────────────────────────────────────────────────────────────────────

TABLE_QUERY_MAP = {
    "SecurityEvent":        "security_events",
    "WindowsEvent":         ["sysmon_events", "powershell_events", "applocker_events"],
    "AzureActivity":        "azure_activity",
    "AuditLogs":            "audit_logs",
    "SigninLogs":            "signin_logs",
    "AADNonInteractiveUserSignInLogs": "signin_logs",
    "OfficeActivity":       "office_activity",
    "Syslog":               "syslog",
    "CommonSecurityLog":    "cef",
    "DeviceProcessEvents":  "mde_process",
    "DeviceNetworkEvents":  "mde_network",
    "DeviceFileEvents":     "mde_file",
    "DeviceRegistryEvents": "mde_registry",
    "DeviceLogonEvents":    "mde_logon",
    "DeviceImageLoadEvents":"mde_image_load",
    "DeviceEvents":         "mde_events",
}


def collect_all(workspace_id: str, mode: str, days: int) -> list:
    """Collect event data from all relevant Sentinel tables."""

    queries = build_queries(days)

    # Set up the backend runner
    if mode == "cli":
        def run(kql): return run_kql_cli(workspace_id, kql, days)
    else:
        token = get_api_token()
        def run(kql): return run_kql_api(workspace_id, kql, days, token)

    # Discover present tables first
    present_tables = discover_tables(run)

    all_events = []
    seen_queries = set()

    for table, query_key in TABLE_QUERY_MAP.items():
        # Check if table is present (or unknown — try anyway)
        if present_tables and table not in present_tables:
            continue

        # Flatten list-valued query keys
        keys = [query_key] if isinstance(query_key, str) else query_key

        for key in keys:
            if key in seen_queries:
                continue
            seen_queries.add(key)

            kql = queries.get(key, "")
            if not kql:
                continue

            print(f"  [→] Running query: {key} ...")
            rows = run(kql)

            if not rows:
                print(f"      (no results)")
                continue

            normalized = normalize_rows(rows)
            print(f"      {len(normalized)} event type(s) found")
            all_events.extend(normalized)

            # Small courtesy delay to avoid throttling
            time.sleep(0.3)

    # De-duplicate: keep max count per (table, event_id)
    deduped = {}
    for ev in all_events:
        key = (ev["table"], ev["event_id"])
        if key not in deduped or ev["count"] > deduped[key]["count"]:
            deduped[key] = ev

    result = list(deduped.values())
    print(f"\n[✓] Total unique (table, event_id) pairs: {len(result)}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect Microsoft Sentinel telemetry and produce normalized events JSON"
    )
    parser.add_argument("--workspace-id", required=True,
                        help="Log Analytics workspace ID (GUID)")
    parser.add_argument("--mode", choices=["cli", "api"], default="cli",
                        help="'cli' uses 'az monitor log-analytics query'; 'api' uses REST + azure-identity")
    parser.add_argument("--days", type=int, default=30,
                        help="Lookback window in days (default: 30)")
    parser.add_argument("--output", default="/tmp/sentinel_events.json",
                        help="Output file path for normalized events JSON")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print KQL queries without running them")
    args = parser.parse_args()

    if args.dry_run:
        queries = build_queries(args.days)
        for name, kql in queries.items():
            print(f"\n{'─'*60}\n  QUERY: {name}\n{'─'*60}")
            print(kql.strip())
        return

    print(f"[*] Collecting Sentinel telemetry")
    print(f"    Workspace : {args.workspace_id}")
    print(f"    Mode      : {args.mode}")
    print(f"    Lookback  : {args.days} days\n")

    events = collect_all(args.workspace_id, args.mode, args.days)

    if not events:
        print("[!] No events collected. Check workspace ID, credentials, and data connector status.")
        sys.exit(1)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"[✓] Sentinel events written → {args.output}")
    print(f"[→] Next step:")
    print(f"    python attack-heatmap.py \\")
    print(f"        --attack-json enterprise-attack.json \\")
    print(f"        --sentinel-events {args.output} \\")
    print(f"        --workspace '{args.workspace_id}' \\")
    print(f"        --days {args.days} \\")
    print(f"        --output /tmp/attack-navigator-layer.json\n")


if __name__ == "__main__":
    main()
