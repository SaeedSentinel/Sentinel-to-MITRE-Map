#!/usr/bin/env python3
"""
attack-heatmap.py — ATT&CK Navigator Layer Generator for Microsoft Sentinel
─────────────────────────────────────────────────────────────────────────────
Takes normalized Sentinel event data (produced by sentinel_collect.py) and
enterprise-attack.json (STIX), then outputs a Navigator v4.5-compatible layer.

Usage:
    python attack-heatmap.py \
        --attack-json enterprise-attack.json \
        --sentinel-events /tmp/sentinel_events.json \
        --workspace "my-sentinel-workspace" \
        --days 30 \
        --output /tmp/attack-navigator-layer.json

"""

import json
import argparse
import datetime
import sys
from pathlib import Path
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# SENTINEL TABLE/EVENT → ATT&CK Data Component Mapping
#
# Format: (table_key, event_identifier_lowercase) → [data_component_names]
#
# table_key conventions:
#   SecurityEvent          Windows Security Event Log
#   WindowsEvent_Sysmon    WindowsEvent where Channel = Sysmon/Operational
#   WindowsEvent_PS        WindowsEvent where Channel = PowerShell
#   WindowsEvent_AppLocker WindowsEvent where Channel = AppLocker
#   AzureActivity          Azure ARM operations (operationName lowercased)
#   AuditLogs              Azure AD audit ops (operationName lowercased)
#   SigninLogs             Azure AD sign-in category (lowercased)
#   OfficeActivity         O365 operation (lowercased)
#   Syslog                 Linux syslog facility (lowercased)
#   CommonSecurityLog      CEF DeviceEventClassID or generic category
#   DeviceProcessEvents    MDE table (all rows count)
#   DeviceNetworkEvents    MDE table
#   DeviceFileEvents       MDE table
#   DeviceRegistryEvents   MDE table
#   DeviceLogonEvents      MDE table
#   DeviceImageLoadEvents  MDE table
#   DeviceEvents           MDE table
# ─────────────────────────────────────────────────────────────────────────────

SENTINEL_EVENT_MAP = {
    # ─── SecurityEvent (Windows Security Log) ───────────────────────────────
    ("SecurityEvent", "4608"): ["Logon Session Creation"],
    ("SecurityEvent", "4616"): ["OS API Execution"],
    ("SecurityEvent", "4624"): ["Logon Session Creation"],
    ("SecurityEvent", "4625"): ["Logon Session Creation", "User Account Authentication"],
    ("SecurityEvent", "4627"): ["Group Membership"],
    ("SecurityEvent", "4634"): ["Logon Session Metadata"],
    ("SecurityEvent", "4647"): ["Logon Session Metadata"],
    ("SecurityEvent", "4648"): ["Logon Session Creation", "User Account Authentication"],
    ("SecurityEvent", "4657"): ["Windows Registry Key Modification"],
    ("SecurityEvent", "4663"): ["File Access"],
    ("SecurityEvent", "4670"): ["File Modification"],
    ("SecurityEvent", "4672"): ["Logon Session Creation"],
    ("SecurityEvent", "4688"): ["Process Creation"],
    ("SecurityEvent", "4689"): ["Process Termination"],
    ("SecurityEvent", "4697"): ["Service Creation"],
    ("SecurityEvent", "4698"): ["Scheduled Job"],
    ("SecurityEvent", "4700"): ["Scheduled Job"],
    ("SecurityEvent", "4702"): ["Scheduled Job"],
    ("SecurityEvent", "4703"): ["User Account Modification"],
    ("SecurityEvent", "4704"): ["User Account Modification"],
    ("SecurityEvent", "4705"): ["User Account Modification"],
    ("SecurityEvent", "4720"): ["User Account Creation"],
    ("SecurityEvent", "4722"): ["User Account Modification"],
    ("SecurityEvent", "4723"): ["User Account Modification"],
    ("SecurityEvent", "4724"): ["User Account Modification"],
    ("SecurityEvent", "4725"): ["User Account Modification"],
    ("SecurityEvent", "4726"): ["User Account Deletion"],
    ("SecurityEvent", "4728"): ["Group Membership"],
    ("SecurityEvent", "4729"): ["Group Membership"],
    ("SecurityEvent", "4732"): ["Group Membership"],
    ("SecurityEvent", "4733"): ["Group Membership"],
    ("SecurityEvent", "4740"): ["User Account Modification"],
    ("SecurityEvent", "4743"): ["User Account Deletion"],
    ("SecurityEvent", "4754"): ["Group Membership"],
    ("SecurityEvent", "4756"): ["Group Membership"],
    ("SecurityEvent", "4757"): ["Group Membership"],
    ("SecurityEvent", "4764"): ["Group Membership"],
    ("SecurityEvent", "4768"): ["Active Directory Credential Request"],
    ("SecurityEvent", "4769"): ["Active Directory Credential Request"],
    ("SecurityEvent", "4771"): ["User Account Authentication"],
    ("SecurityEvent", "4776"): ["User Account Authentication"],
    ("SecurityEvent", "4778"): ["Logon Session Creation"],
    ("SecurityEvent", "4779"): ["Logon Session Metadata"],
    ("SecurityEvent", "4793"): ["User Account Modification"],
    ("SecurityEvent", "4798"): ["User Account Metadata"],
    ("SecurityEvent", "4799"): ["Group Membership"],
    ("SecurityEvent", "4946"): ["Firewall Rule Modification"],
    ("SecurityEvent", "4947"): ["Firewall Rule Modification"],
    ("SecurityEvent", "4948"): ["Firewall Rule Modification"],
    ("SecurityEvent", "5136"): ["Active Directory Object Modification"],
    ("SecurityEvent", "5137"): ["Active Directory Object Creation"],
    ("SecurityEvent", "5139"): ["Active Directory Object Modification"],
    ("SecurityEvent", "5141"): ["Active Directory Object Deletion"],
    ("SecurityEvent", "5145"): ["File Access"],
    ("SecurityEvent", "5156"): ["Network Connection Creation", "Network Traffic Flow"],
    ("SecurityEvent", "5158"): ["Network Connection Creation"],
    ("SecurityEvent", "7045"): ["Service Creation"],
    ("SecurityEvent", "8222"): ["Process Creation"],

    # ─── Sysmon via WindowsEvent ─────────────────────────────────────────────
    ("WindowsEvent_Sysmon", "1"):  ["Process Creation"],
    ("WindowsEvent_Sysmon", "2"):  ["File Modification"],
    ("WindowsEvent_Sysmon", "3"):  ["Network Connection Creation", "Network Traffic Flow"],
    ("WindowsEvent_Sysmon", "4"):  ["Service Metadata"],
    ("WindowsEvent_Sysmon", "5"):  ["Process Termination"],
    ("WindowsEvent_Sysmon", "6"):  ["Driver Load", "Kernel Module Load"],
    ("WindowsEvent_Sysmon", "7"):  ["Module Load", "Image Load"],
    ("WindowsEvent_Sysmon", "8"):  ["Process Metadata"],
    ("WindowsEvent_Sysmon", "9"):  ["Drive Access"],
    ("WindowsEvent_Sysmon", "10"): ["Process Access", "OS API Execution"],
    ("WindowsEvent_Sysmon", "11"): ["File Creation"],
    ("WindowsEvent_Sysmon", "12"): ["Windows Registry Key Creation", "Windows Registry Key Deletion"],
    ("WindowsEvent_Sysmon", "13"): ["Windows Registry Key Modification"],
    ("WindowsEvent_Sysmon", "14"): ["Windows Registry Key Modification"],
    ("WindowsEvent_Sysmon", "15"): ["File Metadata"],
    ("WindowsEvent_Sysmon", "16"): ["Service Modification"],
    ("WindowsEvent_Sysmon", "17"): ["Named Pipe Metadata"],
    ("WindowsEvent_Sysmon", "18"): ["Named Pipe Metadata"],
    ("WindowsEvent_Sysmon", "19"): ["WMI Creation"],
    ("WindowsEvent_Sysmon", "20"): ["WMI Creation"],
    ("WindowsEvent_Sysmon", "21"): ["WMI Creation"],
    ("WindowsEvent_Sysmon", "22"): ["DNS Resolution", "Network Traffic Content"],
    ("WindowsEvent_Sysmon", "23"): ["File Deletion"],
    ("WindowsEvent_Sysmon", "24"): ["Process Metadata"],
    ("WindowsEvent_Sysmon", "25"): ["Process Modification"],
    ("WindowsEvent_Sysmon", "26"): ["File Deletion"],
    ("WindowsEvent_Sysmon", "29"): ["File Metadata"],

    # ─── PowerShell via WindowsEvent ─────────────────────────────────────────
    ("WindowsEvent_PS", "4100"): ["Command Execution", "Script Execution"],
    ("WindowsEvent_PS", "4103"): ["Command Execution", "Script Execution"],
    ("WindowsEvent_PS", "4104"): ["Script Execution", "Command Execution"],

    # ─── AppLocker via WindowsEvent ───────────────────────────────────────────
    ("WindowsEvent_AppLocker", "8003"): ["File Access"],
    ("WindowsEvent_AppLocker", "8004"): ["File Access"],
    ("WindowsEvent_AppLocker", "8006"): ["Script Execution"],
    ("WindowsEvent_AppLocker", "8007"): ["Script Execution"],

    # ─── Azure Resource Manager (AzureActivity) ──────────────────────────────
    ("AzureActivity", "microsoft.compute/virtualmachines/write"):              ["Instance Modification"],
    ("AzureActivity", "microsoft.compute/virtualmachines/delete"):             ["Instance Modification"],
    ("AzureActivity", "microsoft.compute/virtualmachines/runcommand/action"):  ["Command Execution"],
    ("AzureActivity", "microsoft.compute/snapshots/write"):                    ["Snapshot Creation"],
    ("AzureActivity", "microsoft.storage/storageaccounts/write"):              ["Cloud Storage Creation"],
    ("AzureActivity", "microsoft.storage/storageaccounts/delete"):             ["Cloud Storage Deletion"],
    ("AzureActivity", "microsoft.storage/storageaccounts/blobservices/write"): ["Cloud Storage Modification"],
    ("AzureActivity", "microsoft.network/networksecuritygroups/write"):        ["Firewall Rule Modification"],
    ("AzureActivity", "microsoft.network/networksecuritygroups/delete"):       ["Firewall Rule Modification"],
    ("AzureActivity", "microsoft.network/networksecuritygroups/securityrules/write"): ["Firewall Rule Modification"],
    ("AzureActivity", "microsoft.authorization/roleassignments/write"):        ["User Account Modification"],
    ("AzureActivity", "microsoft.authorization/roleassignments/delete"):       ["User Account Modification"],
    ("AzureActivity", "microsoft.authorization/roledefinitions/write"):        ["User Account Modification"],
    ("AzureActivity", "microsoft.keyvault/vaults/secrets/read"):               ["Cloud Service Metadata"],
    ("AzureActivity", "microsoft.keyvault/vaults/write"):                      ["Cloud Service Modification"],
    ("AzureActivity", "microsoft.keyvault/vaults/delete"):                     ["Cloud Service Modification"],
    ("AzureActivity", "microsoft.automation/automationaccounts/runbooks/write"):["Script Execution"],
    ("AzureActivity", "microsoft.automation/automationaccounts/jobs/write"):   ["Command Execution"],
    ("AzureActivity", "microsoft.web/sites/write"):                            ["Application Log Content"],
    ("AzureActivity", "microsoft.containerinstance/containergroups/write"):    ["Container Creation"],
    ("AzureActivity", "microsoft.containerservice/managedclusters/write"):     ["Container Creation"],
    ("AzureActivity", "microsoft.logic/workflows/write"):                      ["Script Execution"],

    # ─── Azure AD Audit Logs ──────────────────────────────────────────────────
    ("AuditLogs", "add user"):                       ["User Account Creation"],
    ("AuditLogs", "delete user"):                    ["User Account Deletion"],
    ("AuditLogs", "update user"):                    ["User Account Modification"],
    ("AuditLogs", "hard delete user"):               ["User Account Deletion"],
    ("AuditLogs", "restore user"):                   ["User Account Modification"],
    ("AuditLogs", "add member to role"):             ["User Account Modification", "Group Membership"],
    ("AuditLogs", "remove member from role"):        ["User Account Modification", "Group Membership"],
    ("AuditLogs", "add application"):                ["Application Log Content"],
    ("AuditLogs", "update application"):             ["Application Log Content"],
    ("AuditLogs", "delete application"):             ["Application Log Content"],
    ("AuditLogs", "add service principal"):          ["User Account Creation"],
    ("AuditLogs", "update service principal"):       ["User Account Modification"],
    ("AuditLogs", "delete service principal"):       ["User Account Deletion"],
    ("AuditLogs", "add owner to application"):       ["User Account Modification"],
    ("AuditLogs", "add member to group"):            ["Group Membership"],
    ("AuditLogs", "remove member from group"):       ["Group Membership"],
    ("AuditLogs", "add group"):                      ["Group Membership"],
    ("AuditLogs", "delete group"):                   ["Group Membership"],
    ("AuditLogs", "update group"):                   ["Group Membership"],
    ("AuditLogs", "reset user password"):            ["User Account Modification"],
    ("AuditLogs", "change user password"):           ["User Account Modification"],
    ("AuditLogs", "add oauth2permissiongrant"):      ["User Account Modification"],
    ("AuditLogs", "consent to application"):         ["User Account Modification"],
    ("AuditLogs", "update device"):                  ["Active Directory Object Modification"],
    ("AuditLogs", "add registered users to application"): ["User Account Modification"],
    ("AuditLogs", "issue an fido2 credential"):      ["User Account Authentication"],
    ("AuditLogs", "update conditional access policy"): ["Active Directory Object Modification"],

    # ─── Azure AD Sign-in Logs ────────────────────────────────────────────────
    ("SigninLogs", "interactive"):        ["Logon Session Creation", "User Account Authentication"],
    ("SigninLogs", "noninteractive"):     ["Logon Session Creation"],
    ("SigninLogs", "serviceprincipal"):   ["Logon Session Creation"],
    ("SigninLogs", "managedidentity"):    ["Logon Session Creation"],

    # ─── Office 365 Activity ──────────────────────────────────────────────────
    ("OfficeActivity", "fileuploaded"):         ["File Creation"],
    ("OfficeActivity", "filedownloaded"):       ["File Access"],
    ("OfficeActivity", "filedeleted"):          ["File Deletion"],
    ("OfficeActivity", "fileaccessed"):         ["File Access"],
    ("OfficeActivity", "filemodified"):         ["File Modification"],
    ("OfficeActivity", "mailboxlogin"):         ["Logon Session Creation"],
    ("OfficeActivity", "send"):                 ["Application Log Content"],
    ("OfficeActivity", "create"):               ["Application Log Content"],
    ("OfficeActivity", "set-mailboxpermission"):["User Account Modification"],
    ("OfficeActivity", "add-mailboxpermission"):["User Account Modification"],
    ("OfficeActivity", "set-transportrule"):    ["Application Log Content"],
    ("OfficeActivity", "new-transportrule"):    ["Application Log Content"],
    ("OfficeActivity", "set-inboxrule"):        ["Application Log Content"],
    ("OfficeActivity", "new-inboxrule"):        ["Application Log Content"],
    ("OfficeActivity", "searchqueryperformed"): ["Application Log Content"],
    ("OfficeActivity", "updatesharepointpermission"): ["User Account Modification"],

    # ─── Linux Syslog ─────────────────────────────────────────────────────────
    ("Syslog", "auth"):     ["Logon Session Creation", "User Account Authentication"],
    ("Syslog", "authpriv"): ["Logon Session Creation", "User Account Authentication"],
    ("Syslog", "cron"):     ["Scheduled Job"],
    ("Syslog", "kern"):     ["Kernel Module Load", "OS API Execution"],
    ("Syslog", "daemon"):   ["Service Metadata"],
    ("Syslog", "user"):     ["Application Log Content"],

    # ─── Common Security Log (CEF) ────────────────────────────────────────────
    ("CommonSecurityLog", "network"):   ["Network Traffic Flow", "Network Traffic Content"],
    ("CommonSecurityLog", "firewall"):  ["Network Traffic Flow"],
    ("CommonSecurityLog", "ids"):       ["Network Traffic Content"],
    ("CommonSecurityLog", "ips"):       ["Network Traffic Content"],
    ("CommonSecurityLog", "web"):       ["Application Log Content", "Network Traffic Content"],

    # ─── Defender for Endpoint (MDE tables) ──────────────────────────────────
    ("DeviceProcessEvents",    "_present"): ["Process Creation"],
    ("DeviceNetworkEvents",    "_present"): ["Network Connection Creation", "Network Traffic Flow"],
    ("DeviceFileEvents",       "_present"): ["File Creation", "File Modification", "File Deletion"],
    ("DeviceRegistryEvents",   "_present"): ["Windows Registry Key Creation", "Windows Registry Key Modification", "Windows Registry Key Deletion"],
    ("DeviceLogonEvents",      "_present"): ["Logon Session Creation", "User Account Authentication"],
    ("DeviceImageLoadEvents",  "_present"): ["Module Load", "Image Load"],
    ("DeviceEvents",           "_present"): ["Named Pipe Metadata", "DNS Resolution", "Command Execution", "WMI Creation"],
    ("DeviceAlertEvents",      "_present"): ["Application Log Content"],
}


# ─────────────────────────────────────────────────────────────────────────────
# ATT&CK STIX Parsing
# ─────────────────────────────────────────────────────────────────────────────

def load_attack_data(attack_json_path: str):
    """
    Parse enterprise-attack.json.
    Returns:
        techniques   dict[stix_id] → {id, name, tactics, ...}
        dc_by_name   dict[dc_name_lower] → stix_id
        dc_to_techs  dict[dc_stix_id]   → [technique_stix_ids]
        by_id        dict[stix_id]      → stix_object
    """
    print(f"[*] Loading ATT&CK data from: {attack_json_path}")
    with open(attack_json_path, encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    by_id = {obj["id"]: obj for obj in objects}

    # ── Techniques ────────────────────────────────────────────────────────────
    techniques = {}
    for obj in objects:
        if (obj.get("type") == "attack-pattern"
                and not obj.get("revoked")
                and not obj.get("x_mitre_deprecated")):
            ext = obj.get("external_references", [])
            tech_id = next(
                (r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"),
                None,
            )
            if tech_id:
                tactics = [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ]
                techniques[obj["id"]] = {
                    "id": tech_id,
                    "name": obj["name"],
                    "stix_id": obj["id"],
                    "tactics": tactics,
                    "data_components": [],
                }

    # ── Data Components ───────────────────────────────────────────────────────
    dc_by_name = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-data-component":
            dc_by_name[obj["name"].lower()] = obj["id"]

    # ── Detects relationships ─────────────────────────────────────────────────
    dc_to_techs = defaultdict(list)
    for obj in objects:
        if (obj.get("type") == "relationship"
                and obj.get("relationship_type") == "detects"):
            dc_id   = obj.get("source_ref", "")
            tech_id = obj.get("target_ref", "")
            if tech_id in techniques:
                dc_to_techs[dc_id].append(tech_id)
                dc_obj = by_id.get(dc_id)
                if dc_obj and dc_obj["name"] not in techniques[tech_id]["data_components"]:
                    techniques[tech_id]["data_components"].append(dc_obj["name"])

    print(f"    ✓ {len(techniques)} techniques, "
          f"{len(dc_by_name)} data components, "
          f"{sum(len(v) for v in dc_to_techs.values())} detects relationships")
    return techniques, dc_by_name, dc_to_techs, by_id


# ─────────────────────────────────────────────────────────────────────────────
# Coverage Calculation
# ─────────────────────────────────────────────────────────────────────────────

def compute_coverage(sentinel_events: list, techniques: dict,
                     dc_by_name: dict, dc_to_techs: dict, by_id: dict):
    """
    Map present sentinel events → data components → techniques.
    Returns dict[technique_id_str] → {score, matched_dcs, total_dcs}
    """
    # Build set of STIX data-component IDs present in the workspace
    present_dc_ids = set()
    matched_event_map = {}   # dc_id → list of (table, event_id)

    # Normalize sentinel events for lookup
    sentinel_lookup = set()
    for ev in sentinel_events:
        sentinel_lookup.add((str(ev["table"]).strip(), str(ev["event_id"]).strip().lower()))

    for (table, event_id_lower), dc_names in SENTINEL_EVENT_MAP.items():
        # MDE table presence check (event_id = "_present" means table exists)
        if event_id_lower == "_present":
            if any(ev["table"] == table for ev in sentinel_events):
                for dc_name in dc_names:
                    dc_id = dc_by_name.get(dc_name.lower())
                    if dc_id:
                        present_dc_ids.add(dc_id)
                        matched_event_map.setdefault(dc_id, []).append((table, "present"))
        else:
            if (table, event_id_lower) in sentinel_lookup:
                for dc_name in dc_names:
                    dc_id = dc_by_name.get(dc_name.lower())
                    if dc_id:
                        present_dc_ids.add(dc_id)
                        matched_event_map.setdefault(dc_id, []).append((table, event_id_lower))

    print(f"[*] Matched {len(present_dc_ids)} unique data components from Sentinel telemetry")

    # Score each technique
    coverage = {}
    for stix_id, tech in techniques.items():
        tech_id = tech["id"]

        # Data components that *can* detect this technique
        all_dcs = set()
        for dc_id, tech_stix_ids in dc_to_techs.items():
            if stix_id in tech_stix_ids:
                all_dcs.add(dc_id)

        if not all_dcs:
            coverage[tech_id] = {"score": -1, "matched_dcs": [], "total_dcs": 0}
            continue

        matched = present_dc_ids.intersection(all_dcs)
        score   = len(matched) / len(all_dcs)

        coverage[tech_id] = {
            "score":      score,
            "matched_dcs": [by_id[d]["name"] for d in matched if d in by_id],
            "total_dcs":   len(all_dcs),
        }

    return coverage


# ─────────────────────────────────────────────────────────────────────────────
# Navigator Layer Generation
# ─────────────────────────────────────────────────────────────────────────────

def _score_to_color(score: float) -> str:
    if score < 0:    return ""          # gray (no detection strategy)
    if score == 0:   return "#ff6b6b"   # red   — blind
    if score < 0.34: return "#ff9f43"   # orange — minimal
    if score < 0.67: return "#feca57"   # yellow — partial
    if score < 1.0:  return "#48dbfb"   # blue  — good
    return           "#1dd1a1"          # green — full


def generate_navigator_layer(coverage: dict, techniques: dict,
                              workspace: str, date_str: str, days: int) -> dict:
    """Produce a Navigator v4.5 layer dict."""
    entries = []
    for stix_id, tech in techniques.items():
        tech_id = tech["id"]
        cov     = coverage.get(tech_id, {"score": -1, "matched_dcs": [], "total_dcs": 0})
        score   = cov["score"]
        color   = _score_to_color(score)

        comment = ""
        if score >= 0 and cov["matched_dcs"]:
            comment = "Covered by: " + ", ".join(cov["matched_dcs"])
        elif score == 0:
            comment = "No matching Sentinel data components found"

        entry = {
            "techniqueID":       tech_id,
            "score":             max(0, round(score * 100)),
            "color":             color,
            "comment":           comment,
            "enabled":           True,
            "metadata":          [],
            "links":             [],
            "showSubtechniques": False,
        }
        entries.append(entry)

    layer = {
        "name":        f"Sentinel Coverage — {workspace} ({date_str}, {days}d lookback)",
        "versions":    {"attack": "16", "navigator": "5.1", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": (
            f"Generated from Microsoft Sentinel workspace '{workspace}' "
            f"on {date_str}. Covers {days}-day lookback window. "
            "Score = % of ATT&CK data components matched by present telemetry."
        ),
        "filters": {
            "platforms": [
                "Windows", "macOS", "Linux",
                "Azure", "Office 365", "Azure AD",
                "SaaS", "IaaS",
            ]
        },
        "sorting": 3,
        "layout": {
            "layout":                "side",
            "aggregateFunction":     "average",
            "showID":                True,
            "showName":              True,
            "showAggregateScores":   True,
            "countUnscored":         False,
            "expandedSubtechniques": "none",
        },
        "hideDisabled": False,
        "techniques":   entries,
        "gradient": {
            "colors":   ["#ff6b6b", "#ff9f43", "#feca57", "#48dbfb", "#1dd1a1"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Full Coverage (100%)",           "color": "#1dd1a1"},
            {"label": "Good Coverage (67–99%)",         "color": "#48dbfb"},
            {"label": "Partial Coverage (34–66%)",      "color": "#feca57"},
            {"label": "Minimal Coverage (1–33%)",       "color": "#ff9f43"},
            {"label": "No Coverage (0%)",               "color": "#ff6b6b"},
            {"label": "No Detection Strategy Defined",  "color": "#cccccc"},
        ],
        "metadata":                   [],
        "links":                      [],
        "showTacticRowBackground":    True,
        "tacticRowBackground":        "#1e3a5f",
        "selectTechniquesAcrossTactics":   True,
        "selectSubtechniquesWithParent":   False,
    }
    return layer


# ─────────────────────────────────────────────────────────────────────────────
# Coverage Report
# ─────────────────────────────────────────────────────────────────────────────

def print_report(coverage: dict, techniques: dict, workspace: str, days: int):
    total      = len(coverage)
    unscored   = sum(1 for v in coverage.values() if v["score"] < 0)
    zero_cov   = sum(1 for v in coverage.values() if v["score"] == 0)
    partial    = sum(1 for v in coverage.values() if 0 < v["score"] < 1)
    full_cov   = sum(1 for v in coverage.values() if v["score"] >= 1)
    scored     = total - unscored

    pct = (full_cov + partial) / scored * 100 if scored else 0

    print()
    print("═" * 70)
    print(f"  ATT&CK NAVIGATOR LAYER — SENTINEL COVERAGE REPORT")
    print(f"  Workspace : {workspace}  |  Lookback: {days} days")
    print("═" * 70)
    print(f"  Total techniques        : {total}")
    print(f"  No detection strategy   : {unscored}  (gray — ATT&CK has no data components)")
    print(f"  No coverage (0%)        : {zero_cov}  [red]")
    print(f"  Partial coverage        : {partial}   [orange/yellow/blue]")
    print(f"  Full coverage (100%)    : {full_cov}  [green]")
    print(f"  Overall coverage score  : {pct:.1f}%  (of techniques with detection strategies)")
    print("─" * 70)

    # Top 5 covered tactics
    tactic_scores = defaultdict(list)
    for stix_id, tech in techniques.items():
        tech_id = tech["id"]
        cov = coverage.get(tech_id, {})
        if cov.get("score", -1) >= 0:
            for tactic in tech["tactics"]:
                tactic_scores[tactic].append(cov["score"])

    print("\n  TOP COVERED TACTICS:")
    ranked = sorted(
        [(t, sum(s)/len(s)*100) for t, s in tactic_scores.items()],
        key=lambda x: x[1],
        reverse=True,
    )
    for tactic, avg in ranked[:5]:
        bar = "█" * int(avg / 5)
        print(f"    {tactic:<35} {avg:5.1f}%  {bar}")

    # Top 5 gaps (scored but 0 coverage)
    gaps = [
        (tech["id"], tech["name"])
        for stix_id, tech in techniques.items()
        if coverage.get(tech["id"], {}).get("score", -1) == 0
    ]
    if gaps:
        print(f"\n  ZERO-COVERAGE SAMPLE (first 5 of {len(gaps)}):")
        for tid, name in gaps[:5]:
            print(f"    [{tid}] {name}")

    print("═" * 70)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate ATT&CK Navigator layer from Microsoft Sentinel telemetry"
    )
    parser.add_argument("--attack-json",      required=True,  help="Path to enterprise-attack.json")
    parser.add_argument("--sentinel-events",  required=True,  help="Path to normalized Sentinel events JSON")
    parser.add_argument("--workspace",        default="sentinel", help="Workspace name (for layer label)")
    parser.add_argument("--date",             default=datetime.date.today().isoformat())
    parser.add_argument("--days",             type=int, default=30)
    parser.add_argument("--output",           required=True,  help="Output path for Navigator layer JSON")
    args = parser.parse_args()

    # Validate inputs
    for p in [args.attack_json, args.sentinel_events]:
        if not Path(p).exists():
            print(f"[!] File not found: {p}", file=sys.stderr)
            sys.exit(1)

    # Load data
    techniques, dc_by_name, dc_to_techs, by_id = load_attack_data(args.attack_json)

    with open(args.sentinel_events, encoding="utf-8") as f:
        sentinel_events = json.load(f)
    print(f"[*] Loaded {len(sentinel_events)} Sentinel event entries")

    # Compute coverage
    coverage = compute_coverage(sentinel_events, techniques, dc_by_name, dc_to_techs, by_id)

    # Generate layer
    layer = generate_navigator_layer(
        coverage, techniques, args.workspace, args.date, args.days
    )

    # Write output
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    print(f"[✓] Navigator layer saved → {args.output}")

    # Print report
    print_report(coverage, techniques, args.workspace, args.days)

    print("  HOW TO USE:")
    print("  1. Open https://mitre-attack.github.io/attack-navigator/")
    print('  2. Click "+" → "Open Existing Layer" → "Upload from local"')
    print(f"  3. Select: {args.output}")
    print("  4. Color scale: red=blind → orange → yellow → blue → green=full coverage\n")


if __name__ == "__main__":
    main()
