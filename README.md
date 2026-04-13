# ATT&CK Navigator Heatmap for Microsoft Sentinel

Generate a MITRE ATT&CK Navigator heatmap from your actual Sentinel telemetry — showing which techniques you have visibility into, and where your blind spots are.

---

## How It Works

```
Microsoft Sentinel          sentinel_collect.py         attack-heatmap.py
─────────────────     ─────────────────────────────   ──────────────────────────────
SecurityEvent         KQL queries via                  Parse enterprise-attack.json
WindowsEvent    ───▶  az CLI or REST API    ──JSON──▶  Map events → data components
AzureActivity         (17 table queries,              Map data components → techniques
AuditLogs             parallel where possible)        Score each technique (0–100%)
SigninLogs                                            Generate Navigator layer JSON
OfficeActivity
Syslog, CEF                                           ┌──────────────────────────┐
DeviceXxxEvents                                       │  attack-navigator-layer  │
                                                      │  .json  →  import into  │
                                                      │  navigator.mitre.org     │
                                                      └──────────────────────────┘
```

**Coverage score per technique** = % of ATT&CK data components (e.g. "Process Creation", "Network Connection", "Logon Session") that have matching telemetry present in your Sentinel workspace.

---

## Files

| File | Description |
|---|---|
| `sentinel_collect.py` | Queries Sentinel workspace, produces normalized events JSON |
| `attack-heatmap.py` | Maps events → ATT&CK data components → Navigator layer JSON |
| `sentinel-attack-nav.md` | Claude Desktop skill (for use with Claude Code / Claude Desktop) |
| `README.md` | This file |

---

## Prerequisites

### 1. Download ATT&CK STIX data (one-time, ~50 MB)

```bash
wget -O enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Or with curl:
```bash
curl -L -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### 2. Authenticate to Azure

**Option A — Azure CLI (simplest):**
```bash
pip install azure-cli        # if not installed
az login
az account set --subscription "<your-subscription-id>"
```

**Option B — Service Principal (automation/CI):**
```bash
pip install azure-identity
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<client-id>"
export AZURE_CLIENT_SECRET="<client-secret>"
```

### 3. Find your Sentinel Workspace ID

```bash
az monitor log-analytics workspace list \
  --query "[].{Name:name, WorkspaceID:customerId, ResourceGroup:resourceGroup}" \
  -o table
```

### 4. Ensure correct permissions

Your identity needs **Log Analytics Reader** role on the workspace (or Sentinel Reader):

```bash
az role assignment create \
  --role "Log Analytics Reader" \
  --assignee "<your-user-or-sp-id>" \
  --scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"
```

---

## Usage

### Step 1 — Collect Sentinel telemetry

```bash
# CLI mode (recommended for local use)
python sentinel_collect.py \
    --workspace-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    --days 30 \
    --output /tmp/sentinel_events.json

# REST API mode (recommended for automation)
python sentinel_collect.py \
    --workspace-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    --mode api \
    --days 30 \
    --output /tmp/sentinel_events.json

# Dry run — print KQL queries without running them
python sentinel_collect.py \
    --workspace-id dummy \
    --dry-run
```

### Step 2 — Generate the Navigator layer

```bash
python attack-heatmap.py \
    --attack-json enterprise-attack.json \
    --sentinel-events /tmp/sentinel_events.json \
    --workspace "my-sentinel-workspace" \
    --days 30 \
    --output /tmp/attack-navigator-layer.json
```

### Step 3 — Import into ATT&CK Navigator

1. Open **https://mitre-attack.github.io/attack-navigator/**
2. Click **"+"** → **"Open Existing Layer"** → **"Upload from local"**
3. Select `/tmp/attack-navigator-layer.json`

---

## Color Scale

| Color | Coverage | Meaning |
|---|---|---|
| 🟢 Green `#1dd1a1` | 100% | All ATT&CK data components present |
| 🔵 Blue `#48dbfb` | 67–99% | Good visibility |
| 🟡 Yellow `#feca57` | 34–66% | Partial visibility |
| 🟠 Orange `#ff9f43` | 1–33% | Minimal visibility |
| 🔴 Red `#ff6b6b` | 0% | Blind — data exists but no matching telemetry |
| ⬜ Gray | — | No ATT&CK detection strategy defined for this technique |

---

## Example Output

```
══════════════════════════════════════════════════════════════════════
  ATT&CK NAVIGATOR LAYER — SENTINEL COVERAGE REPORT
  Workspace : my-sentinel  |  Lookback: 30 days
══════════════════════════════════════════════════════════════════════
  Total techniques        : 647
  No detection strategy   : 89   (gray)
  No coverage (0%)        : 203  [red]
  Partial coverage        : 298  [orange/yellow/blue]
  Full coverage (100%)    : 57   [green]
  Overall coverage score  : 62.4%  (of techniques with detection strategies)
──────────────────────────────────────────────────────────────────────

  TOP COVERED TACTICS:
    defense-evasion                    74.2%  ██████████████
    execution                          71.8%  ██████████████
    persistence                        68.3%  █████████████
    credential-access                  65.1%  █████████████
    lateral-movement                   58.9%  ███████████

  ZERO-COVERAGE SAMPLE (first 5 of 203):
    [T1557.003] DHCP Spoofing
    [T1599.001] Network Address Translation Traversal
    [T1611]     Escape to Host
    [T1620]     Reflective Code Loading
    [T1647]     Plist File Modification
══════════════════════════════════════════════════════════════════════
```

---

## Tables and Data Connectors

| Sentinel Table | Data Connector | ATT&CK Coverage |
|---|---|---|
| SecurityEvent | Windows Security Events (via AMA) | Process creation, logon, AD events |
| WindowsEvent (Sysmon) | Custom Logs / Windows Events | Network, registry, file, process |
| WindowsEvent (PowerShell) | Custom Logs | Script execution |
| AzureActivity | Azure Activity | Cloud service manipulation |
| AuditLogs | Azure Active Directory | Identity operations |
| SigninLogs | Azure Active Directory | Authentication |
| OfficeActivity | Microsoft 365 | Data exfiltration, email abuse |
| Syslog | Syslog (via AMA) | Linux auth, cron, kernel |
| CommonSecurityLog | Common Event Format (CEF) | Network, IDS/IPS |
| Device* tables | Microsoft Defender for Endpoint | Full endpoint telemetry |

---

## Extending Coverage

The `SENTINEL_EVENT_MAP` dictionary in `attack-heatmap.py` defines all event → data component mappings. To add custom mappings:

```python
# In attack-heatmap.py, add to SENTINEL_EVENT_MAP:
("SecurityEvent", "4985"): ["Process Creation"],          # new event
("AzureActivity", "microsoft.batch/batchaccounts/write"): ["Cloud Service Creation"],
```

The ATT&CK data component names must match exactly what's in `enterprise-attack.json`. To browse them:
```bash
python3 -c "
import json
data = json.load(open('enterprise-attack.json'))
dcs = [o['name'] for o in data['objects'] if o.get('type')=='x-mitre-data-component']
print('\n'.join(sorted(dcs)))
"
```

---

## References

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [enterprise-attack.json (MITRE CTI)](https://github.com/mitre/cti/tree/master/enterprise-attack)
- [Log Analytics Query REST API](https://learn.microsoft.com/en-us/rest/api/loganalytics/dataaccess/query/execute)
- [az monitor log-analytics query](https://learn.microsoft.com/en-us/cli/azure/monitor/log-analytics#az-monitor-log-analytics-query)
