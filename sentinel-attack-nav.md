---
argument-hint: "[workspace-id=<GUID>] [days=30]"
allowed-tools: |
  | Bash | Read | Write |
---

# ATT&CK Heatmap — Navigator Layer from Microsoft Sentinel

Query Microsoft Sentinel (Log Analytics) for all ingested telemetry, map it to MITRE ATT&CK techniques via data component chains, and produce a **Navigator-compatible JSON layer** importable directly into the ATT&CK Navigator.

## Input

`$ARGUMENTS` optionally contains:

* `workspace-id=<GUID>` — Log Analytics workspace ID (overrides config default)
* `days=N` — Lookback window in days (default: 30)

If no arguments are given, use values from Configuration below.

## Configuration

```
WORKSPACE_ID       -- from $SENTINEL_WORKSPACE_ID env var (or pass via argument)
ATTACK_JSON        -- path to enterprise-attack.json (download from MITRE)
COLLECT_SCRIPT     -- path to sentinel_collect.py
HEATMAP_SCRIPT     -- path to attack-heatmap.py
OUTPUT_DIR         -- /tmp  (or customize)
AUTH_MODE          -- "cli" (uses `az` login) or "api" (uses azure-identity)
```

Verify `$SENTINEL_WORKSPACE_ID` exists before proceeding. If missing and not passed as argument, abort with a clear message pointing to prerequisites.

**Prerequisite check:**
```bash
# Verify az CLI is authenticated (cli mode)
az account show 2>&1

# OR verify azure-identity is installed (api mode)
python3 -c "from azure.identity import DefaultAzureCredential; print('OK')" 2>&1
```

If neither works, abort with setup instructions (see Error Handling).

---

## Workflow

**Target: 1 discovery pass → parallel table queries → 1 normalization → 1 Python run → 1 file write. No external dependencies beyond the two scripts.**

---

### Step 1 — Collect Sentinel telemetry

Run `sentinel_collect.py` to query all relevant Sentinel tables and produce a normalized events JSON:

```bash
python3 $COLLECT_SCRIPT \
    --workspace-id "$WORKSPACE_ID" \
    --mode "$AUTH_MODE" \
    --days "$DAYS" \
    --output /tmp/sentinel_events.json
```

Parse stdout to confirm:
- Number of tables discovered
- Number of unique `(table, event_id)` pairs collected
- If 0 events → abort with diagnostic message (see Error Handling)

**Tables queried (skip silently if not present in workspace):**

| Table | What it captures |
|---|---|
| SecurityEvent | Windows Security log (Event IDs 4688, 4624, 4648, 4769…) |
| WindowsEvent (Sysmon channel) | Sysmon events 1–29 |
| WindowsEvent (PowerShell channels) | PowerShell script block logging (4103, 4104) |
| WindowsEvent (AppLocker channels) | AppLocker enforcement events |
| AzureActivity | Azure Resource Manager operations |
| AuditLogs | Azure AD audit operations |
| SigninLogs / AAD*SignInLogs | Azure AD authentication events |
| OfficeActivity | Microsoft 365 operations |
| Syslog | Linux syslog (auth, cron, kern, daemon…) |
| CommonSecurityLog | CEF-format logs (firewalls, IDS/IPS) |
| DeviceProcessEvents | Defender for Endpoint — process creation |
| DeviceNetworkEvents | Defender for Endpoint — network connections |
| DeviceFileEvents | Defender for Endpoint — file events |
| DeviceRegistryEvents | Defender for Endpoint — registry changes |
| DeviceLogonEvents | Defender for Endpoint — logon activity |
| DeviceImageLoadEvents | Defender for Endpoint — DLL/module loads |
| DeviceEvents | Defender for Endpoint — misc (named pipes, DNS, WMI) |

---

### Step 2 — Generate Navigator layer

```bash
python3 $HEATMAP_SCRIPT \
    --attack-json   "$ATTACK_JSON" \
    --sentinel-events /tmp/sentinel_events.json \
    --workspace     "$WORKSPACE_ID" \
    --date          "$(date +%Y-%m-%d)" \
    --days          "$DAYS" \
    --output        /tmp/attack-navigator-layer.json
```

---

### Step 3 — Report results

After the layer is generated, read `/tmp/attack-navigator-layer.json` and report:

1. **Coverage summary:**
   - Total techniques in the layer
   - Breakdown: full / partial / zero / unscored (gray)
   - Overall coverage % (of techniques that have detection strategies defined)

2. **Top 5 best-covered tactics** (by average score)

3. **Notable gaps** — sample of high-value techniques with 0% coverage (prioritise by tactic: Execution, Persistence, Credential Access, Defense Evasion)

4. **Tell the user:**
   - Layer file is at `/tmp/attack-navigator-layer.json`
   - How to import it: open https://mitre-attack.github.io/attack-navigator/ → "+" → "Open Existing Layer" → "Upload from local"
   - Color scale: 🔴 red = blind → 🟠 orange → 🟡 yellow → 🔵 blue → 🟢 green = full coverage
   - Gray = no ATT&CK detection strategy defined (not a gap, just unscored)
   - Offer to open it in the browser

5. **Improvement recommendations** (top 3):
   - Which data connectors to enable to close the biggest gaps
   - e.g., "Enable Sysmon → covers X additional techniques in Execution/Defense Evasion"
   - e.g., "Enable Azure AD sign-in logs → covers Y techniques in Initial Access/Credential Access"

---

## Error Handling

### Authentication / credential errors
```
[!] az account show returned error → run: az login
[!] azure-identity not installed   → run: pip install azure-identity
[!] Token expired (api mode)       → re-authenticate: az login
```
Abort with clear fix instructions. Do not proceed with empty credentials.

### Workspace not found
```
[!] Workspace ID <id> not found or access denied.
    Verify: az monitor log-analytics workspace show --workspace-name <name> -g <rg>
    Ensure your identity has "Log Analytics Reader" role on the workspace.
```

### No events collected
```
[!] sentinel_collect.py returned 0 events.
    Possible causes:
      - No data connectors enabled in Sentinel
      - Lookback window too short (try --days 90)
      - Workspace ID is wrong
      - Queried tables have no data in the time window
    Try: python3 sentinel_collect.py --workspace-id <id> --dry-run
    (prints KQL queries you can run manually in Log Analytics)
```

### enterprise-attack.json missing
```
[!] enterprise-attack.json not found at: $ATTACK_JSON
    Download it from:
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    (approx 50 MB)
    wget -O enterprise-attack.json \
      https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### Partial failures (individual table queries fail)
If some table queries fail (table not present / insufficient permissions), continue with the tables that did succeed. Report which tables were skipped at the end. A partial layer is still valuable.

---

## Output Files

| File | Description |
|---|---|
| `/tmp/sentinel_events.json` | Normalized `[{table, event_id, count}]` array from Sentinel |
| `/tmp/attack-navigator-layer.json` | ATT&CK Navigator v4.5 layer — import this |

---

## Quick-start for the user

**Prerequisites:**
```bash
# 1. Download ATT&CK data (once, ~50 MB)
wget -O enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# 2. Install Python deps (api mode only)
pip install azure-identity azure-monitor-query

# 3. Authenticate
az login                          # CLI mode
# OR: set AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET for service principal

# 4. Find your workspace ID
az monitor log-analytics workspace list --query "[].{name:name, id:customerId}" -o table

# 5. Set env var
export SENTINEL_WORKSPACE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Then ask Claude:**
> `Generate an ATT&CK heatmap from my Sentinel workspace workspace-id=<GUID> days=30`
