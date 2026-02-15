# Firewall Scripts — ALCCDC 2026

## CRITICAL: DO NOT PUT ESXi BEHIND THE FIREWALL

Before configuring ANY firewall interfaces on competition day, check the ESXi VM settings for the firewall VM. The VM-100 typically has 3 network adapters:

- **Network Adapter 1** = `mgt` (management) — this is your lifeline. **DO NOT TOUCH.**
- **Network Adapter 2** = `ethernet1/1` (data — outside)
- **Network Adapter 3** = `ethernet1/2` (data — inside)

The virtual wire ONLY binds the data interfaces. Your VPN → ESXi access goes through the management path, which is separate. **Never edit the ESXi vSwitch or port group configuration for the firewall VM.** If the management interface ends up routing through the firewall's data plane, you lose access to everything.

**Preflight on competition day:**
1. ESXi > Firewall VM > Edit Settings — note which adapter maps to which port group
2. **CHECK vSwitch SECURITY** — For vwire/L2: the data interface port groups MUST have Promiscuous Mode, MAC Address Changes, and Forged Transmits set to **Accept**. Without this, the firewall gets zero data traffic.
3. On the firewall CLI: `show interface management` — confirms the mgt IP (this is how you're connected)
4. On the firewall CLI: `debug show vm-series interfaces all` — shows the definitive vNIC-to-interface mapping
5. On the firewall CLI: `show interface all` — shows data interfaces and their status
6. Only bind data interfaces (ethernet1/1, ethernet1/2) into your virtual wire. Never the mgt.

---

Quick-deploy scripts for the Palo Alto VM-100 NGFW. Designed to run on the Debian 13 box (Python 3.13.5, bash, curl — all preinstalled, no pip needed).

## Competition Day Quick Start

### Step 1: Download the repo from the patch server

```bash
wget http://<PATCH_SERVER_IP>/repos/<TEAM_FILE>.zip
unzip <TEAM_FILE>.zip
cd <REPO_DIR>/firewall/
chmod +x *.sh
```

### Step 2: Edit the config file

Open `team_config.json` and fill in every `<PLACEHOLDER>` with the real values from the team packet. At minimum you need:

- `fw_mgmt_ip` — the firewall management IP
- `admin_password` — the NEW password (change it manually first!)
- `scoring_subnet` — the scoring engine subnet
- `scored_services` — every scored service name, IP, and port

```bash
nano team_config.json
```

### Step 3: Change the admin password MANUALLY FIRST

SSH into the firewall and change the password before running any scripts:

```
ssh admin@<FW_MGMT_IP>
configure
set mgt-config users admin password
commit
```

### Step 4: Run the deployment script

```bash
python3 pa_deploy.py --config team_config.json
```

This creates all security rules and commits. Takes ~30 seconds.

### Step 5: Verify scored services, then run Phase 2

After confirming all services still work:

```bash
python3 pa_phase2_profiles.py --config team_config.json
```

This creates threat prevention profiles and attaches them to every rule.

### Step 6: Disable the allow-all rule (from the FW CLI)

```
configure
set rulebase security rules Allow-All-Temp disabled yes
commit
```

### Step 7: Monitor

Get an API key and start the threat monitor:

```bash
./pa_monitor.sh --keygen <FW_MGMT_IP> admin <PASSWORD>
# Copy the key it prints, then:
./pa_monitor.sh <FW_MGMT_IP> <API_KEY>
```

## File Descriptions

| File | Purpose |
|---|---|
| `team_config.json` | All environment-specific values — edit this on competition day |
| `pa_deploy.py` | Phase 1: Creates security rules via XML API |
| `pa_phase2_profiles.py` | Phase 2: Creates security profiles, attaches to rules |
| `pa_monitor.sh` | Live threat log monitor (runs in a loop) |
| `pa_utils.sh` | Utility commands: backup, sessions, traffic, threats, sysinfo, rules, admins, interfaces |
| `pa_cli_commands.txt` | Manual CLI fallback — read aloud if scripts can't reach the FW |
| `README.md` | This file |

## If Scripts Can't Reach the Firewall

The management interface might be on a separate subnet. Try:

1. Run from a different VM that's on the same subnet as the mgmt IP
2. Check if HTTPS is allowed to the management interface
3. Fall back to `pa_cli_commands.txt` — one person reads, one types

## Utility Script Examples

```bash
# Get API key
./pa_monitor.sh --keygen <FW_IP> admin <PASSWORD>

# Export encrypted config backup (GPG AES-256)
./pa_utils.sh <FW_IP> <API_KEY> backup "YourGPGPassphrase"

# Export plaintext backup (not recommended — only if GPG unavailable)
./pa_utils.sh <FW_IP> <API_KEY> backup

# List all local backups + on-firewall saved configs
./pa_utils.sh <FW_IP> <API_KEY> backup-list

# Restore from encrypted backup
./pa_utils.sh <FW_IP> <API_KEY> restore ~/.sys_abc123_20260228.enc "YourGPGPassphrase"

# Check for rogue admin accounts
./pa_utils.sh <FW_IP> <API_KEY> admins

# View active sessions
./pa_utils.sh <FW_IP> <API_KEY> sessions

# List current security rules + profile status
./pa_utils.sh <FW_IP> <API_KEY> rules

# View threat log
./pa_utils.sh <FW_IP> <API_KEY> threats 50

# View traffic log (look for denies)
./pa_utils.sh <FW_IP> <API_KEY> traffic 50
```
