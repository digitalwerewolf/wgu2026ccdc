# Palo Alto Config Template - ALCCDC 2026

## What This Is

A pre-built PAN-OS XML configuration template that can be loaded onto the
competition firewall in under 2 minutes. It includes security rules, security
profiles (AV, anti-spyware, vulnerability protection, URL filtering, file
blocking, WildFire), and a security profile group — all with placeholder IPs
that you fill in from the team packet.

**This is a BACKUP deployment method.** Your primary method is the Python
automation script (`pa_deploy.py`). Use this template if:

- The Python script fails
- The Debian box can't reach the firewall management IP
- You want a faster "load one file and go" approach
- You need to rebuild the firewall from scratch (compromised/factory reset)

## Files

| File | Purpose |
|------|---------|
| `ccdc-config-template.xml` | PAN-OS XML config with `__PLACEHOLDER__` values |
| `deploy_config.sh` | Interactive script: replaces placeholders, pushes to firewall |
| `README_config_template.md` | This file |

## Quick Start (Competition Day)

### Option A: Automated (from Debian 13 box)

```bash
chmod +x deploy_config.sh
./deploy_config.sh
```

It will prompt you for every value (firewall IP, team number, service IPs, etc.),
generate the final XML, and push it to the firewall via the XML API.

### Option B: Manual Edit + CLI Load

If the script can't reach the firewall, or you prefer manual control:

**Step 1: Edit the template on the Debian box**

```bash
cp ccdc-config-template.xml ccdc-config.xml

# Replace all placeholders with real values using sed:
sed -i 's/__TEAM_NUM__/5/g' ccdc-config.xml
sed -i 's/__SCORING_SUBNET__/192.168.28.0\/24/g' ccdc-config.xml
sed -i 's/__COMP_DNS_IP__/10.120.0.53/g' ccdc-config.xml
sed -i 's/__PATCH_SERVER_IP__/10.120.0.9/g' ccdc-config.xml
sed -i 's/__INJECT_PORTAL_IP__/10.120.0.20/g' ccdc-config.xml
sed -i 's/__SYSLOG_IP__/10.120.0.201/g' ccdc-config.xml
sed -i 's/__PROXY_IP__/10.120.0.200/g' ccdc-config.xml
sed -i 's/__SVC_DNS_IP__/10.5.5.5/g' ccdc-config.xml
sed -i 's/__SVC_MAIL_IP__/10.5.5.10/g' ccdc-config.xml
sed -i 's/__SVC_WEB1_IP__/10.5.5.15/g' ccdc-config.xml
sed -i 's/__SVC_WEB2_IP__/10.5.5.20/g' ccdc-config.xml
sed -i 's/__SVC_FTP_IP__/10.5.5.25/g' ccdc-config.xml
sed -i 's/__SVC_ECOMM_IP__/10.5.5.30/g' ccdc-config.xml

# Verify no placeholders remain:
grep -c '__.*__' ccdc-config.xml
# Should output: 0
```

**Step 2: Push to firewall via API**

```bash
# Get API key
API_KEY=$(curl -sk "https://<FW_IP>/api/?type=keygen&user=admin&password=<PASS>" \
  | grep -oP '(?<=<key>).*(?=</key>)')

# Import the config file
curl -sk --form file=@ccdc-config.xml \
  "https://<FW_IP>/api/?type=import&category=configuration&key=${API_KEY}"

# Load it
curl -sk "https://<FW_IP>/api/?type=op&cmd=<load><config><from>ccdc-config.xml</from></config></load>&key=${API_KEY}"

# Commit
curl -sk "https://<FW_IP>/api/?type=commit&cmd=<commit></commit>&key=${API_KEY}"
```

**Step 3: Or SCP + CLI (if API isn't working)**

```bash
# From Debian box, copy config to firewall:
scp ccdc-config.xml admin@<FW_IP>:ccdc-config.xml
```

Then on the firewall CLI (SSH to it):

```
> configure
# load config from ccdc-config.xml
# commit
```

### Option C: Web UI Load (last resort, slowest)

1. Download `ccdc-config.xml` from the Debian box to your local machine
2. Open the firewall Web UI: `https://<FW_IP>`
3. Navigate to **Device > Setup > Operations**
4. Click **Import named configuration snapshot**
5. Browse to your edited `ccdc-config.xml` and upload it
6. Click **Load named configuration snapshot** and select `ccdc-config.xml`
7. Click **Commit**

## What's In The Config

### Security Rules (top-down order)

| # | Rule Name | Source | Destination | Action | Notes |
|---|-----------|--------|-------------|--------|-------|
| 1 | Allow-Scoring | `__SCORING_SUBNET__` | any | Allow | NEVER disable |
| 2 | Allow-ICMP | 10.120.0.0/16, 10.110.0.0/16 | any | Allow | Competition requirement |
| 3 | Allow-CCSClient | any | 10.120.0.111 | Allow | HTTP/HTTPS only |
| 4 | Allow-CompInfra | any | patch, inject, DNS, syslog, proxy | Allow | Infrastructure |
| 5 | Allow-Scored-Services | any | all scored service IPs | Allow | **Has security profiles attached** |
| 6 | Allow-Outbound-Patch | inside | patch server | Allow | For system updates |
| 7 | Deny-All-Log | any | any | Deny | Catches everything else, logged |
| 8 | Allow-All-Temp | any | any | Allow | **DISABLED** - emergency only |

### Security Profiles Included

- **CCDC-AV** — Antivirus: reset-both on all decoders (HTTP, SMTP, POP3, FTP, SMB, IMAP)
- **CCDC-AS** — Anti-Spyware: block crit/high/medium, DNS sinkholing enabled (72.5.65.111)
- **CCDC-VP** — Vulnerability Protection: reset-both for crit/high/med, alert for low/info
- **CCDC-URL** — URL Filtering: blocks C2, dynamic-dns, hacking, malware, phishing, etc.
- **CCDC-FB** — File Blocking: blocks bat, com, dll, exe, hta, msi, pif, scr, vbs
- **CCDC-WF** — WildFire Analysis: forwards unknowns to public cloud
- **CCDC-Profiles** — Profile Group bundling all of the above

### Network Setup

- Virtual Wire deployment (ethernet1/1 outside, ethernet1/2 inside)
- Two zones: `outside` and `inside`
- Adjust interface names if the competition VM uses different ports

### Device Settings

- Hostname: Team`XX`-FW
- Login banner: "AUTHORIZED ACCESS ONLY"
- DNS: Competition DNS + 8.8.8.8 backup
- NTP: pool.ntp.org servers
- Log suppression: disabled (we want ALL logs)

## Placeholders Reference

All placeholders follow the pattern `__NAME__`. Here's the full list:

| Placeholder | Description | Example Value |
|-------------|-------------|---------------|
| `__TEAM_NUM__` | Your team number | `5` |
| `__SCORING_SUBNET__` | Scoring engine subnet | `192.168.28.0/24` |
| `__COMP_DNS_IP__` | Competition DNS server | `10.120.0.53` |
| `__PATCH_SERVER_IP__` | Internal patch server | `10.120.0.9` |
| `__INJECT_PORTAL_IP__` | Inject submission portal | `10.120.0.20` |
| `__SYSLOG_IP__` | ESXi syslog target | `10.120.0.201` |
| `__PROXY_IP__` | Outbound proxy | `10.120.0.200` |
| `__SVC_DNS_IP__` | Scored DNS server | `10.X.X.5` |
| `__SVC_MAIL_IP__` | Scored mail server (SMTP/POP3) | `10.X.X.10` |
| `__SVC_WEB1_IP__` | Scored web server 1 | `10.X.X.15` |
| `__SVC_WEB2_IP__` | Scored web server 2 | `10.X.X.20` |
| `__SVC_FTP_IP__` | Scored FTP server | `10.X.X.25` |
| `__SVC_ECOMM_IP__` | Scored e-commerce server | `10.X.X.30` |

**Note:** The scored service IPs above are guesses based on past patterns. The actual
services and IPs will be in the team packet. You may need to ADD or REMOVE
`<member>` entries in the Allow-Scored-Services rule to match the real environment.

## Important Notes

1. **Change the admin password BEFORE loading this config.** The password cannot
   be set via XML import for security reasons. Do it first thing manually.

2. **Save a backup of the original config** before loading anything:
   ```
   save config to original-backup.xml
   ```

3. **This is a PARTIAL config.** It sets up zones, rules, and profiles. It does NOT
   override the management interface settings, admin accounts, or licensing. The
   firewall will merge this with its existing candidate config.

4. **Verify interfaces before committing.** The template assumes ethernet1/1 and
   ethernet1/2 exist and are correct. Check Network > Interfaces in the Web UI first.

5. **After loading, ALWAYS verify scored services.** If anything breaks:
   ```
   configure
   set rulebase security rules Allow-All-Temp disabled no
   commit
   ```
   Then debug from Monitor > Logs > Traffic.

## Emergency Recovery

If the config breaks everything:

```
# Revert to the backup you saved earlier:
load config from original-backup.xml
commit

# Or revert to last good saved config:
load config last-saved
commit

# Nuclear option (factory reset — lose everything):
request system private-data-reset
```
