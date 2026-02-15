#!/usr/bin/env python3
"""
ALCCDC 2026 - Palo Alto NGFW Rapid Deployment Script
=====================================================
Pushes security rules to the firewall via XML API.
Uses ONLY Python standard library (runs on stock Debian 13 w/ Python 3.13.5).

BEFORE RUNNING:
  1. Change the admin password manually via CLI first
  2. Fill in team_config.json with real values from the team packet
  3. Ensure this machine can reach the firewall management IP on HTTPS

Usage:
  python3 pa_deploy.py --config team_config.json
  python3 pa_deploy.py <FW_MGMT_IP> <ADMIN_PASSWORD> <TEAM_NUMBER>
"""

import sys
import ssl
import json
import time
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET


# ============================================================
# PAN-OS API Client (stdlib only)
# ============================================================

class PANOSFirewall:
    def __init__(self, host, password, user="admin", dry_run=False):
        self.host = host
        self.base_url = f"https://{host}/api/"
        self.user = user
        self.password = password
        self.key = None
        self.dry_run = dry_run
        self.dry_run_log = []  # Stores all would-be API calls
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, params):
        if self.dry_run:
            self.dry_run_log.append(params)
            return '<response status="success"><result/></response>'
        url = self.base_url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url)
        try:
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=30)
            return resp.read().decode()
        except Exception as e:
            print(f"  [-] API request failed: {e}")
            return None

    def get_api_key(self):
        if self.dry_run:
            self.key = "DRY-RUN-FAKE-API-KEY"
            print("[+] DRY RUN: Skipping authentication (no firewall contact)")
            return True
        print("[*] Authenticating to firewall...")
        params = {
            "type": "keygen",
            "user": self.user,
            "password": self.password
        }
        result = self._request(params)
        if result is None:
            return False
        root = ET.fromstring(result)
        key_elem = root.find(".//key")
        if key_elem is not None:
            self.key = key_elem.text
            print("[+] API key obtained")
            return True
        else:
            msg = root.find(".//msg")
            print(f"[-] Auth failed: {msg.text if msg is not None else result[:200]}")
            return False

    def set_config(self, xpath, element):
        if self.dry_run:
            print(f"  [DRY RUN] Would set xpath: {xpath[:80]}...")
            self.dry_run_log.append({"action": "set", "xpath": xpath, "element": element})
            return True
        params = {
            "type": "config",
            "action": "set",
            "xpath": xpath,
            "element": element,
            "key": self.key
        }
        result = self._request(params)
        if result is None:
            return False
        root = ET.fromstring(result)
        status = root.attrib.get("status", "error")
        if status == "success":
            return True
        else:
            msg = root.find(".//msg/line")
            print(f"  [-] Config set failed: {msg.text if msg is not None else result[:200]}")
            return False

    def commit(self):
        if self.dry_run:
            print("[DRY RUN] Would commit configuration")
            return True
        params = {
            "type": "commit",
            "cmd": "<commit></commit>",
            "key": self.key
        }
        print("[*] Committing configuration (this may take 30-90 seconds)...")
        result = self._request(params)
        if result is None:
            return False
        root = ET.fromstring(result)
        status = root.attrib.get("status", "error")
        if status == "success":
            print("[+] Commit initiated")
            # Poll for commit completion
            self._wait_for_commit()
            return True
        else:
            print(f"[-] Commit failed: {result[:200]}")
            return False

    def _wait_for_commit(self):
        """Poll commit status until done or timeout."""
        for i in range(60):  # up to 2 minutes
            time.sleep(2)
            params = {
                "type": "op",
                "cmd": "<show><jobs><all></all></jobs></show>",
                "key": self.key
            }
            result = self._request(params)
            if result and "FIN" in result:
                print("[+] Commit completed")
                return True
            if i % 5 == 0 and i > 0:
                print(f"    ... still committing ({i*2}s)")
        print("[!] Commit may still be in progress - check Web UI")
        return False

    def op_command(self, cmd):
        if self.dry_run:
            print(f"  [DRY RUN] Would run op command: {cmd[:80]}...")
            return '<response status="success"><result/></response>'
        params = {
            "type": "op",
            "cmd": cmd,
            "key": self.key
        }
        return self._request(params)

    def dump_dry_run(self, filename=None):
        """Print or save all would-be API calls from a dry run."""
        if not self.dry_run_log:
            print("[*] No API calls recorded.")
            return
        output_lines = []
        output_lines.append(f"\n{'='*60}")
        output_lines.append(f"  DRY RUN SUMMARY: {len(self.dry_run_log)} API calls")
        output_lines.append(f"{'='*60}\n")
        for i, call in enumerate(self.dry_run_log, 1):
            if isinstance(call, dict) and "xpath" in call:
                output_lines.append(f"--- Call {i}: {call['action'].upper()} ---")
                output_lines.append(f"  XPath: {call['xpath']}")
                output_lines.append(f"  Element: {call['element'][:200]}...")
            else:
                output_lines.append(f"--- Call {i} ---")
                output_lines.append(f"  Params: {call}")
            output_lines.append("")
        text = "\n".join(output_lines)
        print(text)
        if filename:
            with open(filename, "w") as f:
                f.write(text)
            print(f"[+] Dry run log saved to {filename}")


# ============================================================
# Rule Building Helpers
# ============================================================

def members(items):
    """Build <member>x</member><member>y</member> from a list."""
    return "".join(f"<member>{i}</member>" for i in items)

def build_rule(name, from_z, to_z, src, dst, app, svc, action,
               log_end=True, log_start=False, profile_group=None, disabled=False):
    """Build the XML element string for a security rule."""
    parts = []
    parts.append(f"<from>{members(from_z)}</from>")
    parts.append(f"<to>{members(to_z)}</to>")
    parts.append(f"<source>{members(src)}</source>")
    parts.append(f"<destination>{members(dst)}</destination>")
    parts.append(f"<application>{members(app)}</application>")
    parts.append(f"<service>{members(svc)}</service>")
    parts.append(f"<action>{action}</action>")
    if log_end:
        parts.append("<log-end>yes</log-end>")
    if log_start:
        parts.append("<log-start>yes</log-start>")
    if profile_group:
        parts.append(f"<profile-setting><group><member>{profile_group}</member></group></profile-setting>")
    if disabled:
        parts.append("<disabled>yes</disabled>")
    return "".join(parts)

def rule_xpath(rule_name):
    """Build the xpath for a security rule."""
    base = "/config/devices/entry[@name='localhost.localdomain']"
    return f"{base}/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{rule_name}']"


# ============================================================
# Deployment Logic
# ============================================================

def deploy_from_config(config, dry_run=False):
    """Run full deployment from a config dict."""
    fw_ip = config["fw_mgmt_ip"]
    password = config["admin_password"]
    user = config.get("admin_user", "admin")

    print(f"\n{'='*60}")
    if dry_run:
        print(f"  ALCCDC 2026 - DRY RUN (no firewall contact)")
        print(f"  Target would be: {fw_ip}")
    else:
        print(f"  ALCCDC 2026 - Palo Alto Rapid Deployment")
        print(f"  Target: {fw_ip}")
    print(f"{'='*60}")
    print(f"")
    print(f"  ** SAFETY CHECK **")
    print(f"  This script pushes SECURITY RULES only.")
    print(f"  It does NOT configure interfaces/zones/vwire.")
    print(f"  You must set up interfaces MANUALLY first.")
    print(f"")
    print(f"  Before running, confirm:")
    print(f"    1. You changed the admin password via CLI")
    print(f"    2. ESXi vSwitch port groups for data interfaces have")
    print(f"       Promiscuous Mode, MAC Changes, Forged Transmits = Accept")
    print(f"       (REQUIRED for vwire/L2 — without this, zero traffic)")
    print(f"    3. You set up vwire/L3 interfaces manually")
    print(f"    4. You created an Allow-All-Temp rule")
    print(f"    5. You verified scored services work")
    print(f"    6. The mgt interface is NOT in the vwire")
    print(f"       (mgt is separate — never touch it)")
    print(f"")

    fw = PANOSFirewall(fw_ip, password, user, dry_run=dry_run)
    if not fw.get_api_key():
        print("\n[!] FATAL: Cannot authenticate. Check IP and password.")
        print("    Did you change the password via CLI first?")
        sys.exit(1)

    aa = config["always_allow"]
    infra = aa["infrastructure"]
    services = config["scored_services"]

    # Collect infrastructure IPs (skip any still containing placeholder brackets)
    infra_ips = [ip for ip in infra.values() if ip and "<" not in ip]
    service_ips = [s["ip"] for s in services if s["ip"] and "<" not in s["ip"]]
    scoring = aa.get("scoring_subnet", "")
    icmp_sources = aa.get("icmp_sources", [])

    success_count = 0
    fail_count = 0

    def add_rule(name, **kwargs):
        nonlocal success_count, fail_count
        print(f"  [*] Creating rule: {name}")
        ok = fw.set_config(rule_xpath(name), build_rule(name, **kwargs))
        if ok:
            print(f"  [+] {name} - OK")
            success_count += 1
        else:
            print(f"  [-] {name} - FAILED")
            fail_count += 1

    print("\n[*] Phase 1: Creating security rules...\n")

    # --- Rule 1: Allow scoring subnet (top priority) ---
    if scoring and "<" not in scoring:
        add_rule("Allow-Scoring",
            from_z=["any"], to_z=["any"],
            src=[scoring], dst=["any"],
            app=["any"], svc=["any"], action="allow")
    else:
        print("  [!] SKIPPING scoring rule — no scoring subnet in config")

    # --- Rule 2: Allow ICMP from competition infrastructure ---
    valid_icmp = [s for s in icmp_sources if "<" not in s]
    if valid_icmp:
        add_rule("Allow-Comp-ICMP",
            from_z=["any"], to_z=["any"],
            src=valid_icmp, dst=["any"],
            app=["ping"], svc=["application-default"], action="allow")

    # --- Rule 3: Allow CCS Client (if configured) ---
    ccs = infra.get("ccs_client", "")
    if ccs and "<" not in ccs:
        add_rule("Allow-CCSClient",
            from_z=["any"], to_z=["any"],
            src=["any"], dst=[ccs],
            app=["any"], svc=["service-http", "service-https"], action="allow")

    # --- Rule 4: Allow competition infrastructure ---
    if infra_ips:
        add_rule("Allow-CompInfra",
            from_z=["any"], to_z=["any"],
            src=["any"], dst=infra_ips,
            app=["any"], svc=["any"], action="allow")

    # --- Rule 5: Allow all scored services (broad) ---
    if service_ips:
        add_rule("Allow-Scored-Inbound",
            from_z=["any"], to_z=["any"],
            src=["any"], dst=service_ips,
            app=["any"], svc=["any"], action="allow")

    # --- Rule 6: Outbound from all internal systems to infra ---
    if infra_ips:
        add_rule("Allow-Outbound-Infra",
            from_z=["any"], to_z=["any"],
            src=service_ips if service_ips else ["any"],
            dst=infra_ips,
            app=["any"], svc=["any"], action="allow")

    # --- Commit ---
    print(f"\n[*] Rules created: {success_count} succeeded, {fail_count} failed")
    fw.commit()

    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT COMPLETE")
    print(f"  Rules pushed: {success_count}")
    print(f"  Failures:     {fail_count}")
    print(f"{'='*60}")

    if dry_run:
        fw.dump_dry_run("dry_run_output.txt")
        print(f"\n[*] DRY RUN complete. No changes were made to any firewall.")
        print(f"[*] Review the API calls above to verify correctness.")
    else:
        print(f"\n[!] NEXT STEPS:")
        print(f"    1. VERIFY ALL SCORED SERVICES from the External View VM")
        print(f"    2. If everything works, disable Allow-All-Temp via CLI:")
        print(f"       configure")
        print(f"       set rulebase security rules Allow-All-Temp disabled yes")
        print(f"       commit")
        print(f"    3. Run pa_phase2_profiles.py to add threat prevention")


def deploy_minimal(fw_ip, password, team_num):
    """Minimal deployment with just positional args (no config file).
       Creates basic rules — you add service-specific rules manually."""
    config = {
        "fw_mgmt_ip": fw_ip,
        "admin_password": password,
        "admin_user": "admin",
        "always_allow": {
            "scoring_subnet": "",
            "icmp_sources": ["10.120.0.0/16", "10.110.0.0/16"],
            "infrastructure": {}
        },
        "scored_services": []
    }

    print(f"\n{'='*60}")
    print(f"  MINIMAL DEPLOYMENT (no config file)")
    print(f"  Target: {fw_ip} | Team: {team_num}")
    print(f"  Only ICMP rules will be created.")
    print(f"  Use --config for full deployment.")
    print(f"{'='*60}\n")

    fw = PANOSFirewall(fw_ip, password)
    if not fw.get_api_key():
        print("[!] FATAL: Cannot authenticate.")
        sys.exit(1)

    # At minimum, create the ICMP rule (confirmed 2026 requirement)
    print("  [*] Creating Allow-Comp-ICMP rule")
    fw.set_config(
        rule_xpath("Allow-Comp-ICMP"),
        build_rule("Allow-Comp-ICMP",
            from_z=["any"], to_z=["any"],
            src=["10.120.0.0/16", "10.110.0.0/16"], dst=["any"],
            app=["ping"], svc=["application-default"], action="allow")
    )

    fw.commit()
    print("\n[+] Minimal deployment done. Add more rules manually or use --config.")


# ============================================================
# Main
# ============================================================

def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

def validate_config(config):
    """Check for obvious placeholder values still in the config."""
    warnings = []
    if "<" in config.get("fw_mgmt_ip", "<"):
        warnings.append("fw_mgmt_ip is still a placeholder")
    if "<" in config.get("admin_password", "<"):
        warnings.append("admin_password is still a placeholder")
    scoring = config.get("always_allow", {}).get("scoring_subnet", "")
    if not scoring or "<" in scoring:
        warnings.append("scoring_subnet is missing or placeholder — scoring rule will be skipped")
    svc = config.get("scored_services", [])
    filled = [s for s in svc if s.get("ip") and "<" not in s["ip"]]
    if len(filled) == 0:
        warnings.append("No scored_services have real IPs — service rules will be skipped")
    elif len(filled) < len(svc):
        warnings.append(f"Only {len(filled)}/{len(svc)} scored_services have real IPs")
    return warnings

def print_usage():
    print("ALCCDC 2026 - Palo Alto Rapid Deployment")
    print()
    print("Usage:")
    print(f"  python3 {sys.argv[0]} --config team_config.json")
    print(f"  python3 {sys.argv[0]} --config team_config.json --dry-run")
    print(f"  python3 {sys.argv[0]} <FW_MGMT_IP> <ADMIN_PASSWORD> <TEAM_NUMBER>")
    print()
    print("Options:")
    print("  --config FILE   Use a JSON config file (recommended)")
    print("  --dry-run       Validate config and show what would be pushed")
    print("                  without contacting any firewall")
    print()
    print("The --config method is recommended. Fill in team_config.json")
    print("with real values from the team packet before running.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    dry_run = "--dry-run" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--dry-run"]

    if not args:
        print_usage()
        sys.exit(1)

    if args[0] == "--config":
        if len(args) < 2:
            print("Error: --config requires a path to the config file")
            print(f"  python3 {sys.argv[0]} --config team_config.json")
            sys.exit(1)

        config = load_config(args[1])
        warnings = validate_config(config)
        if warnings:
            print("\n[!] CONFIG WARNINGS:")
            for w in warnings:
                print(f"    - {w}")
            print()
            if not dry_run:
                resp = input("Continue anyway? (y/n): ").strip().lower()
                if resp != "y":
                    print("Aborted.")
                    sys.exit(0)
            else:
                print("[*] Continuing in dry-run mode despite warnings...")

        deploy_from_config(config, dry_run=dry_run)

    elif args[0] in ("-h", "--help"):
        print_usage()

    else:
        if len(args) < 3:
            print_usage()
            sys.exit(1)
        deploy_minimal(args[0], args[1], args[2])
