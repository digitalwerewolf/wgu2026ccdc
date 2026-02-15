#!/usr/bin/env python3
"""
ALCCDC 2026 - Phase 2: Security Profiles & Hardening
=====================================================
Run AFTER pa_deploy.py has created the base rules.
Creates security profiles, a profile group, and attaches
the group to all existing allow rules.

Uses ONLY Python standard library.

Usage:
  python3 pa_phase2_profiles.py --config team_config.json
  python3 pa_phase2_profiles.py <FW_MGMT_IP> <ADMIN_PASSWORD>
"""

import sys
import ssl
import json
import time
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET


class PANOSFirewall:
    """Minimal PAN-OS XML API client (stdlib only)."""
    def __init__(self, host, password, user="admin", dry_run=False):
        self.host = host
        self.base_url = f"https://{host}/api/"
        self.user = user
        self.password = password
        self.key = None
        self.dry_run = dry_run
        self.dry_run_log = []
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, params):
        if self.dry_run:
            self.dry_run_log.append(params)
            return '<response status="success"><result><entry name="Allow-Scoring"><action>allow</action></entry><entry name="Allow-Comp-ICMP"><action>allow</action></entry><entry name="Allow-CCSClient"><action>allow</action></entry><entry name="Allow-CompInfra"><action>allow</action></entry><entry name="Allow-Scored-Inbound"><action>allow</action></entry></result></response>'
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
            print("[+] DRY RUN: Skipping authentication")
            return True
        params = {"type": "keygen", "user": self.user, "password": self.password}
        result = self._request(params)
        if result is None:
            return False
        root = ET.fromstring(result)
        key_elem = root.find(".//key")
        if key_elem is not None:
            self.key = key_elem.text
            print("[+] Authenticated")
            return True
        print("[-] Auth failed")
        return False

    def set_config(self, xpath, element):
        if self.dry_run:
            print(f"  [DRY RUN] Would set: {xpath.split('/')[-1][:60]}")
            self.dry_run_log.append({"action": "set", "xpath": xpath, "element": element})
            return True
        params = {
            "type": "config", "action": "set",
            "xpath": xpath, "element": element, "key": self.key
        }
        result = self._request(params)
        if result is None:
            return False
        return "success" in result

    def get_config(self, xpath):
        if self.dry_run:
            # Return fake rules so attach_profiles_to_rules has something to iterate
            return '<response status="success"><result><rules><entry name="Allow-Scoring"/><entry name="Allow-Comp-ICMP"/><entry name="Allow-CCSClient"/><entry name="Allow-CompInfra"/><entry name="Allow-Scored-Inbound"/><entry name="Allow-All-Temp"/></rules></result></response>'
        params = {
            "type": "config", "action": "get",
            "xpath": xpath, "key": self.key
        }
        return self._request(params)

    def commit(self):
        if self.dry_run:
            print("[DRY RUN] Would commit configuration")
            print(f"[*] DRY RUN complete. {len(self.dry_run_log)} API calls would have been made.")
            return True
        params = {"type": "commit", "cmd": "<commit></commit>", "key": self.key}
        print("[*] Committing...")
        result = self._request(params)
        if result and "success" in result:
            print("[+] Commit initiated")
            for i in range(60):
                time.sleep(2)
                params2 = {
                    "type": "op",
                    "cmd": "<show><jobs><all></all></jobs></show>",
                    "key": self.key
                }
                r = self._request(params2)
                if r and "FIN" in r:
                    print("[+] Commit completed")
                    return True
            print("[!] Commit may still be running")
            return True
        print("[-] Commit failed")
        return False


VSYS_BASE = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"


def create_profiles(fw):
    """Create security profiles using built-in defaults where possible."""

    print("\n[*] Phase 2A: Creating security profiles...\n")

    # --- Antivirus Profile ---
    print("  [*] Antivirus profile: CCDC-AV")
    av_xpath = f"{VSYS_BASE}/profiles/virus/entry[@name='CCDC-AV']"
    # Clone from 'default' by creating with basic decoders
    av_element = (
        "<packet-capture>no</packet-capture>"
        "<mlav-category-exception />"
        "<decoder><entry name='ftp'><action>default</action><wildfire-action>default</wildfire-action></entry>"
        "<entry name='http'><action>default</action><wildfire-action>default</wildfire-action></entry>"
        "<entry name='http2'><action>default</action><wildfire-action>default</wildfire-action></entry>"
        "<entry name='imap'><action>default</action><wildfire-action>default</wildfire-action></entry>"
        "<entry name='pop3'><action>default</action><wildfire-action>default</wildfire-action></entry>"
        "<entry name='smb'><action>default</action><wildfire-action>default</wildfire-action></entry>"
        "<entry name='smtp'><action>default</action><wildfire-action>default</wildfire-action></entry></decoder>"
    )
    ok = fw.set_config(av_xpath, av_element)
    print(f"  {'[+]' if ok else '[-]'} CCDC-AV {'created' if ok else 'FAILED'}")

    # --- Anti-Spyware Profile with DNS Sinkholing ---
    print("  [*] Anti-Spyware profile: CCDC-AS")
    as_xpath = f"{VSYS_BASE}/profiles/spyware/entry[@name='CCDC-AS']"
    as_element = (
        "<botnet-domains>"
        "<lists><entry name='default-paloalto-dns'><action><sinkhole /></action><packet-capture>disable</packet-capture></entry></lists>"
        "<dns-security-categories>"
        "<entry name='pan-dns-sec-malware'><log-level>default</log-level><action>sinkhole</action><packet-capture>disable</packet-capture></entry>"
        "<entry name='pan-dns-sec-phishing'><log-level>default</log-level><action>sinkhole</action><packet-capture>disable</packet-capture></entry>"
        "<entry name='pan-dns-sec-cc'><log-level>default</log-level><action>sinkhole</action><packet-capture>disable</packet-capture></entry>"
        "</dns-security-categories>"
        "<sinkhole><ipv4-address>pan-sinkhole-default-ip</ipv4-address><ipv6-address>::1</ipv6-address></sinkhole>"
        "</botnet-domains>"
        "<rules>"
        "<entry name='Block-Critical'><severity><member>critical</member></severity>"
        "<action><reset-both /></action><packet-capture>disable</packet-capture><threat-name>any</threat-name><category>any</category></entry>"
        "<entry name='Block-High'><severity><member>high</member></severity>"
        "<action><reset-both /></action><packet-capture>disable</packet-capture><threat-name>any</threat-name><category>any</category></entry>"
        "<entry name='Default-Medium'><severity><member>medium</member></severity>"
        "<action><default-action /></action><packet-capture>disable</packet-capture><threat-name>any</threat-name><category>any</category></entry>"
        "<entry name='Default-Low'><severity><member>low</member><member>informational</member></severity>"
        "<action><default-action /></action><packet-capture>disable</packet-capture><threat-name>any</threat-name><category>any</category></entry>"
        "</rules>"
    )
    ok = fw.set_config(as_xpath, as_element)
    print(f"  {'[+]' if ok else '[-]'} CCDC-AS {'created' if ok else 'FAILED'}")

    # --- Vulnerability Protection Profile ---
    print("  [*] Vulnerability Protection profile: CCDC-VP")
    vp_xpath = f"{VSYS_BASE}/profiles/vulnerability/entry[@name='CCDC-VP']"
    vp_element = (
        "<rules>"
        "<entry name='Block-Critical-High'>"
        "<severity><member>critical</member><member>high</member></severity>"
        "<action><reset-both /></action>"
        "<vendor-id><member>any</member></vendor-id>"
        "<cve><member>any</member></cve>"
        "<threat-name>any</threat-name><host>any</host><category>any</category>"
        "<packet-capture>disable</packet-capture>"
        "</entry>"
        "<entry name='Default-Medium-Low'>"
        "<severity><member>medium</member><member>low</member><member>informational</member></severity>"
        "<action><default-action /></action>"
        "<vendor-id><member>any</member></vendor-id>"
        "<cve><member>any</member></cve>"
        "<threat-name>any</threat-name><host>any</host><category>any</category>"
        "<packet-capture>disable</packet-capture>"
        "</entry>"
        "</rules>"
    )
    ok = fw.set_config(vp_xpath, vp_element)
    print(f"  {'[+]' if ok else '[-]'} CCDC-VP {'created' if ok else 'FAILED'}")

    # --- File Blocking Profile ---
    print("  [*] File Blocking profile: CCDC-FB")
    fb_xpath = f"{VSYS_BASE}/profiles/file-blocking/entry[@name='CCDC-FB']"
    fb_element = (
        "<rules>"
        "<entry name='Block-Dangerous'>"
        "<application><member>any</member></application>"
        "<file-type>"
        "<member>bat</member><member>cmd</member><member>exe</member>"
        "<member>dll</member><member>msi</member><member>ps1</member>"
        "<member>vbs</member><member>jar</member><member>hta</member>"
        "<member>cpl</member><member>scr</member>"
        "</file-type>"
        "<direction>both</direction>"
        "<action>block</action>"
        "</entry>"
        "<entry name='Alert-Other'>"
        "<application><member>any</member></application>"
        "<file-type><member>any</member></file-type>"
        "<direction>both</direction>"
        "<action>alert</action>"
        "</entry>"
        "</rules>"
    )
    ok = fw.set_config(fb_xpath, fb_element)
    print(f"  {'[+]' if ok else '[-]'} CCDC-FB {'created' if ok else 'FAILED'}")

    return True


def create_profile_group(fw):
    """Create a Security Profile Group that bundles all profiles."""
    print("\n[*] Phase 2B: Creating profile group CCDC-Block...\n")
    pg_xpath = f"{VSYS_BASE}/profile-group/entry[@name='CCDC-Block']"
    pg_element = (
        "<virus><member>CCDC-AV</member></virus>"
        "<spyware><member>CCDC-AS</member></spyware>"
        "<vulnerability><member>CCDC-VP</member></vulnerability>"
        "<file-blocking><member>CCDC-FB</member></file-blocking>"
    )
    ok = fw.set_config(pg_xpath, pg_element)
    print(f"  {'[+]' if ok else '[-]'} CCDC-Block profile group {'created' if ok else 'FAILED'}")
    return ok


def attach_profiles_to_rules(fw):
    """Attach the CCDC-Block profile group to all existing Allow-* rules."""
    print("\n[*] Phase 2C: Attaching profiles to rules...\n")

    # Get current security rules to find their names
    rules_xpath = f"{VSYS_BASE}/rulebase/security/rules"
    result = fw.get_config(rules_xpath)
    if result is None:
        print("  [-] Could not read current rules")
        return False

    root = ET.fromstring(result)
    rule_names = []
    for entry in root.findall(".//entry"):
        name = entry.attrib.get("name", "")
        if name:
            rule_names.append(name)

    if not rule_names:
        print("  [-] No rules found — run pa_deploy.py first")
        return False

    print(f"  Found {len(rule_names)} rules: {', '.join(rule_names)}")

    for name in rule_names:
        # Skip the temporary allow-all and any deny rules
        if "All-Temp" in name or "Deny" in name:
            print(f"  [.] Skipping {name}")
            continue
        if not name.startswith("Allow"):
            print(f"  [.] Skipping {name} (not an Allow rule)")
            continue

        xpath = f"{rules_xpath}/entry[@name='{name}']/profile-setting"
        element = "<group><member>CCDC-Block</member></group>"
        ok = fw.set_config(xpath, element)
        print(f"  {'[+]' if ok else '[-]'} {name} -> CCDC-Block")

    return True


def enable_default_logging(fw):
    """Turn on logging for the default interzone and intrazone deny rules."""
    print("\n[*] Phase 2D: Enabling logging on default rules...\n")

    base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase"

    for rule in ["interzone-default", "intrazone-default"]:
        xpath = f"{base}/default-rules/entry[@name='{rule}']"
        ok = fw.set_config(xpath, "<log-end>yes</log-end>")
        print(f"  {'[+]' if ok else '[-]'} {rule} logging {'enabled' if ok else 'FAILED'}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  python3 {sys.argv[0]} --config team_config.json")
        print(f"  python3 {sys.argv[0]} --config team_config.json --dry-run")
        print(f"  python3 {sys.argv[0]} <FW_MGMT_IP> <ADMIN_PASSWORD>")
        sys.exit(1)

    dry_run = "--dry-run" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--dry-run"]

    if args[0] == "--config":
        with open(args[1]) as f:
            config = json.load(f)
        fw_ip = config["fw_mgmt_ip"]
        pw = config["admin_password"]
        user = config.get("admin_user", "admin")
    else:
        fw_ip = args[0]
        pw = args[1]
        user = "admin"

    print(f"\n{'='*60}")
    if dry_run:
        print(f"  ALCCDC 2026 - Phase 2: Security Profiles (DRY RUN)")
    else:
        print(f"  ALCCDC 2026 - Phase 2: Security Profiles")
    print(f"  Target: {fw_ip}")
    print(f"{'='*60}\n")

    fw = PANOSFirewall(fw_ip, pw, user, dry_run=dry_run)
    if not fw.get_api_key():
        print("[!] FATAL: Cannot authenticate.")
        sys.exit(1)

    create_profiles(fw)
    create_profile_group(fw)
    attach_profiles_to_rules(fw)
    enable_default_logging(fw)

    fw.commit()

    print(f"\n{'='*60}")
    print(f"  PHASE 2 COMPLETE")
    print(f"{'='*60}")
    if dry_run:
        print(f"\n[*] DRY RUN complete. No changes were made to any firewall.")
    else:
        print(f"\n[!] VERIFY ALL SCORED SERVICES ARE STILL WORKING")
        print(f"[!] If anything broke, remove the profile group from that rule via Web UI")


if __name__ == "__main__":
    main()
