#!/usr/bin/env python3
"""
ALCCDC 2026 - Palo Alto NGFW Rapid Deployment Script
=====================================================
Run from any machine with network access to the firewall management IP.
No external dependencies - uses only Python stdlib (urllib, xml, ssl).

Phases:
  Phase 1 - Rulebase: Competition-critical allow rules (scoring, ICMP, CCS, infra, services)
  Phase 2 - Security Profiles: Best-practice profiles derived from IronSkillet templates
  Phase 3 - Attach & Harden: Attach profiles to rules, device hardening, log forwarding

Usage:
  python3 pa_deploy.py <FW_MGMT_IP> <ADMIN_PASSWORD> <TEAM_NUMBER> [--phase 1|2|3|all]

Examples:
  python3 pa_deploy.py 192.168.1.1 MyStr0ngP@ss 5              # Runs all phases
  python3 pa_deploy.py 192.168.1.1 MyStr0ngP@ss 5 --phase 1    # Only Phase 1 (rules)
  python3 pa_deploy.py 192.168.1.1 MyStr0ngP@ss 5 --phase 2    # Only Phase 2 (profiles)
  python3 pa_deploy.py 192.168.1.1 MyStr0ngP@ss 5 --phase 3    # Only Phase 3 (attach+harden)

IMPORTANT: Always verify scored services after EACH phase commit!
"""

import sys
import ssl
import time
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

# ============================================================
# CONFIGURATION - Edit these before competition if needed
# ============================================================
TEAM_NUMBER = "XX"  # Will be overridden by CLI arg

# Scored service IPs (template - {t} replaced with team number)
SERVICES = {
    "dns":    {"ip": "10.{t}.{t}.5",    "ports": ["53"],   "apps": ["dns"]},
    "pop3":   {"ip": "10.{t}.{t}.10",   "ports": ["110"],  "apps": ["pop3"]},
    "smtp":   {"ip": "10.{t}.{t}.10",   "ports": ["25"],   "apps": ["smtp"]},
    "http1":  {"ip": "10.{t}.{t}.15",   "ports": ["80"],   "apps": ["web-browsing"]},
    "http2":  {"ip": "10.{t}.{t}.20",   "ports": ["80"],   "apps": ["web-browsing"]},
    "http3":  {"ip": "10.{t}.{t}.25",   "ports": ["80"],   "apps": ["web-browsing"]},
    "http4":  {"ip": "10.{t}.{t}.30",   "ports": ["80"],   "apps": ["web-browsing"]},
    "ssh1":   {"ip": "10.{t}.{t}.50",   "ports": ["22"],   "apps": ["ssh"]},
    "ssh2":   {"ip": "10.{t}.{t}.51",   "ports": ["22"],   "apps": ["ssh"]},
    "ftp":    {"ip": "10.{t}.{t}.52",   "ports": ["21"],   "apps": ["ftp"]},
    "help":   {"ip": "10.{t}.{t}.54",   "ports": ["80"],   "apps": ["web-browsing"]},
    "hagen":  {"ip": "172.16.{t}.11",   "ports": ["80"],   "apps": ["web-browsing"]},
    "ssh3":   {"ip": "172.16.{t}.12",   "ports": ["22"],   "apps": ["ssh"]},
}

ALWAYS_ALLOW = {
    "scoring_subnet": "192.168.28.0/24",
    "comp_infra_1":   "10.120.0.0/16",
    "comp_infra_2":   "10.110.0.0/16",
    "ccs_client":     "10.120.0.111",
    "syslog_target":  "10.120.0.201",
    "patch_server":   "10.120.0.9",
    "inject_portal":  "10.120.0.20",
    "comp_dns":       "10.120.0.53",
    "outbound_proxy": "10.120.0.200",
}

# IronSkillet-derived: DNS Sinkhole addresses (PA official)
SINKHOLE_IPV4 = "sinkhole.paloaltonetworks.com"  # FQDN used since PAN-OS 9.0+
SINKHOLE_IPV6 = "2600:5200::1"                    # Bogon IPv6

# Syslog target for competition (ESXi syslog)
SYSLOG_TARGET = "10.120.0.201"

# URL categories to block (IronSkillet best practice + CCDC additions)
URL_BLOCK_CATEGORIES = [
    "command-and-control", "hacking", "malware", "phishing", "grayware",
    "dynamic-dns", "unknown", "proxy-avoidance-and-anonymizers",
    "parked", "newly-registered-domain", "high-risk",
]

# URL categories to alert (everything else gets alert for logging)
URL_ALERT_CATEGORIES = [
    "adult", "abused-drugs", "gambling", "extremism",
    "questionable", "not-resolved",
]

# Dangerous file types to block (IronSkillet best practice)
BLOCKED_FILE_TYPES = [
    "bat", "com", "dll", "exe", "hta", "msi", "pif", "scr", "vbs",
    "cab", "cpl", "hlp", "inf", "jse", "lnk", "reg", "rgs",
    "vbe", "wsf", "wsh", "ws", "chm", "cmd",
]


# ============================================================
# PANOS FIREWALL API CLIENT
# ============================================================

class PANOSFirewall:
    """Minimal PAN-OS XML API client using only Python stdlib."""

    def __init__(self, host, password, user="admin"):
        self.host = host
        self.base_url = f"https://{host}/api/"
        self.user = user
        self.password = password
        self.key = None
        # Disable SSL verification (self-signed cert in competition)
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, params, timeout=30):
        """Make an API request and return the raw response text."""
        url = self.base_url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url)
        try:
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=timeout)
            return resp.read().decode()
        except Exception as e:
            print(f"  [-] API request error: {e}")
            return f'<response status="error"><msg>{e}</msg></response>'

    def get_api_key(self):
        """Authenticate and retrieve API key."""
        params = {
            "type": "keygen",
            "user": self.user,
            "password": self.password
        }
        result = self._request(params)
        root = ET.fromstring(result)
        key_elem = root.find(".//key")
        if key_elem is not None:
            self.key = key_elem.text
            print(f"[+] API key obtained successfully")
            return True
        else:
            print(f"[-] Failed to get API key: {result}")
            return False

    def set_config(self, xpath, element):
        """Push a configuration element via the API. Returns True on success."""
        params = {
            "type": "config",
            "action": "set",
            "xpath": xpath,
            "element": element,
            "key": self.key
        }
        result = self._request(params)
        root = ET.fromstring(result)
        status = root.attrib.get("status", "error")
        if status == "success":
            return True
        else:
            msg = root.find(".//msg")
            msg_text = msg.text if msg is not None else result[:200]
            print(f"  [-] Config set failed: {msg_text}")
            return False

    def commit(self):
        """Commit the candidate configuration."""
        params = {
            "type": "commit",
            "cmd": "<commit></commit>",
            "key": self.key
        }
        print("[*] Committing configuration...")
        result = self._request(params, timeout=120)
        root = ET.fromstring(result)
        status = root.attrib.get("status", "error")
        if status == "success":
            print("[+] Commit initiated successfully")
            # Wait a moment for commit job to start
            time.sleep(3)
            return True
        else:
            print(f"[-] Commit failed: {result[:200]}")
            return False

    def op_command(self, cmd):
        """Execute an operational command."""
        params = {
            "type": "op",
            "cmd": cmd,
            "key": self.key
        }
        return self._request(params)


# ============================================================
# XML ELEMENT BUILDERS
# ============================================================

def members(items):
    """Build <member> XML elements from a list."""
    return "".join(f"<member>{i}</member>" for i in items)


def build_security_rule_element(from_zones, to_zones, sources, destinations,
                                 applications, services, action, log_end=True,
                                 log_start=False, profile_group=None):
    """Build XML element for a security rule."""
    parts = []
    parts.append(f"<from>{members(from_zones)}</from>")
    parts.append(f"<to>{members(to_zones)}</to>")
    parts.append(f"<source>{members(sources)}</source>")
    parts.append(f"<destination>{members(destinations)}</destination>")
    parts.append(f"<application>{members(applications)}</application>")
    parts.append(f"<service>{members(services)}</service>")
    parts.append(f"<action>{action}</action>")
    if log_end:
        parts.append("<log-end>yes</log-end>")
    if log_start:
        parts.append("<log-start>yes</log-start>")
    if profile_group:
        parts.append(
            f"<profile-setting><group>{members([profile_group])}</group></profile-setting>"
        )
    return "".join(parts)


# ============================================================
# PHASE 1: COMPETITION RULEBASE
# ============================================================

def deploy_phase1_rules(fw, team_num):
    """
    Phase 1: Create the competition-critical security rules.
    Start permissive with full logging, ensure scoring works.
    """
    t = team_num
    base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

    print("\n" + "="*60)
    print("  PHASE 1: Competition Rulebase")
    print("="*60)

    # Rule 1: Allow scoring subnet (NEVER remove this rule)
    print("  [+] Allow-Scoring rule (192.168.28.0/24 -> any)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-Scoring']",
        build_security_rule_element(
            ["any"], ["any"],
            ["192.168.28.0/24"], ["any"],
            ["any"], ["any"], "allow",
            log_end=True, log_start=True
        )
    )

    # Rule 2: Allow ICMP from competition infrastructure
    print("  [+] Allow-Comp-ICMP rule")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-Comp-ICMP']",
        build_security_rule_element(
            ["any"], ["any"],
            ["10.120.0.0/16", "10.110.0.0/16"], ["any"],
            ["ping"], ["application-default"], "allow"
        )
    )

    # Rule 3: Allow CCSClient outbound
    print("  [+] Allow-CCSClient rule (-> 10.120.0.111)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-CCSClient']",
        build_security_rule_element(
            ["any"], ["any"],
            ["any"], ["10.120.0.111"],
            ["any"], ["service-http", "service-https"], "allow"
        )
    )

    # Rule 4: Allow competition infrastructure
    infra_ips = ["10.120.0.201", "10.120.0.9", "10.120.0.20",
                 "10.120.0.53", "10.120.0.200"]
    print(f"  [+] Allow-CompInfra rule ({len(infra_ips)} IPs)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-CompInfra']",
        build_security_rule_element(
            ["any"], ["any"],
            ["any"], infra_ips,
            ["any"], ["any"], "allow"
        )
    )

    # Rule 5: Allow inbound to scored services
    all_svc_ips = [svc["ip"].format(t=t) for svc in SERVICES.values()]
    # Deduplicate (smtp/pop3 share an IP)
    all_svc_ips = list(dict.fromkeys(all_svc_ips))
    print(f"  [+] Allow-Scored-Services rule ({len(all_svc_ips)} unique IPs)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-Scored-Services']",
        build_security_rule_element(
            ["any"], ["any"],
            ["any"], all_svc_ips,
            ["any"], ["any"], "allow"
        )
    )

    # Rule 6: Temporary Allow-All with full logging (safety net)
    print("  [+] Allow-All-Temp rule (will disable in Phase 3)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-All-Temp']",
        build_security_rule_element(
            ["any"], ["any"],
            ["any"], ["any"],
            ["any"], ["any"], "allow",
            log_end=True, log_start=True
        )
    )

    fw.commit()
    print("\n[+] Phase 1 complete!")
    print("[!] >>> VERIFY ALL SCORED SERVICES ARE WORKING <<<")
    print("[!] >>> Then run Phase 2 to deploy security profiles <<<\n")


# ============================================================
# PHASE 2: SECURITY PROFILES (IronSkillet-Derived)
# ============================================================
# These profiles are modeled on IronSkillet best practices with
# CCDC-specific tuning. Three tiers per profile type:
#   Outbound- : traffic leaving your network (strictest)
#   Inbound-  : traffic entering your network
#   Internal- : intra-zone traffic (slightly relaxed)
#   Alert-Only-: monitoring without blocking (safe fallback)
# Plus a CCDC-Profiles group bundling the Outbound set.

def deploy_phase2_profiles(fw):
    """
    Phase 2: Deploy IronSkillet-derived security profiles.
    Creates AV, Anti-Spyware, Vuln Protection, URL Filtering,
    File Blocking, WildFire, and Security Profile Groups.
    """
    base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
    profiles_xpath = f"{base}/profiles"
    shared_xpath = "/config/shared"

    print("\n" + "="*60)
    print("  PHASE 2: Security Profiles (IronSkillet Best Practices)")
    print("="*60)

    success_count = 0
    fail_count = 0

    def push(name, xpath, element):
        nonlocal success_count, fail_count
        if fw.set_config(xpath, element):
            success_count += 1
        else:
            fail_count += 1
            print(f"  [!] WARNING: '{name}' may require a license not yet active")

    # ----------------------------------------------------------
    # 2A. ANTIVIRUS PROFILES
    # ----------------------------------------------------------
    # IronSkillet: All decoders set to reset-both for AV + WildFire signatures
    # http2 decoder included (PAN-OS 9.0+)
    print("\n  --- Antivirus Profiles ---")

    av_decoders_strict = """
        <decoder><entry name="http"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
        <decoder><entry name="http2"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
        <decoder><entry name="smtp"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
        <decoder><entry name="imap"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
        <decoder><entry name="pop3"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
        <decoder><entry name="ftp"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
        <decoder><entry name="smb"><action>reset-both</action><wildfire-action>reset-both</wildfire-action></entry></decoder>
    """

    av_decoders_alert = """
        <decoder><entry name="http"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
        <decoder><entry name="http2"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
        <decoder><entry name="smtp"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
        <decoder><entry name="imap"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
        <decoder><entry name="pop3"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
        <decoder><entry name="ftp"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
        <decoder><entry name="smb"><action>alert</action><wildfire-action>alert</wildfire-action></entry></decoder>
    """

    # Outbound-AV (strictest - used for outbound and default)
    print("  [+] Outbound-AV")
    push("Outbound-AV",
        f"{profiles_xpath}/virus/entry[@name='Outbound-AV']",
        av_decoders_strict
    )

    # Inbound-AV (identical to outbound for CCDC - block everything)
    print("  [+] Inbound-AV")
    push("Inbound-AV",
        f"{profiles_xpath}/virus/entry[@name='Inbound-AV']",
        av_decoders_strict
    )

    # Internal-AV (identical for CCDC - trust nothing internally either)
    print("  [+] Internal-AV")
    push("Internal-AV",
        f"{profiles_xpath}/virus/entry[@name='Internal-AV']",
        av_decoders_strict
    )

    # Alert-Only-AV (safe fallback - alerts but doesn't block)
    print("  [+] Alert-Only-AV")
    push("Alert-Only-AV",
        f"{profiles_xpath}/virus/entry[@name='Alert-Only-AV']",
        av_decoders_alert
    )

    # ----------------------------------------------------------
    # 2B. ANTI-SPYWARE PROFILES
    # ----------------------------------------------------------
    # IronSkillet: Block critical/high/medium, default for low/info
    # DNS sinkholing enabled with PA official sinkhole addresses
    print("\n  --- Anti-Spyware Profiles ---")

    def build_antispyware_xml(name, medium_action="reset-both"):
        """Build anti-spyware profile XML. medium_action varies by tier."""
        return f"""
        <rules>
            <entry name="{name}-critical">
                <severity><member>critical</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <action><reset-both/></action>
            </entry>
            <entry name="{name}-high">
                <severity><member>high</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <action><reset-both/></action>
            </entry>
            <entry name="{name}-medium">
                <severity><member>medium</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <action><{medium_action}/></action>
            </entry>
            <entry name="{name}-low">
                <severity><member>low</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>disable</packet-capture>
                <action><default-action/></action>
            </entry>
            <entry name="{name}-info">
                <severity><member>informational</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>disable</packet-capture>
                <action><default-action/></action>
            </entry>
        </rules>
        <botnet-domains>
            <lists>
                <entry name="default-paloalto-dns">
                    <packet-capture>single-packet</packet-capture>
                    <action><sinkhole/></action>
                </entry>
            </lists>
            <sinkhole>
                <ipv4-address>{SINKHOLE_IPV4}</ipv4-address>
                <ipv6-address>{SINKHOLE_IPV6}</ipv6-address>
            </sinkhole>
            <threat-exception/>
        </botnet-domains>
        """

    # Outbound-AS
    print("  [+] Outbound-AS (with DNS sinkholing)")
    push("Outbound-AS",
        f"{profiles_xpath}/spyware/entry[@name='Outbound-AS']",
        build_antispyware_xml("Outbound-AS", "reset-both")
    )

    # Inbound-AS
    print("  [+] Inbound-AS")
    push("Inbound-AS",
        f"{profiles_xpath}/spyware/entry[@name='Inbound-AS']",
        build_antispyware_xml("Inbound-AS", "reset-both")
    )

    # Internal-AS (slightly relaxed - medium uses default)
    print("  [+] Internal-AS (medium=default)")
    push("Internal-AS",
        f"{profiles_xpath}/spyware/entry[@name='Internal-AS']",
        build_antispyware_xml("Internal-AS", "default-action")
    )

    # Alert-Only-AS (all alerts, no blocking)
    print("  [+] Alert-Only-AS")
    alert_as_xml = """
        <rules>
            <entry name="Alert-Only-AS-rule">
                <severity><member>any</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>disable</packet-capture>
                <action><alert/></action>
            </entry>
        </rules>
        <botnet-domains>
            <lists>
                <entry name="default-paloalto-dns">
                    <packet-capture>disable</packet-capture>
                    <action><alert/></action>
                </entry>
            </lists>
            <sinkhole>
                <ipv4-address>{sinkv4}</ipv4-address>
                <ipv6-address>{sinkv6}</ipv6-address>
            </sinkhole>
        </botnet-domains>
    """.format(sinkv4=SINKHOLE_IPV4, sinkv6=SINKHOLE_IPV6)
    push("Alert-Only-AS",
        f"{profiles_xpath}/spyware/entry[@name='Alert-Only-AS']",
        alert_as_xml
    )

    # ----------------------------------------------------------
    # 2C. VULNERABILITY PROTECTION PROFILES
    # ----------------------------------------------------------
    # IronSkillet: Block critical/high/medium, default for low/info
    # Client and server rules with packet capture
    print("\n  --- Vulnerability Protection Profiles ---")

    def build_vuln_profile_xml(name, medium_action="reset-both"):
        return f"""
        <rules>
            <entry name="{name}-critical">
                <severity><member>critical</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <host>any</host>
                <action><reset-both/></action>
                <vendor-id><member>any</member></vendor-id>
                <cve><member>any</member></cve>
            </entry>
            <entry name="{name}-high">
                <severity><member>high</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <host>any</host>
                <action><reset-both/></action>
                <vendor-id><member>any</member></vendor-id>
                <cve><member>any</member></cve>
            </entry>
            <entry name="{name}-medium">
                <severity><member>medium</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <host>any</host>
                <action><{medium_action}/></action>
                <vendor-id><member>any</member></vendor-id>
                <cve><member>any</member></cve>
            </entry>
            <entry name="{name}-low">
                <severity><member>low</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>disable</packet-capture>
                <host>any</host>
                <action><default-action/></action>
                <vendor-id><member>any</member></vendor-id>
                <cve><member>any</member></cve>
            </entry>
            <entry name="{name}-info">
                <severity><member>informational</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>disable</packet-capture>
                <host>any</host>
                <action><default-action/></action>
                <vendor-id><member>any</member></vendor-id>
                <cve><member>any</member></cve>
            </entry>
        </rules>
        """

    print("  [+] Outbound-VP")
    push("Outbound-VP",
        f"{profiles_xpath}/vulnerability/entry[@name='Outbound-VP']",
        build_vuln_profile_xml("Outbound-VP", "reset-both")
    )

    print("  [+] Inbound-VP")
    push("Inbound-VP",
        f"{profiles_xpath}/vulnerability/entry[@name='Inbound-VP']",
        build_vuln_profile_xml("Inbound-VP", "reset-both")
    )

    print("  [+] Internal-VP (medium=default)")
    push("Internal-VP",
        f"{profiles_xpath}/vulnerability/entry[@name='Internal-VP']",
        build_vuln_profile_xml("Internal-VP", "default-action")
    )

    print("  [+] Alert-Only-VP")
    push("Alert-Only-VP",
        f"{profiles_xpath}/vulnerability/entry[@name='Alert-Only-VP']",
        """<rules><entry name="Alert-Only-VP-rule">
            <severity><member>any</member></severity>
            <category>any</category><threat-name>any</threat-name>
            <packet-capture>disable</packet-capture><host>any</host>
            <action><alert/></action>
            <vendor-id><member>any</member></vendor-id>
            <cve><member>any</member></cve>
        </entry></rules>"""
    )

    # ----------------------------------------------------------
    # 2D. URL FILTERING PROFILES
    # ----------------------------------------------------------
    # IronSkillet: Block C2, malware, phishing, hacking, grayware + extras
    # All other categories set to alert for logging
    print("\n  --- URL Filtering Profiles ---")

    def build_url_profile_xml(name, block_cats, alert_cats):
        """Build URL filtering profile. Non-listed categories get alert."""
        cat_parts = []
        for cat in block_cats:
            cat_parts.append(f"<entry name=\"{cat}\"><action>block</action></entry>")
        for cat in alert_cats:
            cat_parts.append(f"<entry name=\"{cat}\"><action>alert</action></entry>")
        return f"""
        <credential-enforcement><mode><disabled/></mode></credential-enforcement>
        <allow><member>none</member></allow>
        <block>{''.join(f'<member>{c}</member>' for c in block_cats)}</block>
        <alert>{''.join(f'<member>{c}</member>' for c in alert_cats)}</alert>
        """

    print("  [+] Outbound-URL (blocks C2, malware, phishing, etc.)")
    push("Outbound-URL",
        f"{profiles_xpath}/url-filtering/entry[@name='Outbound-URL']",
        build_url_profile_xml("Outbound-URL", URL_BLOCK_CATEGORIES, URL_ALERT_CATEGORIES)
    )

    print("  [+] Alert-Only-URL")
    push("Alert-Only-URL",
        f"{profiles_xpath}/url-filtering/entry[@name='Alert-Only-URL']",
        """<credential-enforcement><mode><disabled/></mode></credential-enforcement>
        <alert><member>any</member></alert>"""
    )

    # ----------------------------------------------------------
    # 2E. FILE BLOCKING PROFILES
    # ----------------------------------------------------------
    # IronSkillet: Block common malicious file types, alert on all others
    print("\n  --- File Blocking Profiles ---")

    file_types_xml = members(BLOCKED_FILE_TYPES)

    print("  [+] Outbound-FB (blocks dangerous file types)")
    push("Outbound-FB",
        f"{profiles_xpath}/file-blocking/entry[@name='Outbound-FB']",
        f"""<rules>
            <entry name="Block-Dangerous-Types">
                <application>{members(['any'])}</application>
                <file-type>{file_types_xml}</file-type>
                <direction>both</direction>
                <action>block</action>
            </entry>
            <entry name="Alert-All-Others">
                <application>{members(['any'])}</application>
                <file-type>{members(['any'])}</file-type>
                <direction>both</direction>
                <action>alert</action>
            </entry>
        </rules>"""
    )

    print("  [+] Alert-Only-FB")
    push("Alert-Only-FB",
        f"{profiles_xpath}/file-blocking/entry[@name='Alert-Only-FB']",
        f"""<rules>
            <entry name="Alert-All">
                <application>{members(['any'])}</application>
                <file-type>{members(['any'])}</file-type>
                <direction>both</direction>
                <action>alert</action>
            </entry>
        </rules>"""
    )

    # ----------------------------------------------------------
    # 2F. WILDFIRE ANALYSIS PROFILES
    # ----------------------------------------------------------
    # IronSkillet: Forward all file types for all apps in both directions
    # Uses public-cloud analysis
    print("\n  --- WildFire Analysis Profiles ---")

    wf_xml = f"""<rules>
        <entry name="Forward-All">
            <application>{members(['any'])}</application>
            <file-type>{members(['any'])}</file-type>
            <direction>both</direction>
            <analysis>public-cloud</analysis>
        </entry>
    </rules>"""

    print("  [+] Outbound-WF")
    push("Outbound-WF",
        f"{profiles_xpath}/wildfire-analysis/entry[@name='Outbound-WF']",
        wf_xml
    )

    print("  [+] Inbound-WF")
    push("Inbound-WF",
        f"{profiles_xpath}/wildfire-analysis/entry[@name='Inbound-WF']",
        wf_xml
    )

    print("  [+] Internal-WF")
    push("Internal-WF",
        f"{profiles_xpath}/wildfire-analysis/entry[@name='Internal-WF']",
        wf_xml
    )

    print("  [+] Alert-Only-WF")
    push("Alert-Only-WF",
        f"{profiles_xpath}/wildfire-analysis/entry[@name='Alert-Only-WF']",
        wf_xml  # WF is always forward-for-analysis, no blocking in WF profile itself
    )

    # ----------------------------------------------------------
    # 2G. SECURITY PROFILE GROUPS
    # ----------------------------------------------------------
    # Bundle profiles into groups for easy attachment to rules
    print("\n  --- Security Profile Groups ---")

    def build_profile_group_xml(av, spyware, vuln, url, fb, wf):
        return f"""
        <virus>{members([av])}</virus>
        <spyware>{members([spyware])}</spyware>
        <vulnerability>{members([vuln])}</vulnerability>
        <url-filtering>{members([url])}</url-filtering>
        <file-blocking>{members([fb])}</file-blocking>
        <wildfire-analysis>{members([wf])}</wildfire-analysis>
        """

    # Primary group: strictest profiles for outbound/general traffic
    print("  [+] CCDC-Strict (Outbound profiles - primary group)")
    push("CCDC-Strict",
        f"{base}/profile-group/entry[@name='CCDC-Strict']",
        build_profile_group_xml(
            "Outbound-AV", "Outbound-AS", "Outbound-VP",
            "Outbound-URL", "Outbound-FB", "Outbound-WF"
        )
    )

    # Inbound group: for rules allowing traffic TO your servers
    print("  [+] CCDC-Inbound (Inbound profiles)")
    push("CCDC-Inbound",
        f"{base}/profile-group/entry[@name='CCDC-Inbound']",
        build_profile_group_xml(
            "Inbound-AV", "Inbound-AS", "Inbound-VP",
            "Outbound-URL", "Outbound-FB", "Inbound-WF"
        )
    )

    # Internal group: for intra-zone traffic
    print("  [+] CCDC-Internal (Internal profiles, slightly relaxed)")
    push("CCDC-Internal",
        f"{base}/profile-group/entry[@name='CCDC-Internal']",
        build_profile_group_xml(
            "Internal-AV", "Internal-AS", "Internal-VP",
            "Outbound-URL", "Outbound-FB", "Internal-WF"
        )
    )

    # Alert-only group: safe fallback that logs but doesn't block
    print("  [+] CCDC-AlertOnly (monitoring only - safe fallback)")
    push("CCDC-AlertOnly",
        f"{base}/profile-group/entry[@name='CCDC-AlertOnly']",
        build_profile_group_xml(
            "Alert-Only-AV", "Alert-Only-AS", "Alert-Only-VP",
            "Alert-Only-URL", "Alert-Only-FB", "Alert-Only-WF"
        )
    )

    # ----------------------------------------------------------
    # 2H. SINKHOLE ADDRESS OBJECTS
    # ----------------------------------------------------------
    # IronSkillet: Create address objects for sinkhole IPs
    # Used to identify infected hosts in traffic logs
    print("\n  --- Sinkhole Address Objects ---")

    print("  [+] Sinkhole-IPv4 address object")
    push("Sinkhole-IPv4",
        f"{base}/address/entry[@name='Sinkhole-IPv4']",
        f"<fqdn>{SINKHOLE_IPV4}</fqdn><description>PA DNS Sinkhole IPv4 - traffic here = infected host</description>"
    )

    print("  [+] Sinkhole-IPv6 address object")
    push("Sinkhole-IPv6",
        f"{base}/address/entry[@name='Sinkhole-IPv6']",
        f"<ip-netmask>{SINKHOLE_IPV6}/128</ip-netmask><description>PA DNS Sinkhole IPv6 - traffic here = infected host</description>"
    )

    # ----------------------------------------------------------
    # 2I. LOG FORWARDING PROFILE
    # ----------------------------------------------------------
    # IronSkillet: Default log forwarding profile referenced in security rules
    print("\n  --- Log Forwarding Profile ---")

    print("  [+] CCDC-Logging profile (syslog forwarding)")
    push("CCDC-Logging",
        f"{base}/log-settings/profiles/entry[@name='CCDC-Logging']",
        f"""<match-list>
            <entry name="Traffic-Log-Forward">
                <log-type>traffic</log-type>
                <filter>All Logs</filter>
                <send-to-panorama>no</send-to-panorama>
            </entry>
            <entry name="Threat-Log-Forward">
                <log-type>threat</log-type>
                <filter>All Logs</filter>
                <send-to-panorama>no</send-to-panorama>
            </entry>
            <entry name="WildFire-Log-Forward">
                <log-type>wildfire</log-type>
                <filter>All Logs</filter>
                <send-to-panorama>no</send-to-panorama>
            </entry>
            <entry name="URL-Log-Forward">
                <log-type>url</log-type>
                <filter>All Logs</filter>
                <send-to-panorama>no</send-to-panorama>
            </entry>
        </match-list>"""
    )

    # Commit Phase 2
    fw.commit()

    print(f"\n[+] Phase 2 complete! ({success_count} succeeded, {fail_count} warnings)")
    if fail_count > 0:
        print("[!] Some profiles had warnings - likely missing licenses.")
        print("[!] Those profiles may not be functional until licenses are activated.")
        print("[!] The profiles still exist as objects - they'll activate once licensed.")
    print("[!] >>> VERIFY SCORED SERVICES STILL WORK <<<")
    print("[!] >>> Then run Phase 3 to attach profiles to rules <<<\n")


# ============================================================
# PHASE 3: ATTACH PROFILES + DEVICE HARDENING
# ============================================================

def deploy_phase3_harden(fw, team_num):
    """
    Phase 3: Attach security profile groups to rules, harden device,
    configure dynamic updates, and disable Allow-All-Temp.
    """
    t = team_num
    base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
    dev_base = "/config/devices/entry[@name='localhost.localdomain']"

    print("\n" + "="*60)
    print("  PHASE 3: Attach Profiles + Device Hardening")
    print("="*60)

    # ----------------------------------------------------------
    # 3A. ATTACH PROFILE GROUPS TO EXISTING RULES
    # ----------------------------------------------------------
    print("\n  --- Attaching Security Profile Groups to Rules ---")

    # Scoring rule gets Alert-Only first (safest - never risk blocking scoring)
    print("  [+] Allow-Scoring -> CCDC-AlertOnly (safe: alert only for scoring)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-Scoring']/profile-setting",
        f"<group>{members(['CCDC-AlertOnly'])}</group>"
    )

    # CCSClient gets Alert-Only (don't risk blocking monitoring)
    print("  [+] Allow-CCSClient -> CCDC-AlertOnly")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-CCSClient']/profile-setting",
        f"<group>{members(['CCDC-AlertOnly'])}</group>"
    )

    # CompInfra gets Alert-Only (don't block infrastructure)
    print("  [+] Allow-CompInfra -> CCDC-AlertOnly")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-CompInfra']/profile-setting",
        f"<group>{members(['CCDC-AlertOnly'])}</group>"
    )

    # Scored services get CCDC-Inbound (block threats hitting your servers)
    print("  [+] Allow-Scored-Services -> CCDC-Inbound (block threats to servers)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-Scored-Services']/profile-setting",
        f"<group>{members(['CCDC-Inbound'])}</group>"
    )

    # ----------------------------------------------------------
    # 3B. ADD SINKHOLE DROP RULE
    # ----------------------------------------------------------
    # IronSkillet: Drop traffic destined for sinkhole IPs
    # This catches infected hosts trying to reach C2 domains
    print("\n  --- Sinkhole Traffic Drop Rule ---")
    print("  [+] Block-Sinkhole rule (catches C2 callbacks)")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Block-Sinkhole']",
        build_security_rule_element(
            ["any"], ["any"],
            ["any"], ["Sinkhole-IPv4", "Sinkhole-IPv6"],
            ["any"], ["any"], "deny",
            log_end=True, log_start=True
        )
    )

    # ----------------------------------------------------------
    # 3C. DISABLE ALLOW-ALL-TEMP
    # ----------------------------------------------------------
    print("\n  --- Disabling Allow-All-Temp ---")
    print("  [+] Disabling Allow-All-Temp rule")
    fw.set_config(
        f"{base}/rulebase/security/rules/entry[@name='Allow-All-Temp']/disabled",
        "yes"
    )

    # ----------------------------------------------------------
    # 3D. ENABLE LOGGING ON DEFAULT RULES
    # ----------------------------------------------------------
    # IronSkillet: Log the interzone-default and intrazone-default rules
    print("\n  --- Enable Logging on Default Rules ---")
    print("  [+] Logging on interzone-default (deny)")
    fw.set_config(
        f"{base}/rulebase/default-rules/entry[@name='interzone-default']/log-end",
        "yes"
    )
    print("  [+] Logging on intrazone-default (allow)")
    fw.set_config(
        f"{base}/rulebase/default-rules/entry[@name='intrazone-default']/log-end",
        "yes"
    )

    # ----------------------------------------------------------
    # 3E. DEVICE HARDENING (IronSkillet Settings)
    # ----------------------------------------------------------
    print("\n  --- Device Hardening (IronSkillet) ---")

    # Session rematch: re-evaluate existing sessions against new policies
    print("  [+] Enable session rematch on policy change")
    fw.set_config(
        f"{dev_base}/vsys/entry[@name='vsys1']/setting/session/rematch-sessions",
        "yes"
    )

    # Disable log suppression (ensure every log entry is recorded)
    print("  [+] Disable log suppression")
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/logging/log-suppression",
        "no"
    )

    # Notify users when web-app is blocked (application response page)
    print("  [+] Enable application block page")
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/application/notify-user",
        "yes"
    )

    # Enable log on high DP load
    print("  [+] Enable logging on high dataplane load")
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/management/enable-log-high-dp-load",
        "yes"
    )

    # TCP/UDP settings to prevent evasion techniques
    print("  [+] Harden TCP settings (prevent evasion)")
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/tcp/urgent-data",
        "clear"
    )
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/tcp/drop-zero-flag",
        "yes"
    )
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/tcp/bypass-exceed-oo-queue",
        "no"
    )
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/tcp/check-timestamp-option",
        "yes"
    )
    fw.set_config(
        f"{dev_base}/deviceconfig/setting/tcp/strip-mptcp-option",
        "yes"
    )

    # ----------------------------------------------------------
    # 3F. CONFIGURE DYNAMIC CONTENT UPDATE SCHEDULES
    # ----------------------------------------------------------
    # IronSkillet: Set schedules so signatures auto-update
    print("\n  --- Dynamic Update Schedules ---")

    # Threat content updates - check every 30 minutes
    print("  [+] Threat content: check every 30 min, install automatically")
    fw.set_config(
        f"{dev_base}/deviceconfig/system/update-schedule/threats",
        """<recurring><every-30-mins><at>2</at><action>download-and-install</action></every-30-mins></recurring>"""
    )

    # Antivirus updates - daily
    print("  [+] Antivirus: daily auto-update")
    fw.set_config(
        f"{dev_base}/deviceconfig/system/update-schedule/anti-virus",
        """<recurring><daily><at>01:00</at><action>download-and-install</action></daily></recurring>"""
    )

    # WildFire updates - every minute (if licensed)
    print("  [+] WildFire: real-time updates (every minute if licensed)")
    fw.set_config(
        f"{dev_base}/deviceconfig/system/update-schedule/wildfire",
        """<recurring><every-min><action>download-and-install</action></every-min></recurring>"""
    )

    # ----------------------------------------------------------
    # 3G. SAVE BACKUP CONFIG
    # ----------------------------------------------------------
    print("\n  --- Saving Configuration Backup ---")
    print("  [+] Saving post-hardening backup")
    fw.op_command("<save><config><to>post-hardening-backup.xml</to></config></save>")

    # Commit Phase 3
    fw.commit()

    print("\n[+] Phase 3 complete! Firewall is hardened.")
    print("="*60)
    print("  DEPLOYMENT SUMMARY")
    print("="*60)
    print("  Phase 1: Competition rulebase deployed")
    print("  Phase 2: IronSkillet security profiles created")
    print("  Phase 3: Profiles attached, device hardened")
    print()
    print("  Profile Groups Available:")
    print("    CCDC-Strict    - Full blocking (outbound profiles)")
    print("    CCDC-Inbound   - Full blocking (inbound profiles)")
    print("    CCDC-Internal  - Slightly relaxed (internal traffic)")
    print("    CCDC-AlertOnly - Alert only, no blocking (safe fallback)")
    print()
    print("  Rules with profiles:")
    print("    Allow-Scoring         -> CCDC-AlertOnly (safe)")
    print("    Allow-CCSClient       -> CCDC-AlertOnly (safe)")
    print("    Allow-CompInfra       -> CCDC-AlertOnly (safe)")
    print("    Allow-Scored-Services -> CCDC-Inbound   (blocks threats)")
    print("    Block-Sinkhole        -> Deny (catches C2 callbacks)")
    print("    Allow-All-Temp        -> DISABLED")
    print()
    print("[!] >>> VERIFY ALL SCORED SERVICES ARE WORKING <<<")
    print("[!] >>> Monitor > Logs > Threat for Red Team activity <<<")
    print("[!] >>> To upgrade scoring rule: change CCDC-AlertOnly -> CCDC-Inbound <<<")
    print("[!] >>> If anything breaks: re-enable Allow-All-Temp <<<")
    print(f"[!] >>> Config backup saved as: post-hardening-backup.xml <<<\n")


# ============================================================
# MAIN
# ============================================================

def print_banner():
    print("""
 ╔══════════════════════════════════════════════════════════╗
 ║       ALCCDC 2026 - Palo Alto NGFW Rapid Deploy         ║
 ║     IronSkillet Best Practices + Competition Rules       ║
 ╚══════════════════════════════════════════════════════════╝
    """)


def main():
    print_banner()

    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <FW_MGMT_IP> <ADMIN_PASSWORD> <TEAM_NUMBER> [--phase 1|2|3|all]")
        print(f"\nExamples:")
        print(f"  {sys.argv[0]} 192.168.1.1 MyStr0ngP@ss 5          # All phases")
        print(f"  {sys.argv[0]} 192.168.1.1 MyStr0ngP@ss 5 --phase 1  # Rules only")
        print(f"  {sys.argv[0]} 192.168.1.1 MyStr0ngP@ss 5 --phase 2  # Profiles only")
        print(f"  {sys.argv[0]} 192.168.1.1 MyStr0ngP@ss 5 --phase 3  # Attach+harden")
        sys.exit(1)

    fw_ip = sys.argv[1]
    password = sys.argv[2]
    team_num = sys.argv[3]

    # Parse phase argument
    phase = "all"
    if "--phase" in sys.argv:
        idx = sys.argv.index("--phase")
        if idx + 1 < len(sys.argv):
            phase = sys.argv[idx + 1]

    print(f"[*] Target: {fw_ip}")
    print(f"[*] Team:   {team_num}")
    print(f"[*] Phase:  {phase}")

    # Connect and authenticate
    fw = PANOSFirewall(fw_ip, password)
    if not fw.get_api_key():
        print("\n[-] Cannot proceed without API key. Check IP, credentials, and connectivity.")
        sys.exit(1)

    # Execute requested phase(s)
    if phase in ("1", "all"):
        deploy_phase1_rules(fw, team_num)
        if phase == "1":
            return

    if phase in ("2", "all"):
        deploy_phase2_profiles(fw)
        if phase == "2":
            return

    if phase in ("3", "all"):
        deploy_phase3_harden(fw, team_num)

    if phase not in ("1", "2", "3", "all"):
        print(f"[-] Unknown phase '{phase}'. Use 1, 2, 3, or all.")
        sys.exit(1)


if __name__ == "__main__":
    main()
