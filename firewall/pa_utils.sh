#!/bin/bash
# ============================================================
# ALCCDC 2026 - Palo Alto Utility Commands
# ============================================================
# Quick operational commands via the XML API.
# Run from Debian 13 box or any Linux VM with curl + python3.
#
# Usage:
#   ./pa_utils.sh <FW_IP> <API_KEY> <COMMAND>
#
# Commands:
#   backup <filename>    Export running config to a file
#   sessions             Show active sessions
#   traffic [count]      Show recent traffic log (default 20)
#   threats [count]      Show recent threat log (default 20)
#   sysinfo              Show system info
#   rules                List security rule names
#   admins               List admin accounts (check for rogue accounts)
#   interfaces           Show interface status
# ============================================================

set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <FW_IP> <API_KEY> <COMMAND> [args]"
    echo ""
    echo "Commands: backup, sessions, traffic, threats, sysinfo, rules, admins, interfaces"
    exit 1
fi

FW_IP="$1"
API_KEY="$2"
CMD="$3"
shift 3

api() {
    curl -sk "https://$FW_IP/api/?$1&key=$API_KEY"
}

api_op() {
    api "type=op&cmd=$1"
}

case "$CMD" in

backup)
    FILENAME="${1:-backup-$(date +%Y%m%d-%H%M%S).xml}"
    echo "[*] Exporting config to $FILENAME..."
    api "type=export&category=configuration" > "$FILENAME"
    echo "[+] Saved to $FILENAME ($(wc -c < "$FILENAME") bytes)"
    ;;

sessions)
    echo "[*] Active sessions:"
    api_op "<show><session><all></all></session></show>" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
for e in tree.findall('.//entry'):
    s = e.findtext('source','?')
    d = e.findtext('dst','?')
    dp = e.findtext('dport','?')
    a = e.findtext('application','?')
    st = e.findtext('state','?')
    print(f'  {s} -> {d}:{dp}  app={a}  state={st}')
" 2>/dev/null
    ;;

traffic)
    COUNT="${1:-20}"
    echo "[*] Last $COUNT traffic log entries:"
    api "type=log&log-type=traffic&nlogs=$COUNT" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
for e in tree.findall('.//entry'):
    ts  = e.findtext('receive_time','?')
    src = e.findtext('src','?')
    dst = e.findtext('dst','?')
    dp  = e.findtext('dport','?')
    app = e.findtext('app','?')
    act = e.findtext('action','?')
    rule = e.findtext('rule','?')
    print(f'  [{ts}] {src} -> {dst}:{dp} | app={app} | {act} (rule={rule})')
" 2>/dev/null
    ;;

threats)
    COUNT="${1:-20}"
    echo "[*] Last $COUNT threat log entries:"
    api "type=log&log-type=threat&nlogs=$COUNT" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
for e in tree.findall('.//entry'):
    ts  = e.findtext('receive_time','?')
    src = e.findtext('src','?')
    dst = e.findtext('dst','?')
    tid = e.findtext('threatid','?')
    sev = e.findtext('severity','?')
    act = e.findtext('action','?')
    print(f'  [{ts}] SEV={sev} {src} -> {dst} | {tid} | {act}')
" 2>/dev/null
    ;;

sysinfo)
    echo "[*] System info:"
    api_op "<show><system><info></info></system></show>" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
r = tree.find('.//result/system')
if r is None:
    print('  Could not parse response')
    sys.exit()
for field in ['hostname','ip-address','model','serial','sw-version',
              'app-version','av-version','threat-version','uptime']:
    v = r.findtext(field, 'N/A')
    print(f'  {field}: {v}')
" 2>/dev/null
    ;;

rules)
    echo "[*] Security rules:"
    api "type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
for e in tree.findall('.//rules/entry'):
    name = e.attrib.get('name','?')
    action = e.findtext('action','?')
    disabled = e.findtext('disabled','no')
    pg = e.find('.//profile-setting/group/member')
    profile = pg.text if pg is not None else 'none'
    status = ' [DISABLED]' if disabled == 'yes' else ''
    print(f'  {name}: {action} (profiles={profile}){status}')
" 2>/dev/null
    ;;

admins)
    echo "[*] Admin accounts (check for unauthorized accounts!):"
    api "type=config&action=get&xpath=/config/mgt-config/users" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
for e in tree.findall('.//users/entry'):
    name = e.attrib.get('name','?')
    role = e.findtext('.//role-based/superuser','')
    if role:
        print(f'  {name} [superuser]')
    else:
        print(f'  {name}')
" 2>/dev/null
    ;;

interfaces)
    echo "[*] Interface status:"
    api_op "<show><interface>all</interface></show>" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
for e in tree.findall('.//ifnet/entry'):
    name = e.findtext('name','?')
    ip = e.findtext('ip','N/A')
    zone = e.findtext('zone','N/A')
    status = e.findtext('status','?')
    print(f'  {name}: ip={ip} zone={zone} status={status}')
" 2>/dev/null
    ;;

*)
    echo "Unknown command: $CMD"
    echo "Available: backup, sessions, traffic, threats, sysinfo, rules, admins, interfaces"
    exit 1
    ;;
esac
