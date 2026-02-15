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
    echo "ALCCDC 2026 - Palo Alto Utility Commands"
    echo ""
    echo "Usage: $0 <FW_IP> <API_KEY> <COMMAND> [args]"
    echo ""
    echo "Commands:"
    echo "  backup [passphrase]       Export config — encrypted with GPG if passphrase given"
    echo "  backup-list               List all local backups and on-firewall saved configs"
    echo "  restore <file> [pass]     Import a backup to the firewall (decrypts .enc files)"
    echo "  sessions                  Show active sessions"
    echo "  traffic [count]           Show recent traffic log (default 20)"
    echo "  threats [count]           Show recent threat log (default 20)"
    echo "  sysinfo                   Show system info"
    echo "  rules                     List security rule names and profile status"
    echo "  admins                    List admin accounts (check for rogue accounts)"
    echo "  interfaces                Show interface status"
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
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    RAND=$(head -c 6 /dev/urandom | xxd -p)
    RAW_FILE="/tmp/.fwstate_${RAND}.tmp"
    PASSPHRASE="${2:-}"

    echo "[*] Exporting config from $FW_IP..."
    api "type=export&category=configuration" > "$RAW_FILE" 2>/dev/null

    if [ ! -s "$RAW_FILE" ]; then
        echo "[-] Export failed — empty response"
        rm -f "$RAW_FILE"
        exit 1
    fi

    echo "[+] Raw config exported ($(wc -c < "$RAW_FILE") bytes)"

    if [ -n "$PASSPHRASE" ]; then
        # Encrypt with GPG symmetric (AES256), then shred the plaintext
        ENC_FILE="${HOME}/.sys_${RAND}_${TIMESTAMP}.enc"
        echo "$PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 \
            --symmetric --cipher-algo AES256 \
            --output "$ENC_FILE" "$RAW_FILE" 2>/dev/null

        if [ $? -eq 0 ]; then
            # Securely delete the plaintext
            shred -u "$RAW_FILE" 2>/dev/null || rm -f "$RAW_FILE"
            chmod 600 "$ENC_FILE"
            echo "[+] Encrypted backup: $ENC_FILE"
            echo "    To decrypt: gpg --decrypt $ENC_FILE > config.xml"
        else
            echo "[-] GPG encryption failed. Falling back to plaintext."
            PLAIN_FILE="${HOME}/.sys_${RAND}_${TIMESTAMP}.xml"
            mv "$RAW_FILE" "$PLAIN_FILE"
            chmod 600 "$PLAIN_FILE"
            echo "[!] Plaintext backup: $PLAIN_FILE"
        fi
    else
        PLAIN_FILE="${HOME}/.sys_${RAND}_${TIMESTAMP}.xml"
        mv "$RAW_FILE" "$PLAIN_FILE"
        chmod 600 "$PLAIN_FILE"
        echo "[!] Unencrypted backup: $PLAIN_FILE"
        echo "    To encrypt, re-run with a passphrase:"
        echo "    $0 $FW_IP <API_KEY> backup <PASSPHRASE>"
    fi
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

restore)
    # Restore from an encrypted or plaintext backup
    BACKUP_FILE="${1:-}"
    PASSPHRASE="${2:-}"
    if [ -z "$BACKUP_FILE" ]; then
        echo "Usage: $0 <FW_IP> <API_KEY> restore <BACKUP_FILE> [PASSPHRASE]"
        echo ""
        echo "  If the file ends in .enc, you must provide the passphrase."
        echo "  This imports the config and commits it."
        exit 1
    fi
    if [ ! -f "$BACKUP_FILE" ]; then
        echo "[-] File not found: $BACKUP_FILE"
        exit 1
    fi

    RESTORE_FILE="$BACKUP_FILE"
    TEMP_DECRYPT=""

    # Decrypt if encrypted
    if echo "$BACKUP_FILE" | grep -q '\.enc$'; then
        if [ -z "$PASSPHRASE" ]; then
            echo "[-] Encrypted file requires a passphrase"
            echo "    $0 $FW_IP <KEY> restore $BACKUP_FILE <PASSPHRASE>"
            exit 1
        fi
        TEMP_DECRYPT="/tmp/.fwrestore_$$.xml"
        echo "$PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 \
            --decrypt --output "$TEMP_DECRYPT" "$BACKUP_FILE" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo "[-] Decryption failed — wrong passphrase?"
            rm -f "$TEMP_DECRYPT"
            exit 1
        fi
        RESTORE_FILE="$TEMP_DECRYPT"
        echo "[+] Decrypted successfully"
    fi

    echo "[*] Importing config to firewall..."
    curl -sk -F "file=@${RESTORE_FILE}" \
        "https://$FW_IP/api/?type=import&category=configuration&key=$API_KEY" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
status = tree.getroot().attrib.get('status','?')
print(f'  Import status: {status}')
" 2>/dev/null

    # Clean up temp decrypted file
    if [ -n "$TEMP_DECRYPT" ]; then
        shred -u "$TEMP_DECRYPT" 2>/dev/null || rm -f "$TEMP_DECRYPT"
    fi

    echo ""
    echo "[!] Config imported. To activate it on the firewall:"
    echo "    1. SSH into the firewall"
    echo "    2. load config from <imported-filename>"
    echo "    3. commit"
    echo "    4. VERIFY ALL SCORED SERVICES"
    ;;

backup-list)
    echo "[*] Encrypted backups in home directory:"
    ls -la "${HOME}"/.sys_*.enc 2>/dev/null || echo "  (none found)"
    echo ""
    echo "[*] Plaintext backups in home directory:"
    ls -la "${HOME}"/.sys_*.xml 2>/dev/null || echo "  (none found)"
    echo ""
    echo "[*] Configs saved on the firewall:"
    api_op "<show><config><saved></saved></config></show>" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.stdin)
    for e in tree.findall('.//entry'):
        print(f'  {e.text}')
except:
    print('  (could not parse response)')
" 2>/dev/null
    ;;

*)
    echo "Unknown command: $CMD"
    echo "Available: backup, backup-list, restore, sessions, traffic, threats, sysinfo, rules, admins, interfaces"
    exit 1
    ;;
esac
