#!/bin/bash
# ============================================================
# ALCCDC 2026 - Palo Alto Threat Log Monitor
# ============================================================
# Polls the firewall threat log via API and prints new alerts.
# Run on the Debian 13 box (or any Linux VM that can reach the FW).
#
# Usage:
#   ./pa_monitor.sh <FW_MGMT_IP> <API_KEY>
#
# To get your API key first:
#   curl -sk "https://<FW_MGMT_IP>/api/?type=keygen&user=admin&password=<PW>"
#
# Or use the helper:
#   ./pa_monitor.sh --keygen <FW_MGMT_IP> <USER> <PASSWORD>
# ============================================================

set -euo pipefail

if [ "${1:-}" = "--keygen" ]; then
    if [ $# -lt 4 ]; then
        echo "Usage: $0 --keygen <FW_IP> <USER> <PASSWORD>"
        exit 1
    fi
    FW_IP="$2"
    USER="$3"
    PASS="$4"
    echo "[*] Requesting API key from $FW_IP..."
    RESULT=$(curl -sk "https://$FW_IP/api/?type=keygen&user=$USER&password=$PASS")
    KEY=$(echo "$RESULT" | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
k = tree.find('.//key')
print(k.text if k is not None else 'FAILED')
")
    if [ "$KEY" = "FAILED" ]; then
        echo "[-] Could not get API key. Response:"
        echo "$RESULT"
        exit 1
    fi
    echo "[+] API Key: $KEY"
    echo ""
    echo "Now run:"
    echo "  $0 $FW_IP $KEY"
    exit 0
fi

if [ $# -lt 2 ]; then
    echo "ALCCDC 2026 - Palo Alto Threat Monitor"
    echo ""
    echo "Usage:"
    echo "  $0 <FW_MGMT_IP> <API_KEY>         # Monitor threats"
    echo "  $0 --keygen <FW_IP> <USER> <PASS>  # Get API key first"
    exit 1
fi

FW_IP="$1"
API_KEY="$2"
INTERVAL="${3:-30}"

echo "============================================"
echo "  Threat Monitor - $FW_IP"
echo "  Polling every ${INTERVAL}s (Ctrl+C to stop)"
echo "============================================"
echo ""

while true; do
    curl -sk "https://$FW_IP/api/?type=log&log-type=threat&nlogs=20&key=$API_KEY" \
    | python3 -c "
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.stdin)
    entries = tree.findall('.//entry')
    if not entries:
        pass
    for e in entries:
        ts   = e.findtext('receive_time', '?')
        src  = e.findtext('src', '?')
        dst  = e.findtext('dst', '?')
        dp   = e.findtext('dport', '?')
        app  = e.findtext('app', '?')
        tid  = e.findtext('threatid', '?')
        act  = e.findtext('action', '?')
        sev  = e.findtext('severity', '?')
        print(f'[{ts}] SEV={sev} | {src} -> {dst}:{dp} | app={app} | threat={tid} | action={act}')
except Exception as ex:
    print(f'[parse error: {ex}]')
" 2>/dev/null
    sleep "$INTERVAL"
done
