#!/bin/bash
TARGET_NET=$1
OUTPUT_DIR="logs/session_${TEAM_NUM:-default}"
mkdir -p $OUTPUT_DIR

echo "[*] Passive Listen (10s)..."
timeout 10 tcpdump -i eth0 -n -c 100 'broadcast or multicast' > $OUTPUT_DIR/passive.log 2>&1

echo "[*] Active ARP Scan..."
if command -v arp-scan &> /dev/null; then
    arp-scan --localnet --ignoredups > $OUTPUT_DIR/arp_targets.txt
else
    echo "arp-scan not found, skipping."
fi

echo "[*] Nmap Service Scan (Fast)..."
nmap -Pn -n --open -p 21,22,23,80,443,445,3389,8080 -oX $OUTPUT_DIR/scan.xml $TARGET_NET
echo "[+] Scan results saved to $OUTPUT_DIR/scan.xml"
