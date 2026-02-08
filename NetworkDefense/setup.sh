#!/bin/bash
# setup.sh - CCDC Day 0 Initialization
echo "==================================================="
echo "   CCDC NETWORK DEFENSE - DAY 0 INITIALIZATION   "
echo "==================================================="
read -p "Enter Team Number (e.g., 1): " TEAM_NUM
read -p "Enter Network CIDR (e.g., 10.0.5.0/24): " NET_CIDR
read -p "Enter Gateway IP: " GATEWAY_IP
read -p "Enter Firewall Mgmt IP: " FW_IP

export TEAM_NUM
export NET_CIDR
export GATEWAY_IP
export FW_IP

echo "[+] Variables captured. Starting Discovery..."
mkdir -p logs/session_$TEAM_NUM
chmod +x scripts/discovery/quick_map.sh
./scripts/discovery/quick_map.sh "$NET_CIDR"
echo "[+] Done. Check inventory/hosts.ini"
