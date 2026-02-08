#!/bin/bash
# Usage:./kill_switch.sh <ATTACKER_IP>
TARGET_IP=$1
echo "[!] ENGAGING KILL SWITCH FOR $TARGET_IP"
# Add your firewall specific commands here (pfctl or api calls)
echo "$(date) - BLOCKED $TARGET_IP - Automated Response" >>../../docs/incident_log.md
