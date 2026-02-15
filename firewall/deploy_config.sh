#!/bin/bash
#
# ALCCDC 2026 - Palo Alto Config Template Deployer
# =================================================
# Replaces placeholders in ccdc-config-template.xml with real values,
# then imports and loads the config onto the firewall via XML API.
#
# Usage:
#   ./deploy_config.sh                  # Interactive mode (prompts for values)
#   ./deploy_config.sh --from-json team_config.json   # Read from JSON config
#
# Requirements: curl, sed, bash (all available on Debian 13)
# No Python or external dependencies needed.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/ccdc-config-template.xml"
OUTPUT="${SCRIPT_DIR}/ccdc-config.xml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} ALCCDC 2026 - Palo Alto Config Deployer${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# ------------------------------------------------------------------
# Check prerequisites
# ------------------------------------------------------------------
if [ ! -f "$TEMPLATE" ]; then
    echo -e "${RED}ERROR: Template file not found: ${TEMPLATE}${NC}"
    echo "Make sure ccdc-config-template.xml is in the same directory as this script."
    exit 1
fi

command -v curl >/dev/null 2>&1 || { echo -e "${RED}ERROR: curl is required but not installed.${NC}"; exit 1; }

# ------------------------------------------------------------------
# Gather values - interactive mode
# ------------------------------------------------------------------
echo -e "${YELLOW}Enter values from the team packet. Press Enter to keep default [shown in brackets].${NC}"
echo ""

read -p "Firewall Management IP [192.168.1.1]: " FW_MGMT_IP
FW_MGMT_IP=${FW_MGMT_IP:-192.168.1.1}

read -p "Admin username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -sp "Admin password (current/new): " ADMIN_PASS
echo ""

read -p "Team number: " TEAM_NUM

read -p "Scoring subnet [192.168.28.0/24]: " SCORING_SUBNET
SCORING_SUBNET=${SCORING_SUBNET:-192.168.28.0/24}

read -p "Competition DNS IP [10.120.0.53]: " COMP_DNS_IP
COMP_DNS_IP=${COMP_DNS_IP:-10.120.0.53}

read -p "Patch server IP [10.120.0.9]: " PATCH_SERVER_IP
PATCH_SERVER_IP=${PATCH_SERVER_IP:-10.120.0.9}

read -p "Inject portal IP [10.120.0.20]: " INJECT_PORTAL_IP
INJECT_PORTAL_IP=${INJECT_PORTAL_IP:-10.120.0.20}

read -p "Syslog target IP [10.120.0.201]: " SYSLOG_IP
SYSLOG_IP=${SYSLOG_IP:-10.120.0.201}

read -p "Proxy IP (IP:port or just IP) [10.120.0.200]: " PROXY_IP
PROXY_IP=${PROXY_IP:-10.120.0.200}

echo ""
echo -e "${YELLOW}Scored service IPs (from team packet):${NC}"
echo "Enter each IP or press Enter to use placeholder format 10.X.X.N"
echo "(You can also edit the XML file directly later)"
echo ""

T="${TEAM_NUM}"

read -p "DNS server IP [10.${T}.${T}.5]: " SVC_DNS_IP
SVC_DNS_IP=${SVC_DNS_IP:-10.${T}.${T}.5}

read -p "Mail server IP (SMTP/POP3) [10.${T}.${T}.10]: " SVC_MAIL_IP
SVC_MAIL_IP=${SVC_MAIL_IP:-10.${T}.${T}.10}

read -p "Web server 1 IP [10.${T}.${T}.15]: " SVC_WEB1_IP
SVC_WEB1_IP=${SVC_WEB1_IP:-10.${T}.${T}.15}

read -p "Web server 2 IP [10.${T}.${T}.20]: " SVC_WEB2_IP
SVC_WEB2_IP=${SVC_WEB2_IP:-10.${T}.${T}.20}

read -p "FTP server IP [10.${T}.${T}.25]: " SVC_FTP_IP
SVC_FTP_IP=${SVC_FTP_IP:-10.${T}.${T}.25}

read -p "E-Commerce server IP [10.${T}.${T}.30]: " SVC_ECOMM_IP
SVC_ECOMM_IP=${SVC_ECOMM_IP:-10.${T}.${T}.30}

# ------------------------------------------------------------------
# Perform replacements
# ------------------------------------------------------------------
echo ""
echo -e "${GREEN}[1/4] Generating config from template...${NC}"

cp "$TEMPLATE" "$OUTPUT"

sed -i "s|__TEAM_NUM__|${TEAM_NUM}|g" "$OUTPUT"
sed -i "s|__SCORING_SUBNET__|${SCORING_SUBNET}|g" "$OUTPUT"
sed -i "s|__COMP_DNS_IP__|${COMP_DNS_IP}|g" "$OUTPUT"
sed -i "s|__PATCH_SERVER_IP__|${PATCH_SERVER_IP}|g" "$OUTPUT"
sed -i "s|__INJECT_PORTAL_IP__|${INJECT_PORTAL_IP}|g" "$OUTPUT"
sed -i "s|__SYSLOG_IP__|${SYSLOG_IP}|g" "$OUTPUT"
sed -i "s|__PROXY_IP__|${PROXY_IP}|g" "$OUTPUT"
sed -i "s|__SVC_DNS_IP__|${SVC_DNS_IP}|g" "$OUTPUT"
sed -i "s|__SVC_MAIL_IP__|${SVC_MAIL_IP}|g" "$OUTPUT"
sed -i "s|__SVC_WEB1_IP__|${SVC_WEB1_IP}|g" "$OUTPUT"
sed -i "s|__SVC_WEB2_IP__|${SVC_WEB2_IP}|g" "$OUTPUT"
sed -i "s|__SVC_FTP_IP__|${SVC_FTP_IP}|g" "$OUTPUT"
sed -i "s|__SVC_ECOMM_IP__|${SVC_ECOMM_IP}|g" "$OUTPUT"

# Verify no placeholders remain
REMAINING=$(grep -c '__.*__' "$OUTPUT" 2>/dev/null || true)
if [ "$REMAINING" -gt 0 ]; then
    echo -e "${YELLOW}WARNING: ${REMAINING} unreplaced placeholders found:${NC}"
    grep -n '__.*__' "$OUTPUT" | head -20
    echo ""
    read -p "Continue anyway? (y/N): " CONT
    if [ "$CONT" != "y" ] && [ "$CONT" != "Y" ]; then
        echo "Aborted. Edit $OUTPUT manually and re-run."
        exit 1
    fi
fi

echo -e "${GREEN}  Config written to: ${OUTPUT}${NC}"

# ------------------------------------------------------------------
# Show summary for confirmation
# ------------------------------------------------------------------
echo ""
echo -e "${YELLOW}=== DEPLOYMENT SUMMARY ===${NC}"
echo "  Firewall:        https://${FW_MGMT_IP}"
echo "  Team:            ${TEAM_NUM}"
echo "  Scoring subnet:  ${SCORING_SUBNET}"
echo "  DNS:             ${COMP_DNS_IP}"
echo "  Patch server:    ${PATCH_SERVER_IP}"
echo "  Inject portal:   ${INJECT_PORTAL_IP}"
echo "  Scored services: ${SVC_DNS_IP}, ${SVC_MAIL_IP}, ${SVC_WEB1_IP},"
echo "                   ${SVC_WEB2_IP}, ${SVC_FTP_IP}, ${SVC_ECOMM_IP}"
echo ""
read -p "Push this config to the firewall? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo -e "${GREEN}Config saved to ${OUTPUT} but NOT pushed.${NC}"
    echo "To push manually:"
    echo "  1. Import: curl -k --form file=@${OUTPUT} \"https://${FW_MGMT_IP}/api/?type=import&category=configuration&key=<API_KEY>\""
    echo "  2. Load:   load config from ccdc-config.xml"
    echo "  3. Commit: commit"
    exit 0
fi

# ------------------------------------------------------------------
# Get API key
# ------------------------------------------------------------------
echo ""
echo -e "${GREEN}[2/4] Authenticating to firewall...${NC}"

API_RESPONSE=$(curl -sk "https://${FW_MGMT_IP}/api/?type=keygen&user=${ADMIN_USER}&password=${ADMIN_PASS}" 2>/dev/null)

API_KEY=$(echo "$API_RESPONSE" | grep -oP '(?<=<key>).*(?=</key>)' || true)

if [ -z "$API_KEY" ]; then
    echo -e "${RED}ERROR: Failed to get API key. Check IP, username, and password.${NC}"
    echo "Raw response: $API_RESPONSE"
    echo ""
    echo -e "${YELLOW}Config file is still saved at: ${OUTPUT}${NC}"
    echo "You can load it manually via the CLI:"
    echo "  1. SCP it:  scp ${OUTPUT} admin@${FW_MGMT_IP}:ccdc-config.xml"
    echo "  2. Load:    load config from ccdc-config.xml"
    echo "  3. Commit:  commit"
    exit 1
fi

echo -e "${GREEN}  API key obtained successfully.${NC}"

# ------------------------------------------------------------------
# Import the config file
# ------------------------------------------------------------------
echo -e "${GREEN}[3/4] Importing config file to firewall...${NC}"

IMPORT_RESPONSE=$(curl -sk --form "file=@${OUTPUT}" \
    "https://${FW_MGMT_IP}/api/?type=import&category=configuration&key=${API_KEY}" 2>/dev/null)

if echo "$IMPORT_RESPONSE" | grep -q "success"; then
    echo -e "${GREEN}  Config imported successfully.${NC}"
else
    echo -e "${RED}ERROR: Import failed.${NC}"
    echo "Response: $IMPORT_RESPONSE"
    echo ""
    echo "Try manual import via CLI instead."
    exit 1
fi

# ------------------------------------------------------------------
# Load and commit
# ------------------------------------------------------------------
echo -e "${GREEN}[4/4] Loading and committing config...${NC}"

# Load the imported config
LOAD_RESPONSE=$(curl -sk "https://${FW_MGMT_IP}/api/?type=op&cmd=<load><config><from>ccdc-config.xml</from></config></load>&key=${API_KEY}" 2>/dev/null)

if echo "$LOAD_RESPONSE" | grep -q "success"; then
    echo -e "${GREEN}  Config loaded into candidate configuration.${NC}"
else
    echo -e "${YELLOW}  Load response: ${LOAD_RESPONSE}${NC}"
    echo -e "${YELLOW}  Config may need manual load. Attempting commit anyway...${NC}"
fi

# Commit
echo -e "${YELLOW}  Committing (this takes 30-90 seconds)...${NC}"
COMMIT_RESPONSE=$(curl -sk "https://${FW_MGMT_IP}/api/?type=commit&cmd=<commit></commit>&key=${API_KEY}" 2>/dev/null)

if echo "$COMMIT_RESPONSE" | grep -q "success"; then
    echo -e "${GREEN}  Commit initiated successfully.${NC}"
else
    echo -e "${YELLOW}  Commit response: ${COMMIT_RESPONSE}${NC}"
fi

# ------------------------------------------------------------------
# Done
# ------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} DEPLOYMENT COMPLETE${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${RED}>>> CRITICAL: VERIFY ALL SCORED SERVICES NOW <<<${NC}"
echo ""
echo "Next steps:"
echo "  1. Check every scored service from External View VM"
echo "  2. If anything is broken:"
echo "     - Enable safety net: set rulebase security rules Allow-All-Temp disabled no"
echo "     - commit"
echo "     - Debug from traffic logs: Monitor > Logs > Traffic"
echo "  3. Save a working backup:"
echo "     - save config to phase2-hardened.xml"
echo ""
echo "Config backup saved locally at: ${OUTPUT}"
