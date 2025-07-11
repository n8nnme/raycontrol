#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

function step() {
    echo -e "\n${YELLOW}--- $1 ---${NC}"
}

function remove_file_if_exists() {
    local file_path=$1
    if [ -f "$file_path" ]; then
        rm -f "$file_path"
        echo "Removed file: $file_path"
    else
        echo "File not found (OK): $file_path"
    fi
}

function remove_dir_if_exists() {
    local dir_path=$1
    if [ -d "$dir_path" ]; then
        rm -rf "$dir_path"
        echo "Removed directory: $dir_path"
    else
        echo "Directory not found (OK): $dir_path"
    fi
}

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: This script must be run as root.${NC}" >&2
  exit 1
fi

step "Ray.sh Smart Uninstaller"
echo "This script will remove files created by the ray.sh installer."
echo "It will then guide you through the optional removal of shared packages."
echo ""
read -rp "Are you sure you want to proceed? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Uninstallation cancelled."
    exit 1
fi

DOMAIN=""
INSTALL_CONF="/etc/ray-aio/install.conf"
if [ -f "$INSTALL_CONF" ]; then
    # shellcheck source=/dev/null
    source "$INSTALL_CONF"
fi

step "Phase 1: Removing Script-Specific Files (Fully Automated)"

step "Disabling and Stopping Services"
for service in xray hysteria-server; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        echo "Stopping and disabling '$service'..."
        systemctl disable --now "$service" &>/dev/null
    else
        echo "Service '$service.service' not found, skipping."
    fi
done
systemctl stop nftables &>/dev/null || true

step "Flushing Firewall Rules"
if command -v nft &> /dev/null; then
    echo "Flushing all rules from NFTables..."
    nft flush ruleset
    nft -s list ruleset > /etc/nftables.conf
    echo "Firewall rules have been cleared and the empty config has been saved."
else
    echo "Command 'nft' not found, skipping firewall flush."
fi

step "Removing Systemd Service Files"
remove_file_if_exists "/etc/systemd/system/xray.service"
remove_file_if_exists "/etc/systemd/system/hysteria-server.service"
echo "Reloading systemd daemon to apply changes..."
systemctl daemon-reload

step "Removing Let's Encrypt Certificate and Renewal Hook"
if [ -n "$DOMAIN" ] && command -v certbot &> /dev/null; then
    if certbot certificates -d "$DOMAIN" &>/dev/null; then
        echo "Deleting Let's Encrypt certificate for domain: $DOMAIN"
        certbot delete --non-interactive --cert-name "$DOMAIN"
    else
        echo "Certbot certificate for '$DOMAIN' not found, skipping deletion."
    fi
else
    echo "Domain variable not set or certbot not installed, cannot remove certificate."
fi
remove_file_if_exists "/etc/letsencrypt/renewal-hooks/post/reload_services.sh"

step "Removing All Script-Specific Files and Directories"
remove_file_if_exists "/usr/local/bin/xray"
remove_file_if_exists "/usr/local/bin/hysteria-server"
remove_file_if_exists "/usr/local/bin/raycontrol"
remove_file_if_exists "/usr/local/bin/apply_nftables_xray.sh"
remove_dir_if_exists "/etc/ray-aio"
remove_dir_if_exists "/var/backups/ray-aio"
remove_dir_if_exists "/etc/xray"
remove_dir_if_exists "/var/log/xray"
remove_dir_if_exists "/etc/hysteria"
remove_dir_if_exists "/root/.secrets"

step "Phase 2: Removing Dependencies (User-Guided)"
echo "The original script installed the following packages:"
CORE_DEPS="curl wget unzip jq nftables certbot qrencode python3-certbot-dns-cloudflare uuid-runtime openssl socat gawk dnsutils uuid uuid-dev uuidcdef ssl-cert conntrack bc coreutils watch"
echo -e "${YELLOW}$CORE_DEPS${NC}"
echo ""
echo "These packages may be used by other applications on your system."
echo -e "${RED}Removing them is not recommended unless you are certain they are no longer needed.${NC}"
echo ""
read -rp "Do you want to proceed with removing these packages? [y/N]: " REMOVE_DEPS
if [[ "${REMOVE_DEPS,,}" == "y" ]]; then
    echo "To remove the packages, please copy and run the following command:"
    echo -e "\n  ${GREEN}apt-get remove --purge $CORE_DEPS${NC}\n"
    echo "This script will not run the command for you, to ensure you are in control."
else
    echo "Skipping removal of core dependencies. You can clean them up later with 'apt autoremove'."
fi


step "Handling XanMod Kernel (Optional)"
if [ -f "/etc/apt/sources.list.d/xanmod-kernel.list" ]; then
    read -rp "XanMod kernel repository found. Do you want to remove it and any installed XanMod kernels? [y/N]: " REMOVE_XANMOD
    if [[ "${REMOVE_XANMOD,,}" == "y" ]]; then
        echo "Removing XanMod kernel packages and repository files..."
        apt-get remove --purge -y "linux-xanmod-*"
        remove_file_if_exists "/etc/apt/sources.list.d/xanmod-kernel.list"
        remove_file_if_exists "/etc/apt/trusted.gpg.d/xanmod-kernel.gpg"
        echo "Updating package lists..."
        apt-get update
        echo -e "${YELLOW}A reboot is required to switch to the previous kernel.${NC}"
    else
        echo "Skipping XanMod kernel removal."
    fi
else
    echo "XanMod repository not found, skipping kernel removal step."
fi

step "Uninstallation Complete"
echo -e "${GREEN}All files and configurations specific to the ray.sh script have been removed.${NC}"
if [[ "${REMOVE_XANMOD:-n}" == "y" ]]; then
    echo -e "${YELLOW}Please reboot your system to complete the kernel removal process.${NC}"
fi