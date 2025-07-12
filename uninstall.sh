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
    if [[ -e "$file_path" ]]; then
        rm -rf "$file_path"
        echo "Removed: $file_path"
    else
        echo "Not found (OK): $file_path"
    fi
}

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must be run as root.${NC}" >&2
    exit 1
fi

step "Ray.sh Smart Uninstaller"
cat <<-EOF
This script will:
  1) Disable & stop ray.sh services
  2) Flush firewall rules
  3) Remove certificates & configs
  4) (Optionally) Remove dependencies
EOF

read -rp "Proceed? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Cancelled."
    exit 1
fi

# Load domain from install.conf if present
DOMAIN=""
INSTALL_CONF="/etc/ray-aio/install.conf"
if [[ -f "$INSTALL_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$INSTALL_CONF"
fi

step "Phase 1: Removing Script-Specific Files"

step "Stopping & Disabling Services"
for svc in xray hysteria-server; do
    if systemctl is-active --quiet "$svc"; then
        echo "Stopping $svc..."
        systemctl stop "$svc"
    fi
    if systemctl is-enabled --quiet "$svc"; then
        echo "Disabling $svc..."
        systemctl disable "$svc"
    fi
done

step "Flushing Firewall Rules"
if command -v nft &>/dev/null; then
    nft flush ruleset
    nft -s list ruleset > /etc/nftables.conf
    echo "Cleared NFTables rules; saved empty config."
else
    echo "nft not found; skipping."
fi

step "Removing Systemd Unit Files"
remove_file_if_exists "/etc/systemd/system/xray.service"
remove_file_if_exists "/etc/systemd/system/hysteria-server.service"
systemctl daemon-reload

step "Removing Let's Encrypt Certificate"
if [[ -n "${DOMAIN}" ]] && command -v certbot &>/dev/null; then
    if certbot certificates --cert-name "$DOMAIN" &>/dev/null; then
        certbot delete --non-interactive --cert-name "$DOMAIN"
        echo "Deleted cert: $DOMAIN"
    else
        echo "No certificate found for $DOMAIN."
    fi
else
    echo "No domain or certbot; skipping."
fi
remove_file_if_exists "/etc/letsencrypt/renewal-hooks/post/reload_services.sh"

step "Removing Binaries & Configs"
remove_file_if_exists "/usr/local/bin/xray"
remove_file_if_exists "/usr/local/bin/hysteria-server"
remove_file_if_exists "/usr/local/bin/raycontrol"
remove_file_if_exists "/usr/local/bin/apply_nftables_xray.sh"
remove_dir_if_exists() { remove_file_if_exists "$1"; }  # rm -rf handles dirs too
remove_dir_if_exists "/etc/ray-aio"
remove_dir_if_exists "/var/backups/ray-aio"
remove_dir_if_exists "/etc/xray"
remove_dir_if_exists "/var/log/xray"
remove_dir_if_exists "/etc/hysteria"
remove_dir_if_exists "/root/.secrets"

step "Phase 2: Removing Dependencies"
CORE_DEPS=(
  curl wget unzip jq nftables certbot qrencode
  python3-certbot-dns-cloudflare uuid-runtime openssl
  socat gawk dnsutils ssl-cert conntrack bc watch
)
echo -e "${YELLOW}${CORE_DEPS[*]}${NC}"
echo "Removing these may affect other apps."
read -rp "Remove them? [y/N]: " RM_DEPS
if [[ "${RM_DEPS,,}" == "y" ]]; then
    echo -e "${GREEN}apt-get remove --purge -y ${CORE_DEPS[*]}${NC}"
else
    echo "Skipped dependency removal."
fi

step "Optional: XanMod Kernel"
if [[ -f "/etc/apt/sources.list.d/xanmod-kernel.list" ]]; then
    read -rp "Remove XanMod repo & kernels? [y/N]: " RX
    if [[ "${RX,,}" == "y" ]]; then
        apt-get remove --purge -y "linux-xanmod-*"
        remove_file_if_exists "/etc/apt/sources.list.d/xanmod-kernel.list"
        remove_file_if_exists "/etc/apt/trusted.gpg.d/xanmod-kernel.gpg"
        apt-get update
        echo -e "${YELLOW}Reboot required to revert kernel.${NC}"
    else
        echo "Skipped XanMod removal."
    fi
else
    echo "No XanMod repo; skipping."
fi

step "Uninstallation Complete"
echo -e "${GREEN}All ray.sh artifacts removed.${NC}"
