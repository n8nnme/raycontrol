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
remove_dir_if_exists() { remove_file_if_exists "$1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must be run as root.${NC}" >&2
    exit 1
fi

step "Ray.sh Smart Uninstaller"
cat <<-EOF
This script will:
  1) Disable & stop ray.sh services and PostgreSQL
  2) Flush firewall rules
  3) Drop the PostgreSQL database and user
  4) Remove certificates & configuration files
  5) (Optionally) Remove dependencies and the XanMod kernel
EOF

read -rp "Proceed with uninstallation? [y/N]: " CONFIRM
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

step "Phase 1: Shutting Down and Cleaning Up Services"

step "Stopping & Disabling Services"
for svc in xray hysteria-server postgresql; do
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
    echo "nft command not found; skipping."
fi

step "Dropping PostgreSQL Database and User"
DB_CONF="/root/.secrets/db.conf"
if [[ -f "$DB_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$DB_CONF"
    if [[ -n "${PG_DB_NAME:-}" && -n "${PG_USER:-}" ]]; then
       echo "Dropping database '$PG_DB_NAME' and user '$PG_USER'..."
       sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$PG_DB_NAME\";"
       sudo -u postgres psql -c "DROP USER IF EXISTS \"$PG_USER\";"
       echo "PostgreSQL cleanup complete."
    else
        echo "PostgreSQL config found, but DB name/user variables not set."
    fi
else
    echo "PostgreSQL config not found; skipping database drop."
fi


step "Phase 2: Removing Files and Configurations"

step "Removing Systemd Unit Files"
remove_file_if_exists "/etc/systemd/system/xray.service"
remove_file_if_exists "/etc/systemd/system/hysteria-server.service"
systemctl daemon-reload

step "Removing Let's Encrypt Certificate"
if [[ -n "${DOMAIN}" ]] && command -v certbot &>/dev/null; then
    if certbot certificates --cert-name "$DOMAIN" &>/dev/null; then
        certbot delete --non-interactive --cert-name "$DOMAIN"
        echo "Deleted certificate for $DOMAIN."
    else
        echo "No certificate found for '$DOMAIN'."
    fi
else
    echo "Domain variable not set or certbot not found; skipping certificate removal."
fi
remove_file_if_exists "/etc/letsencrypt/renewal-hooks/post/reload_services.sh"

step "Removing Binaries, Configs, and Logs"
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
remove_file_if_exists "/var/log/raycontrol.log"


step "Phase 3: Removing Packages"
CORE_DEPS=(
  curl wget unzip jq nftables certbot qrencode
  python3-certbot-dns-cloudflare uuid-runtime openssl
  socat gawk dnsutils ssl-cert conntrack bc watch
  postgresql postgresql-client postgresql-contrib
)
echo "The following packages were installed as dependencies:"
echo -e "${YELLOW}${CORE_DEPS[*]}${NC}"
echo "Removing these may affect other applications on the system."
read -rp "Do you want to remove these packages? [y/N]: " RM_DEPS
if [[ "${RM_DEPS,,}" == "y" ]]; then
    apt-get remove --purge -y "${CORE_DEPS[@]}"
    echo -e "${GREEN}Dependencies removed.${NC}"
else
    echo "Skipped dependency removal."
fi

step "Optional: XanMod Kernel"
if [[ -f "/etc/apt/sources.list.d/xanmod-kernel.list" ]]; then
    read -rp "Do you want to remove the XanMod repository and any installed XanMod kernels? [y/N]: " RX
    if [[ "${RX,,}" == "y" ]]; then
        apt-get remove --purge -y "linux-xanmod-*"
        remove_file_if_exists "/etc/apt/sources.list.d/xanmod-kernel.list"
        remove_file_if_exists "/etc/apt/trusted.gpg.d/xanmod-kernel.gpg"
        apt-get update
        echo -e "${YELLOW}A reboot is required to switch to the previous kernel.${NC}"
    else
        echo "Skipped XanMod removal."
    fi
else
    echo "XanMod repository not found; skipping."
fi

step "Uninstallation Complete"
echo -e "${GREEN}All known ray.sh script artifacts have been removed.${NC}"
echo "Please reboot the system if you removed a kernel."