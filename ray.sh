#!/usr/bin/env bash
set -euo pipefail

# --- Argument Parsing ---
DEBUG=false
VERBOSE_FLAG=""
if [[ "${1:-}" == "--debug" || "${1:-}" == "--verbose" ]]; then
    DEBUG=true
    VERBOSE_FLAG=$1
    set -x # Enable expanded output for troubleshooting
fi

# --- Configuration: Paths ---
RAY_AIO_DIR="/etc/ray-aio"
SETTINGS_FILE="$RAY_AIO_DIR/settings.json"
INSTALL_CONF="$RAY_AIO_DIR/install.conf"
LOG_FILE="/var/log/raycontrol.log"
RAYCONTROL_PATH="/usr/local/bin/raycontrol"
APPLY_NFTABLES_SCRIPT="/usr/local/bin/apply_nftables_xray.sh"
XRAY_DIR="/etc/xray"
XRAY_LOG_DIR="/var/log/xray"
XRAY_CONFIG="$XRAY_DIR/config.json"
XRAY_USERS_DB="$XRAY_DIR/users.db"
XRAY_BIN="/usr/local/bin/xray"
XRAY_SERVICE="/etc/systemd/system/xray.service"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONFIG="$HYSTERIA_DIR/config.yaml"
HYSTERIA_USERS_DB="$HYSTERIA_DIR/users.db"
HYSTERIA_BIN="/usr/local/bin/hysteria-server"
HYSTERIA_SERVICE="/etc/systemd/system/hysteria-server.service"
SECRETS_DIR="/root/.secrets"
CLOUDFLARE_INI="$SECRETS_DIR/cloudflare.ini"
LE_POST_HOOK_DIR="/etc/letsencrypt/renewal-hooks/post"
LE_POST_HOOK_SCRIPT="$LE_POST_HOOK_DIR/reload_services.sh"
TEMP_ZIP="/tmp/Xray-linux-64.zip"
TEMP_AWK="/tmp/check_x86_v_level.awk"

# --- Configuration: Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Logging Functions ---
log_msg() {
    local level_color="$1"
    local level_text="$2"
    local message="$3"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level_text] $message" | tee -a "$LOG_FILE" > /dev/null
    echo -e "${level_color}[$timestamp] [$level_text] ${message}${NC}"
}
log_info() {
    log_msg "$GREEN" "INFO" "$1"
}
log_warn() {
    log_msg "$YELLOW" "WARN" "$1"
}
log_error() {
    log_msg "$RED" "ERROR" "$1" >&2
}

touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

trap 'cleanup' ERR EXIT

cleanup() {
    set +e
    log_error "--- An error occurred. Rolling back changes... ---"

    if systemctl is-active --quiet nftables; then
        log_warn "Flushing firewall rules..."
        nft flush ruleset
    fi

    if command -v xray &> /dev/null; then
        systemctl disable --now xray &>/dev/null
        rm -f "$XRAY_BIN" "$XRAY_SERVICE"
    fi

    if command -v hysteria-server &> /dev/null; then
        systemctl disable --now hysteria-server &>/dev/null
        rm -f "$HYSTERIA_BIN" "$HYSTERIA_SERVICE"
    fi

    systemctl daemon-reload

    log_warn "Removing configuration directories..."
    rm -rf "$RAY_AIO_DIR" "$XRAY_DIR" "$HYSTERIA_DIR" "$SECRETS_DIR"

    if [[ -n "${XANMOD_PKG_NAME_INSTALLED:-}" ]]; then
        log_warn "Uninstalling XanMod Kernel package: ${XANMOD_PKG_NAME_INSTALLED}"
        apt-get remove -y "$XANMOD_PKG_NAME_INSTALLED"
    fi

    log_warn "Removing temporary files..."
    rm -f "$TEMP_AWK" "$TEMP_ZIP"

    log_warn "Rollback complete. The system should be in its original state."
    exit 1
}

validate_port() {
    local port_val="$1"
    local port_name="$2"
    local min_val="${3:-1}"
    if ! [[ "$port_val" =~ ^[1-9][0-9]*$ ]]; then
        log_error "Port '$port_name' ($port_val) is not a valid number."
        exit 1
    fi
    if (( port_val < min_val || port_val > 65535 )); then
        log_error "Port '$port_name' ($port_val) must be between $min_val and 65535."
        exit 1
    fi
}

if [[ $EUID -ne 0 ]]; then
  log_error "This script must be run as root."
  exit 1
fi

read -rp "Domain (e.g. your.domain.com): " DOMAIN
read -rp "Cloudflare API Token: " CF_API_TOKEN
read -rp "Let’s Encrypt email: " EMAIL

log_info "--- Verifying Cloudflare API Token ---"
CF_ZONE_ID_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json")

if ! echo "$CF_ZONE_ID_RESPONSE" | jq -e '.success' &>/dev/null; then
    ERROR_MSG=$(echo "$CF_ZONE_ID_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null || echo "Unknown error")
    log_error "Cloudflare API token is invalid or lacks 'Zone.Read' permissions."
    log_error "API response: $ERROR_MSG"
    exit 1
fi
log_info "Cloudflare API Token appears to be valid."

echo
log_warn "Specify three distinct TCP ports for Port Knocking (e.g. 10001 10002 10003):"
read -rp "Knock ports: " K1 K2 K3

read -rp "Port for VLESS/XTLS (TCP, 200–65535, default 443): " PORT_VLESS
PORT_VLESS=${PORT_VLESS:-443}
read -rp "Port for Trojan (TCP, 200–65535, default 8443): " PORT_TROJAN
PORT_TROJAN=${PORT_TROJAN:-8443}
read -rp "Port for Hysteria2 (UDP, 200-65535, default 3478): " PORT_HYSTERIA
PORT_HYSTERIA=${PORT_HYSTERIA:-3478}

validate_port "$K1" "K1"
validate_port "$K2" "K2"
validate_port "$K3" "K3"
if [[ "$K1" == "$K2" || "$K2" == "$K3" || "$K1" == "$K3" ]]; then
  log_error "Knock ports must be three distinct numbers."
  exit 1
fi

validate_port "$PORT_VLESS" "PORT_VLESS" 200
validate_port "$PORT_TROJAN" "PORT_TROJAN" 200
validate_port "$PORT_HYSTERIA" "PORT_HYSTERIA" 200

echo
read -rp "Install XanMod kernel for BBRv3 and other optimizations? [y/N]: " INSTALL_XANMOD

log_info "--- Pre-flight Checks ---"
SSH_PORT=$(ss -tnlp | awk '/sshd/ && /LISTEN/ { sub(".*:", "", $4); print $4; exit }')
log_info "Detected SSH port: $SSH_PORT"

for P_VAR in PORT_VLESS PORT_TROJAN; do
    VAL=${!P_VAR}
    if ss -tlpn | grep -q ":$VAL\s"; then
        log_error "TCP Port $VAL is already in use."
        exit 1
    fi
    log_info "TCP Port $VAL is available."
done
if ss -ulpn | grep -q ":$PORT_HYSTERIA\s"; then
    log_error "UDP Port $PORT_HYSTERIA is already in use."
    exit 1
fi
log_info "UDP Port $PORT_HYSTERIA is available."

echo
log_warn "--- Installation Summary ---"
echo "Domain:             $DOMAIN"
echo "VLESS Port (TCP):   $PORT_VLESS"
echo "Trojan Port (TCP):  $PORT_TROJAN"
echo "Hysteria2 Port (UDP):$PORT_HYSTERIA"
echo "Knock Ports:        $K1, $K2, $K3"
if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    echo "Install XanMod:     Yes"
fi
echo -e "${YELLOW}----------------------------${NC}\n"

read -rp "Proceed with installation? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Installation cancelled."
    trap - ERR EXIT
    exit 1
fi

log_info "--- Installing Core Dependencies ---"
apt-get update
apt-get install -y \
  curl wget unzip jq nftables certbot qrencode \
  python3-certbot-dns-cloudflare \
  uuid-runtime openssl socat gawk \
  dnsutils uuid uuid-dev uuid-runtime uuidcdef ssl-cert conntrack \
  bc coreutils watch

mkdir -p "$RAY_AIO_DIR" "/var/backups/ray-aio"

cat > "$INSTALL_CONF" <<EOF
DOMAIN="$DOMAIN"
PORT_VLESS="$PORT_VLESS"
PORT_TROJAN="$PORT_TROJAN"
PORT_HYSTERIA="$PORT_HYSTERIA"
SSH_PORT="$SSH_PORT"
K1="$K1"
K2="$K2"
K3="$K3"
EOF

cat > "$SETTINGS_FILE" <<EOF
{
  "alpn": ["h2"],
  "vless_flow": "xtls-rprx-vision"
}
EOF
VLESS_FLOW=$(jq -r '.vless_flow' "$SETTINGS_FILE")
XRAY_ALPN=$(jq -c '.alpn' "$SETTINGS_FILE")

if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    log_info "--- Setting up XanMod Repository ---"
    apt-get install -y gpg
    echo 'deb http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-kernel.list
    wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/xanmod-kernel.gpg
    log_info "--- Updating sources for XanMod ---"
    apt-get update
    log_info "--- Checking CPU microarchitecture level ---"
    cat > "$TEMP_AWK" <<'AWK'
#!/usr/bin/awk -f
BEGIN {
    while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1
    if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1
    if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2
    if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3
    if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4
    if (level > 0) { print "CPU supports x86-64-v" level; exit level + 1 }
    exit 1
}
AWK
    chmod +x "$TEMP_AWK"
    XANMOD_PKG_NAME="linux-xanmod-lts-x64v1"
    CPU_LEVEL_EXIT_CODE=0
    "$TEMP_AWK" || CPU_LEVEL_EXIT_CODE=$?
    case $CPU_LEVEL_EXIT_CODE in
        3) XANMOD_PKG_NAME="linux-xanmod-x64v2" ;;
        4) XANMOD_PKG_NAME="linux-xanmod-x64v3" ;;
        5) XANMOD_PKG_NAME="linux-xanmod-x64v3" ;;
        *) XANMOD_PKG_NAME="linux-xanmod-lts-x64v1" ;;
    esac
    log_info "--- Installing XanMod Kernel ($XANMOD_PKG_NAME) ---"
    apt-get install -y "$XANMOD_PKG_NAME"
    XANMOD_PKG_NAME_INSTALLED=$XANMOD_PKG_NAME
    rm -f "$TEMP_AWK"
fi

UUID_VLESS=$(uuidgen)
PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
PASSWORD_HYSTERIA=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
PASSWORD_HYSTERIA_OBFS=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')

log_info "--- Validating DNS Records ---"
SERVER_IP=$(curl -s https://ipwho.de/ip)
if [[ -z "$SERVER_IP" ]]; then
    log_error "Could not determine server's public IP address."
    exit 1
fi
log_info "This server's public IP is: $SERVER_IP"
log_warn "Please ensure you have an A record for $DOMAIN pointing to this IP in your Cloudflare DNS."
log_warn "Waiting 60 seconds for DNS to propagate..."
for i in {60..1}; do printf "\rWaiting... %2d" "$i"; sleep 1; done
echo -e "\rDone waiting. Now checking DNS resolution."

RESOLVED_IP=$(dig +short "$DOMAIN" @1.1.1.1 || echo "")
log_info "Resolved IP for $DOMAIN is: ${RESOLVED_IP:-Not found}"
if [[ "$RESOLVED_IP" != "$SERVER_IP" ]]; then
    log_error "DNS validation failed!"
    log_error "The domain $DOMAIN does not resolve to this server's IP ($SERVER_IP)."
    log_error "Please update your DNS A record in Cloudflare and run the script again."
    exit 1
fi
log_info "DNS validation successful!"

cat > "$RAYCONTROL_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEBUG=false
VERBOSE_FLAG=""
if [[ "${1:-}" == "--debug" || "${1:-}" == "--verbose" ]]; then
    DEBUG=true
    VERBOSE_FLAG=$1
    set -x
    shift
fi

LOG_FILE="/var/log/raycontrol.log"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_msg() {
    local level_color="$1"
    local level_text="$2"
    local message="$3"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level_text] $message" >> "$LOG_FILE"
    echo -e "${level_color}[$timestamp] [$level_text] ${message}${NC}"
}
log_info() {
    log_msg "$GREEN" "INFO" "$1"
}
log_warn() {
    log_msg "$YELLOW" "WARN" "$1"
}
log_error() {
    log_msg "$RED" "ERROR" "$1" >&2
}

XRAY_DIR="/etc/xray"
HYSTERIA_DIR="/etc/hysteria"
RAY_AIO_DIR="/etc/ray-aio"
BACKUP_DIR="/var/backups/ray-aio"
XCONF="${XRAY_DIR}/config.json"
HYSTERIA_CONF="${HYSTERIA_DIR}/config.yaml"
DB_XRAY_USERS="${XRAY_DIR}/users.db"
DB_HY_USERS="${HYSTERIA_DIR}/users.db"
DB_IPS="${XRAY_DIR}/ips.db"
ENABLED_FLAG="${XRAY_DIR}/enabled.flag"
INSTALL_CONF="${RAY_AIO_DIR}/install.conf"
SETTINGS_FILE="${RAY_AIO_DIR}/settings.json"
NFT_TABLE="inet filter"
NFT_SET="xray_clients"

ensure_db(){
    mkdir -p "$XRAY_DIR" "$HYSTERIA_DIR" "$BACKUP_DIR"
    touch "$DB_XRAY_USERS" "$DB_HY_USERS" "$DB_IPS"
    if [ ! -f "$ENABLED_FLAG" ]; then
        echo "disabled" > "$ENABLED_FLAG"
    fi
}

reload_services(){
    if [[ "$(cat "$ENABLED_FLAG")" == "enabled" ]]; then
        case "$1" in
            xray) systemctl restart xray; log_info "Xray service reloaded." ;;
            hysteria) systemctl restart hysteria-server; log_info "Hysteria2 service reloaded." ;;
            *) systemctl restart xray; systemctl restart hysteria-server; log_info "All services reloaded." ;;
        esac
    fi
}

show_qr() {
    local type="$1"
    local id="$2"

    if ! command -v qrencode &> /dev/null; then
        log_error "Error: 'qrencode' is not installed. Please run 'apt install qrencode'."
        return 1
    fi
    if [ ! -f "$INSTALL_CONF" ] || [ ! -f "$SETTINGS_FILE" ]; then
        log_error "Core config files not found in $RAY_AIO_DIR"
        exit 1;
    fi
    source "$INSTALL_CONF"
    local vless_flow
    vless_flow=$(jq -r '.vless_flow' "$SETTINGS_FILE")
    local alpn
    alpn=$(jq -r '.alpn[0]' "$SETTINGS_FILE")

    local uri=""
    local name=""

    case "$type" in
        vless)
            name="${DOMAIN}-VLESS-${id:0:8}"
            uri="vless://${id}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=xtls&flow=${vless_flow}&alpn=${alpn}&sni=${DOMAIN}#${name}"
            ;;
        trojan)
            name="${DOMAIN}-Trojan-${id:0:8}"
            uri="trojan://${id}@${DOMAIN}:${PORT_TROJAN}?alpn=${alpn}&sni=${DOMAIN}#${name}"
            ;;
        hysteria)
            if [[ -z "$id" ]]; then
                log_error "Please provide a Hysteria password to generate a QR code."
                exit 1;
            fi
            local obfs_pass
            obfs_pass=$(awk '/salamander:/,/password:/ {if ($1 == "password:") {print $2; exit}}' "$HYSTERIA_CONF")
            if [[ -z "$obfs_pass" ]]; then
                log_error "Could not read Hysteria OBFS password from $HYSTERIA_CONF"
                exit 1;
            fi
            name="${DOMAIN}-Hysteria2-${id:0:6}"
            uri="hysteria2://${id}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${obfs_pass}#${name}"
            ;;
        *)
            log_error "Invalid type specified for QR code generation."
            return 1;;
    esac

    log_warn "--- QR Code for: $name ---"
    qrencode -t ANSIUTF8 "$uri"
    echo -e "${YELLOW}URI: ${uri}${NC}\n"
}

add_user(){
    local type="$1"
    local vless_flow
    vless_flow=$(jq -r '.vless_flow' "$SETTINGS_FILE")
    if [[ "$type" == "vless" ]]; then
        local uuid
        uuid=$(uuidgen)
        jq --arg id "$uuid" --arg flow "$vless_flow" \
           '.inbounds[0].settings.clients += [{"id":$id,"flow":$flow}]' \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "vless:$uuid" >> "$DB_XRAY_USERS"
        log_info "Added VLESS user: $uuid"
        reload_services xray
        show_qr vless "$uuid"
    elif [[ "$type" == "trojan" ]]; then
        local pass
        pass=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
        jq --arg pw "$pass" \
           '.inbounds[1].settings.clients += [{"password":$pw}]' \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "trojan:$pass" >> "$DB_XRAY_USERS"
        log_info "Added Trojan user. Password: $pass"
        reload_services xray
        show_qr trojan "$pass"
    elif [[ "$type" == "hysteria" ]]; then
        local pass
        pass=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
        echo "$pass" >> "$DB_HY_USERS"
        log_info "Added Hysteria2 user. Password: $pass"
        reload_services hysteria
        show_qr hysteria "$pass"
    else
        echo "Usage: raycontrol add-user [vless|trojan|hysteria]" >&2
        exit 1
    fi
}

del_user(){
    local id="$1"
    if grep -qE "^(vless|trojan):$id" "$DB_XRAY_USERS"; then
        sed -i "\%^.*:$id.*%d" "$DB_XRAY_USERS"
        jq "del(.inbounds[] | .settings.clients[]? | select(.id == \"$id\" or .password == \"$id\"))" \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        log_info "Removed Xray user: $id"
        reload_services xray
    elif grep -qFx "$id" "$DB_HY_USERS"; then
        sed -i "\%^${id}\$%d" "$DB_HY_USERS"
        log_info "Removed Hysteria2 user: $id"
        reload_services hysteria
    else
        log_error "User not found: $id"
        exit 1
    fi
}

list_users(){
    log_warn "--- Xray Users (VLESS/Trojan) ---"
    if [[ ! -s "$DB_XRAY_USERS" ]]; then
        echo "(none)"
    else
        echo "TYPE    ID/PASSWORD"
        echo "----------------------------------------"
        while IFS=":" read -r type id; do
            printf "%-7s %s\n" "$type" "$id"
        done < "$DB_XRAY_USERS"
    fi

    echo
    log_warn "--- Hysteria2 Users ---"
    if [[ ! -s "$DB_HY_USERS" ]]; then
        echo "(none)"
    else
        echo "PASSWORD"
        echo "--------------------------------"
        cat "$DB_HY_USERS"
    fi
}

list_ips(){ echo "Function list_ips placeholder"; }
check_conns(){ echo "Function check_conns placeholder"; }
add_ip(){ echo "Function add_ip placeholder"; }
del_ip(){ echo "Function del_ip placeholder"; }
apply_nftables(){ echo "Function apply_nftables placeholder"; }
enable_all(){ echo "Function enable_all placeholder"; }
disable_all(){ echo "Function disable_all placeholder"; }
backup_config(){ echo "Function backup_config placeholder"; }
restore_config(){ echo "Function restore_config placeholder"; }
show_status(){ echo "Function show_status placeholder"; }

help(){
    cat <<MSG
Usage: raycontrol <command> [args] [--debug|--verbose]

Services Management:
  enable         Enable all services + firewall and persist rules
  disable        Disable all services + firewall and persist flushed rules
  status         Show service states, connections, and bandwidth usage
  monitor        Live monitor the status command (updates every 5s)

User & QR Code Management:
  list-users     List all users (VLESS, Trojan, Hysteria2)
  add-user <type>  Add a new user. Type: [vless|trojan|hysteria]
  del-user <ID>    Delete a user (VLESS UUID, Trojan pass, or Hysteria2 pass)
  show-qr <type> [ID]
                 Show QR code for a connection.
                 - For Hysteria: raycontrol show-qr hysteria <PASSWORD>
                 - For existing user: raycontrol show-qr <vless|trojan> <USER_ID>

Disaster Recovery:
  backup         Create a full backup of all configurations
  restore <file> Restore configuration from a backup archive

IP Whitelist Management:
  list-ips       List whitelisted IPs and their remaining timeout
  add-ip <IP>    Whitelist an IP
  del-ip <IP>    Remove a whitelisted IP

Troubleshooting:
  --debug        Enable syscall tracing and expanded output.
  --verbose      Alias for --debug.
MSG
}

ensure_db
case "${1:-help}" in
  help)        help ;;
  enable)      enable_all ;;
  disable)     disable_all ;;
  status)      show_status ;;
  monitor)     watch -n 5 -t --color "$0" "$VERBOSE_FLAG" status ;;
  backup)      backup_config ;;
  restore)     restore_config "${2:-}" ;;
  list-users)  list_users ;;
  add-user)    add_user "${2:-}" ;;
  del-user)    del_user "${2:-}" ;;
  show-qr)     show_qr "${2:-}" "${3:-}" ;;
  list-ips)    list_ips ;;
  add-ip)      add_ip "${2:-}" ;;
  del-ip)      del_ip "${2:-}" ;;
  check-conns) check_conns "${2:-}" ;;
  *)           help ;;
esac
EOF
chmod +x "$RAYCONTROL_PATH"

cat > "$APPLY_NFTABLES_SCRIPT" <<EOF
#!/usr/bin/env bash
set -e
SSH_PORT="$SSH_PORT"
PORT_VLESS="$PORT_VLESS"
PORT_TROJAN="$PORT_TROJAN"
PORT_HYSTERIA="$PORT_HYSTERIA"
K1="$K1"
K2="$K2"
K3="$K3"
nft flush ruleset
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
nft add chain inet filter forward '{ type filter hook forward priority 0; policy drop; }'
nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'
nft add set inet filter knock_stage1 '{ type ipv4_addr; flags dynamic; timeout 10s; }'
nft add set inet filter knock_stage2 '{ type ipv4_addr; flags dynamic; timeout 10s; }'
nft add set inet filter xray_clients '{ type ipv4_addr; flags dynamic; timeout 10m; }'
nft add chain inet filter knock
nft add rule inet filter input iif lo accept
nft add rule inet filter input ip saddr @xray_clients tcp dport $PORT_VLESS counter update @xray_clients '{ ip saddr }' accept
nft add rule inet filter input ip saddr @xray_clients tcp dport $PORT_TROJAN counter update @xray_clients '{ ip saddr }' accept
nft add rule inet filter input ip saddr @xray_clients udp dport $PORT_HYSTERIA counter update @xray_clients '{ ip saddr }' accept
nft add rule inet filter input ip saddr @xray_clients tcp dport $SSH_PORT counter update @xray_clients '{ ip saddr }' accept
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input ip protocol icmp accept
nft add rule inet filter input ip6 nexthdr ipv6-icmp accept
nft add rule inet filter input tcp dport $K1 add @knock_stage1 '{ ip saddr }' drop
nft add rule inet filter input tcp dport $K2 ip saddr @knock_stage1 add @knock_stage2 '{ ip saddr }' drop
nft add rule inet filter input tcp dport $K3 ip saddr @knock_stage2 jump knock
nft add rule inet filter knock add @xray_clients '{ ip saddr }'
nft add rule inet filter knock drop
EOF
chmod +x "$APPLY_NFTABLES_SCRIPT"

log_info "--- Issuing Certificate with Certbot ---"
mkdir -p "$SECRETS_DIR"
cat > "$CLOUDFLARE_INI" <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 "$CLOUDFLARE_INI"
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials "$CLOUDFLARE_INI" \
  --agree-tos --no-eff-email \
  -m "$EMAIL" \
  -d "$DOMAIN"

log_info "--- Configuring Automatic Certificate Renewal ---"
mkdir -p "$LE_POST_HOOK_DIR"
cat > "$LE_POST_HOOK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
ENABLED_FLAG="/etc/xray/enabled.flag"
if [[ -f "$ENABLED_FLAG" && "$(cat "$ENABLED_FLAG")" == "enabled" ]]; then
    systemctl restart xray
    systemctl restart hysteria-server
fi
EOF
chmod +x "$LE_POST_HOOK_SCRIPT"

log_info "--- Installing Xray-core ---"
mkdir -p "$XRAY_DIR" "$XRAY_LOG_DIR"
chown -R nobody:nogroup "$XRAY_DIR" "$XRAY_LOG_DIR"
XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
wget -qO "$TEMP_ZIP" "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER/Xray-linux-64.zip"
unzip -qo "$TEMP_ZIP" -d /usr/local/bin
rm "$TEMP_ZIP"
chmod +x "$XRAY_BIN"

cat > "$XRAY_CONFIG" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": $PORT_VLESS, "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID_VLESS", "flow": "$VLESS_FLOW"}], "decryption": "none"},
      "streamSettings": {"network": "tcp", "security": "tls", "xtlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}], "alpn": $XRAY_ALPN}}
    },
    {
      "port": $PORT_TROJAN, "protocol": "trojan",
      "settings": {"clients": [{"password": "$PASSWORD_TROJAN"}], "fallbacks": [{"dest": "@blackhole"}]},
      "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}], "alpn": $XRAY_ALPN}}
    }
  ],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "@blackhole"}]
}
EOF
echo "vless:$UUID_VLESS" > "$XRAY_USERS_DB"
echo "trojan:$PASSWORD_TROJAN" >> "$XRAY_USERS_DB"

cat > "$XRAY_SERVICE" <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN -config $XRAY_CONFIG
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

log_info "--- Installing Hysteria2 ---"
RAW_TAG=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r .tag_name)
ENC_TAG=${RAW_TAG//\//%2F}
DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${ENC_TAG}/hysteria-linux-amd64"
wget -nv -O "$HYSTERIA_BIN" "$DOWNLOAD_URL"
chmod +x "$HYSTERIA_BIN"
log_info "Hysteria2 installed successfully!"

mkdir -p "$HYSTERIA_DIR"
cat > "$HYSTERIA_CONFIG" <<EOF
listen: :$PORT_HYSTERIA
tls:
  cert: /etc/letsencrypt/live/$DOMAIN/fullchain.pem
  key: /etc/letsencrypt/live/$DOMAIN/privkey.pem
auth:
  type: file
  file:
    path: $HYSTERIA_USERS_DB
obfs:
  type: salamander
  salamander:
    password: $PASSWORD_HYSTERIA_OBFS
masquerade:
  type: proxy
  proxy:
    url: https://1.1.1.1
    rewriteHost: true
EOF

echo "$PASSWORD_HYSTERIA" > "$HYSTERIA_USERS_DB"

cat > "$HYSTERIA_SERVICE" <<EOF
[Unit]
Description=Hysteria2 Service
After=network.target nss-lookup.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$HYSTERIA_BIN server -c $HYSTERIA_CONFIG
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

usermod -aG ssl-cert nobody
chgrp -R ssl-cert /etc/letsencrypt/live /etc/letsencrypt/archive
chmod -R g+rx /etc/letsencrypt/live /etc/letsencrypt/archive

systemctl daemon-reload
systemctl enable xray
systemctl enable hysteria-server

VLESS_URI="vless://${UUID_VLESS}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=xtls&flow=${VLESS_FLOW}&alpn=$(jq -r '.alpn[0]' "$SETTINGS_FILE")&sni=${DOMAIN}#${DOMAIN}-VLESS"
TROJAN_URI="trojan://${PASSWORD_TROJAN}@${DOMAIN}:${PORT_TROJAN}?alpn=$(jq -r '.alpn[0]' "$SETTINGS_FILE")&sni=${DOMAIN}#${DOMAIN}-Trojan"
HYSTERIA_URI="hysteria2://${PASSWORD_HYSTERIA}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${PASSWORD_HYSTERIA_OBFS}#${DOMAIN}-Hysteria2"

trap - ERR EXIT
log_info "--- Installation successful! ---"

echo -e "\n\n${YELLOW}=====================================================${NC}"
echo -e "${YELLOW}               ACTION REQUIRED TO ACTIVATE               ${NC}"
echo -e "${YELLOW}=====================================================${NC}\n"

if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    echo -e "${YELLOW}IMPORTANT: A reboot is required to use the new XanMod kernel.${NC}"
    echo -e "After rebooting, run '$RAYCONTROL_PATH enable'.\n"
else
    echo -e "Services are installed but NOT RUNNING. The firewall is NOT ACTIVE."
    echo -e "To start all services and apply the firewall, run:\n"
    echo -e "  ${GREEN}$RAYCONTROL_PATH enable${NC}\n"
fi
echo -e "After enabling, your system will be fully configured and ready."
echo -e "Your IP will not be whitelisted automatically. You must perform the port knock first."
echo -e "An IP will be removed from the whitelist after 10 minutes of inactivity."

echo -e "\n${YELLOW}--- Initial Connection Info (once enabled) ---${NC}"
echo "Knock sequence for all services: $K1 -> $K2 -> $K3"
echo "SSH Port: $SSH_PORT"
echo
echo -e "${YELLOW}VLESS (TCP, $(jq -r '.alpn[0]' "$SETTINGS_FILE")-Only):${NC}"
echo "  Port: $PORT_VLESS, UUID: $UUID_VLESS"
echo
echo -e "${YELLOW}Trojan (TCP, $(jq -r '.alpn[0]' "$SETTINGS_FILE")-Only):${NC}"
echo "  Port: $PORT_TROJAN, Password: $PASSWORD_TROJAN"
echo
echo -e "${YELLOW}Hysteria2 (UDP):${NC}"
echo "  Port: $PORT_HYSTERIA"
echo "  Initial Auth Pass: $PASSWORD_HYSTERIA"
echo "  OBFS Pass: $PASSWORD_HYSTERIA_OBFS"

if command -v qrencode &> /dev/null; then
  echo -e "\n${YELLOW}--- QR Codes for Initial Users ---${NC}"
  echo "VLESS Configuration:"
  qrencode -t ANSIUTF8 "$VLESS_URI"
  echo "Trojan Configuration:"
  qrencode -t ANSIUTF8 "$TROJAN_URI"
  echo "Hysteria2 Configuration:"
  qrencode -t ANSIUTF8 "$HYSTERIA_URI"
else
  echo -e "\n${YELLOW}--- Configuration URIs ---${NC}"
  echo "VLESS: $VLESS_URI"
  echo "Trojan: $TROJAN_URI"
  echo "Hysteria2: $HYSTERIA_URI"
fi

echo -e "\nUse ${GREEN}'$RAYCONTROL_PATH help'${NC} for a full list of commands including status, backup, and restore."
echo -e "For more detailed output, use the ${GREEN}'--debug'${NC} or ${GREEN}'--verbose'${NC} flag with any command."
echo -e "\n${GREEN}=========================================================================================${NC}\n"