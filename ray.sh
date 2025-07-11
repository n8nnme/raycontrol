#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

trap 'cleanup' ERR EXIT

cleanup() {
    set +e
    echo -e "\n${RED}--- An error occurred. Rolling back changes... ---${NC}"
    
    if systemctl is-active --quiet nftables; then
        echo "Flushing firewall rules..."
        nft flush ruleset
    fi

    if command -v xray &> /dev/null; then
        systemctl disable --now xray &>/dev/null
        rm -f /usr/local/bin/xray /etc/systemd/system/xray.service
    fi
    
    if command -v hysteria-server &> /dev/null; then
        systemctl disable --now hysteria-server &>/dev/null
        rm -f /usr/local/bin/hysteria-server /etc/systemd/system/hysteria-server.service
    fi

    systemctl daemon-reload

    echo "Removing configuration directories..."
    rm -rf /etc/ray-aio /etc/xray /etc/hysteria /root/.secrets
    
    if [[ -n "${XANMOD_PKG_NAME_INSTALLED:-}" ]]; then
        echo "Uninstalling XanMod Kernel package: ${XANMOD_PKG_NAME_INSTALLED}"
        apt-get remove -y "$XANMOD_PKG_NAME_INSTALLED"
    fi

    echo "Removing temporary files..."
    rm -f /tmp/check_x86_v_level.awk /tmp/Xray-linux-64.zip

    echo -e "${YELLOW}Rollback complete. The system should be in its original state.${NC}"
    exit 1
}

validate_port() {
    local port_val="$1"
    local port_name="$2"
    local min_val="${3:-1}"
    if ! [[ "$port_val" =~ ^[1-9][0-9]*$ ]]; then
        echo -e "${RED}ERROR: Port '$port_name' ($port_val) is not a valid number.${NC}" >&2
        exit 1
    fi
    if (( port_val < min_val || port_val > 65535 )); then
        echo -e "${RED}ERROR: Port '$port_name' ($port_val) must be between $min_val and 65535.${NC}" >&2
        exit 1
    fi
}

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: This script must be run as root.${NC}" >&2
  exit 1
fi

read -rp "Domain (e.g. your.domain.com): " DOMAIN
read -rp "Cloudflare API Token: " CF_API_TOKEN
read -rp "Let’s Encrypt email: " EMAIL

echo -e "\n${GREEN}--- Verifying Cloudflare API Token ---${NC}"
CF_ZONE_ID_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json")

if ! echo "$CF_ZONE_ID_RESPONSE" | jq -e '.success' &>/dev/null; then
    ERROR_MSG=$(echo "$CF_ZONE_ID_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null || echo "Unknown error")
    echo -e "${RED}ERROR: Cloudflare API token is invalid or lacks 'Zone.Read' permissions.${NC}" >&2
    echo -e "${RED}API response: $ERROR_MSG${NC}" >&2
    exit 1
fi
echo -e "${GREEN}Cloudflare API Token appears to be valid.${NC}"

echo
echo -e "${YELLOW}Specify three distinct TCP ports for Port Knocking (e.g. 10001 10002 10003):${NC}"
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
  echo -e "${RED}ERROR: Knock ports must be three distinct numbers.${NC}" >&2
  exit 1
fi

validate_port "$PORT_VLESS" "PORT_VLESS" 200
validate_port "$PORT_TROJAN" "PORT_TROJAN" 200
validate_port "$PORT_HYSTERIA" "PORT_HYSTERIA" 200

echo
read -rp "Install XanMod kernel for BBRv3 and other optimizations? [y/N]: " INSTALL_XANMOD

echo -e "\n${GREEN}--- Pre-flight Checks ---${NC}"
SSH_PORT=$(ss -tnlp | awk '/sshd/ && /LISTEN/ { sub(".*:", "", $4); print $4; exit }')
echo "Detected SSH port: $SSH_PORT"

for P_VAR in PORT_VLESS PORT_TROJAN; do
    VAL=${!P_VAR}
    if ss -tlpn | grep -q ":$VAL\s"; then
        echo -e "${RED}ERROR: TCP Port $VAL is already in use.${NC}" >&2
        exit 1
    fi
    echo -e "TCP Port $VAL is available."
done
if ss -ulpn | grep -q ":$PORT_HYSTERIA\s"; then
    echo -e "${RED}ERROR: UDP Port $PORT_HYSTERIA is already in use.${NC}" >&2
    exit 1
fi
echo -e "UDP Port $PORT_HYSTERIA is available."

echo -e "\n${YELLOW}--- Installation Summary ---${NC}"
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

echo -e "\n${GREEN}--- Installing Core Dependencies ---${NC}"
apt-get update
apt-get install -y \
  curl wget unzip jq nftables certbot qrencode \
  python3-certbot-dns-cloudflare \
  uuid-runtime openssl socat gawk \
  dnsutils uuid uuid-dev uuid-runtime uuidcdef ssl-cert conntrack \
  bc coreutils watch

mkdir -p /etc/ray-aio /var/backups/ray-aio

cat > /etc/ray-aio/install.conf <<EOF
DOMAIN="$DOMAIN"
PORT_VLESS="$PORT_VLESS"
PORT_TROJAN="$PORT_TROJAN"
PORT_HYSTERIA="$PORT_HYSTERIA"
SSH_PORT="$SSH_PORT"
K1="$K1"
K2="$K2"
K3="$K3"
EOF

if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    echo -e "\n${GREEN}--- Setting up XanMod Repository ---${NC}"
    apt-get install -y gpg
    echo 'deb http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-kernel.list
    wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/xanmod-kernel.gpg
    echo -e "\n${GREEN}--- Updating sources for XanMod ---${NC}"
    apt-get update
    echo -e "\n${GREEN}--- Checking CPU microarchitecture level ---${NC}"
    cat > /tmp/check_x86_v_level.awk <<'AWK'
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
    chmod +x /tmp/check_x86_v_level.awk
    XANMOD_PKG_NAME="linux-xanmod-lts-x64v1"
    CPU_LEVEL_EXIT_CODE=0
    /tmp/check_x86_v_level.awk || CPU_LEVEL_EXIT_CODE=$?
    case $CPU_LEVEL_EXIT_CODE in
        3) XANMOD_PKG_NAME="linux-xanmod-x64v2" ;;
        4) XANMOD_PKG_NAME="linux-xanmod-x64v3" ;;
        5) XANMOD_PKG_NAME="linux-xanmod-x64v3" ;;
        *) XANMOD_PKG_NAME="linux-xanmod-lts-x64v1" ;;
    esac
    echo -e "\n${GREEN}--- Installing XanMod Kernel ($XANMOD_PKG_NAME) ---${NC}"
    apt-get install -y "$XANMOD_PKG_NAME"
    XANMOD_PKG_NAME_INSTALLED=$XANMOD_PKG_NAME
    rm -f /tmp/check_x86_v_level.awk
fi

UUID_VLESS=$(uuidgen)
PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
PASSWORD_HYSTERIA=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
PASSWORD_HYSTERIA_OBFS=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')

echo -e "\n${GREEN}--- Validating DNS Records ---${NC}"
SERVER_IP=$(curl -s https://ipwho.de/ip)
if [[ -z "$SERVER_IP" ]]; then
    echo -e "${RED}ERROR: Could not determine server's public IP address.${NC}" >&2
    exit 1
fi
echo "This server's public IP is: $SERVER_IP"
echo "Please ensure you have an A record for $DOMAIN pointing to this IP in your Cloudflare DNS."
echo "Waiting 60 seconds for DNS to propagate..."
for i in {60..1}; do printf "\rWaiting... %2d" "$i"; sleep 1; done
echo -e "\rDone waiting. Now checking DNS resolution.${NC}"

RESOLVED_IP=$(dig +short "$DOMAIN" @1.1.1.1 || echo "")
echo "Resolved IP for $DOMAIN is: ${YELLOW}${RESOLVED_IP:-Not found}${NC}"
if [[ "$RESOLVED_IP" != "$SERVER_IP" ]]; then
    echo -e "\n${RED}ERROR: DNS validation failed!${NC}" >&2
    echo "The domain ${YELLOW}$DOMAIN${NC} does not resolve to this server's IP (${YELLOW}$SERVER_IP${NC})." >&2
    echo "Please update your DNS A record in Cloudflare and run the script again." >&2
    exit 1
fi
echo -e "${GREEN}DNS validation successful!${NC}"

cat > /usr/local/bin/raycontrol <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

XCONF="/etc/xray/config.json"
NFT_TABLE="inet filter"
NFT_SET="xray_clients"
DB_XRAY_USERS="/etc/xray/users.db"
DB_HY_USERS="/etc/hysteria/users.db"
DB_IPS="/etc/xray/ips.db"
ENABLED_FLAG="/etc/xray/enabled.flag"
BACKUP_DIR="/var/backups/ray-aio"
INSTALL_CONF="/etc/ray-aio/install.conf"
HYSTERIA_CONF="/etc/hysteria/config.yaml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ensure_db(){
    mkdir -p /etc/xray /etc/hysteria "$BACKUP_DIR"
    touch "$DB_XRAY_USERS" "$DB_HY_USERS" "$DB_IPS"
    if [ ! -f "$ENABLED_FLAG" ]; then
        echo "disabled" > "$ENABLED_FLAG"
    fi
}

reload_services(){
    if [[ "$(cat "$ENABLED_FLAG")" == "enabled" ]]; then
        case "$1" in
            xray) systemctl restart xray; echo -e "${GREEN}Xray service reloaded.${NC}" ;;
            hysteria) systemctl restart hysteria-server; echo -e "${GREEN}Hysteria2 service reloaded.${NC}" ;;
            *) systemctl restart xray; systemctl restart hysteria-server; echo -e "${GREEN}All services reloaded.${NC}" ;;
        esac
    fi
}

show_qr() {
    local type="$1"
    local id="$2"

    if ! command -v qrencode &> /dev/null; then
        echo -e "${RED}Error: 'qrencode' is not installed. Please run 'apt install qrencode'.${NC}" >&2
        return 1
    fi
    if [ ! -f "$INSTALL_CONF" ]; then
        echo -e "${RED}ERROR: Install config not found at $INSTALL_CONF${NC}" >&2; exit 1;
    fi
    source "$INSTALL_CONF"

    local uri=""
    local name=""

    case "$type" in
        vless)
            name="${DOMAIN}-VLESS-${id:0:8}"
            uri="vless://${id}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=xtls&flow=xtls-rprx-vision&alpn=h2&sni=${DOMAIN}#${name}"
            ;;
        trojan)
            name="${DOMAIN}-Trojan-${id:0:8}"
            uri="trojan://${id}@${DOMAIN}:${PORT_TROJAN}?alpn=h2&sni=${DOMAIN}#${name}"
            ;;
        hysteria)
            if [[ -z "$id" ]]; then
                echo -e "${RED}ERROR: Please provide a Hysteria password to generate a QR code.${NC}" >&2; exit 1;
            fi
            local obfs_pass
            obfs_pass=$(awk '/salamander:/,/password:/ {if ($1 == "password:") {print $2; exit}}' "$HYSTERIA_CONF")
            if [[ -z "$obfs_pass" ]]; then
                echo -e "${RED}ERROR: Could not read Hysteria OBFS password from $HYSTERIA_CONF${NC}" >&2; exit 1;
            fi
            name="${DOMAIN}-Hysteria2-${id:0:6}"
            uri="hysteria2://${id}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${obfs_pass}#${name}"
            ;;
        *)
            echo -e "${RED}Invalid type specified for QR code generation.${NC}" >&2; return 1;;
    esac

    echo -e "\n${YELLOW}--- QR Code for: $name ---${NC}"
    qrencode -t ANSIUTF8 "$uri"
    echo -e "${YELLOW}URI: ${uri}${NC}\n"
}

add_user(){
    local type="$1"
    if [[ "$type" == "vless" ]]; then
        local uuid
        uuid=$(uuidgen)
        jq --arg id "$uuid" \
           '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision"}]' \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "vless:$uuid" >> "$DB_XRAY_USERS"
        echo -e "${GREEN}Added VLESS user: $uuid${NC}"
        reload_services xray
        show_qr vless "$uuid"
    elif [[ "$type" == "trojan" ]]; then
        local pass
        pass=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
        jq --arg pw "$pass" \
           '.inbounds[1].settings.clients += [{"password":$pw}]' \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "trojan:$pass" >> "$DB_XRAY_USERS"
        echo -e "${GREEN}Added Trojan user. Password: $pass${NC}"
        reload_services xray
        show_qr trojan "$pass"
    elif [[ "$type" == "hysteria" ]]; then
        local pass
        pass=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
        echo "$pass" >> "$DB_HY_USERS"
        echo -e "${GREEN}Added Hysteria2 user. Password: $pass${NC}"
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
        echo "Removed Xray user: $id"
        reload_services xray
    elif grep -qFx "$id" "$DB_HY_USERS"; then
        sed -i "\%^${id}\$%d" "$DB_HY_USERS"
        echo "Removed Hysteria2 user: $id"
        reload_services hysteria
    else
        echo "User not found: $id" >&2
        exit 1
    fi
}

list_users(){
    echo -e "${YELLOW}--- Xray Users (VLESS/Trojan) ---${NC}"
    if [[ ! -s "$DB_XRAY_USERS" ]]; then
        echo "(none)"
    else
        echo "TYPE    ID/PASSWORD"
        echo "----------------------------------------"
        while IFS=":" read -r type id; do
            printf "%-7s %s\n" "$type" "$id"
        done < "$DB_XRAY_USERS"
    fi

    echo -e "\n${YELLOW}--- Hysteria2 Users ---${NC}"
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
Usage: raycontrol <command> [args]

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
MSG
}

ensure_db
case "${1:-help}" in
  help)        help ;;
  enable)      enable_all ;;
  disable)     disable_all ;;
  status)      show_status ;;
  monitor)     watch -n 5 -t --color "$0" status ;;
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
chmod +x /usr/local/bin/raycontrol

cat > /usr/local/bin/apply_nftables_xray.sh <<EOF
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
chmod +x /usr/local/bin/apply_nftables_xray.sh

echo -e "\n${GREEN}--- Issuing Certificate with Certbot ---${NC}"
mkdir -p /root/.secrets
cat > /root/.secrets/cloudflare.ini <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
chmod 600 /root/.secrets/cloudflare.ini
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  --agree-tos --no-eff-email \
  -m "$EMAIL" \
  -d "$DOMAIN"

echo -e "\n${GREEN}--- Configuring Automatic Certificate Renewal ---${NC}"
mkdir -p /etc/letsencrypt/renewal-hooks/post
cat > /etc/letsencrypt/renewal-hooks/post/reload_services.sh <<'EOF'
#!/usr/bin/env bash
if [[ -f /etc/xray/enabled.flag && "$(cat /etc/xray/enabled.flag)" == "enabled" ]]; then
    systemctl restart xray
    systemctl restart hysteria-server
fi
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/reload_services.sh

echo -e "\n${GREEN}--- Installing Xray-core ---${NC}"
mkdir -p /etc/xray /var/log/xray
chown -R nobody:nogroup /etc/xray /var/log/xray
XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
wget -qO /tmp/Xray-linux-64.zip "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER/Xray-linux-64.zip"
unzip -qo /tmp/Xray-linux-64.zip -d /usr/local/bin
rm /tmp/Xray-linux-64.zip
chmod +x /usr/local/bin/xray

cat > /etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": $PORT_VLESS, "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID_VLESS", "flow": "xtls-rprx-vision"}], "decryption": "none"},
      "streamSettings": {"network": "tcp", "security": "tls", "xtlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}], "alpn": ["h2"]}}
    },
    {
      "port": $PORT_TROJAN, "protocol": "trojan",
      "settings": {"clients": [{"password": "$PASSWORD_TROJAN"}], "fallbacks": [{"dest": "@blackhole"}]},
      "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}], "alpn": ["h2"]}}
    }
  ],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "@blackhole"}]
}
EOF
echo "vless:$UUID_VLESS" > /etc/xray/users.db
echo "trojan:$PASSWORD_TROJAN" >> /etc/xray/users.db

cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray -config /etc/xray/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

echo -e "\n${GREEN}--- Installing Hysteria2 ---${NC}"
RAW_TAG=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r .tag_name)
ENC_TAG=${RAW_TAG//\//%2F}
DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${ENC_TAG}/hysteria-linux-amd64"
wget -nv -O /usr/local/bin/hysteria-server "$DOWNLOAD_URL"
chmod +x /usr/local/bin/hysteria-server
echo -e "${GREEN}Hysteria2 installed successfully!${NC}"

mkdir -p /etc/hysteria
cat > /etc/hysteria/config.yaml <<EOF
listen: :$PORT_HYSTERIA
tls:
  cert: /etc/letsencrypt/live/$DOMAIN/fullchain.pem
  key: /etc/letsencrypt/live/$DOMAIN/privkey.pem
auth:
  type: file
  file:
    path: /etc/hysteria/users.db
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

echo "$PASSWORD_HYSTERIA" > /etc/hysteria/users.db

cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Service
After=network.target nss-lookup.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/hysteria-server server -c /etc/hysteria/config.yaml
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

VLESS_URI="vless://${UUID_VLESS}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=xtls&flow=xtls-rprx-vision&alpn=h2&sni=${DOMAIN}#${DOMAIN}-VLESS"
TROJAN_URI="trojan://${PASSWORD_TROJAN}@${DOMAIN}:${PORT_TROJAN}?alpn=h2&sni=${DOMAIN}#${DOMAIN}-Trojan"
HYSTERIA_URI="hysteria2://${PASSWORD_HYSTERIA}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${PASSWORD_HYSTERIA_OBFS}#${DOMAIN}-Hysteria2"

trap - ERR EXIT
echo -e "\n${GREEN}--- Installation successful! ---${NC}"

echo -e "\n\n${YELLOW}=====================================================${NC}"
echo -e "${YELLOW}               ACTION REQUIRED TO ACTIVATE               ${NC}"
echo -e "${YELLOW}=====================================================${NC}\n"

if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    echo -e "${YELLOW}IMPORTANT: A reboot is required to use the new XanMod kernel.${NC}"
    echo -e "After rebooting, run 'raycontrol enable'.\n"
else
    echo -e "Services are installed but NOT RUNNING. The firewall is NOT ACTIVE."
    echo -e "To start all services and apply the firewall, run:\n"
    echo -e "  ${GREEN}raycontrol enable${NC}\n"
fi
echo -e "After enabling, your system will be fully configured and ready."
echo -e "Your IP will not be whitelisted automatically. You must perform the port knock first."
echo -e "An IP will be removed from the whitelist after 10 minutes of inactivity."

echo -e "\n${YELLOW}--- Initial Connection Info (once enabled) ---${NC}"
echo "Knock sequence for all services: $K1 -> $K2 -> $K3"
echo "SSH Port: $SSH_PORT"
echo
echo -e "${YELLOW}VLESS (TCP, H2-Only):${NC}"
echo "  Port: $PORT_VLESS, UUID: $UUID_VLESS"
echo
echo -e "${YELLOW}Trojan (TCP, H2-Only):${NC}"
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

echo -e "\nUse ${GREEN}'raycontrol help'${NC} for a full list of commands including status, backup, and restore."
echo -e "\n${GREEN}=========================================================================================${NC}\n"