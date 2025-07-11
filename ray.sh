#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: This script must be run as root.${NC}" >&2
  exit 1
fi

read -rp "Domain (e.g. your.domain.com): " DOMAIN
read -rp "Cloudflare API Token: " CF_API_TOKEN
read -rp "Let’s Encrypt email: " EMAIL

echo
echo -e "${YELLOW}Specify three distinct TCP ports for Port Knocking (e.g. 10001 10002 10003):${NC}"
read -rp "Knock ports: " K1 K2 K3

if [[ "$K1" == "$K2" || "$K2" == "$K3" || "$K1" == "$K3" || -z "$K1" || -z "$K2" || -z "$K3" ]]; then
  echo -e "${RED}ERROR: Knock ports must be three distinct numbers.${NC}" >&2
  exit 1
fi

read -rp "Port for VLESS/XTLS (TCP, 200–65535, default 443): " PORT_VLESS
PORT_VLESS=${PORT_VLESS:-443}
read -rp "Port for Trojan (TCP, 200–65535, default 8443): " PORT_TROJAN
PORT_TROJAN=${PORT_TROJAN:-8443}
read -rp "Port for Hysteria2 (UDP, 200-65535, default 3478): " PORT_HYSTERIA
PORT_HYSTERIA=${PORT_HYSTERIA:-3478}

for P in K1 K2 K3 PORT_VLESS PORT_TROJAN PORT_HYSTERIA; do
  VAL=${!P}
  if ! [[ "$VAL" =~ ^[0-9]+$ ]] || (( VAL<1 || VAL>65535 )); then
    echo -e "${RED}ERROR: Port $P ($VAL) must be a number between 1 and 65535.${NC}" >&2
    exit 1
  fi
done

echo
read -rp "Install XanMod kernel for BBRv3 and other optimizations? [y/N]: " INSTALL_XANMOD

echo -e "\n${GREEN}--- Pre-flight Checks ---${NC}"
SSH_PORT=$(ss -tnlp | awk '/sshd/ && /LISTEN/ { sub(".*:", "", $4); print $4; exit }')
echo "Detected SSH port: $SSH_PORT"

for P in PORT_VLESS PORT_TROJAN; do
    VAL=${!P}
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
    exit 1
fi

echo -e "\n${GREEN}--- Installing Core Dependencies ---${NC}"
apt update
apt install -y \
  curl wget unzip jq nftables certbot qrencode \
  python3-certbot-dns-cloudflare \
  uuid-runtime openssl socat gawk \
  dnsutils uuid uuid-dev uuid-runtime uuidcdef ssl-cert conntrack \
  bc numfmt watch

# Create directories for config and backups
mkdir -p /etc/ray-aio /var/backups/ray-aio

# Save installation variables for backup and status commands
cat > /etc/ray-aio/install.conf <<EOF
DOMAIN="$DOMAIN"
PORT_VLESS="$PORT_VLESS"
PORT_TROJAN="$PORT_TROJAN"
PORT_HYSTERIA="$PORT_HYSTERIA"
SSH_PORT="$SSH_PORT"
EOF

if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    echo -e "\n${GREEN}--- Setting up XanMod Repository ---${NC}"
    apt install -y gpg
    echo 'deb http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-kernel.list
    wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/xanmod-kernel.gpg

    echo -e "\n${GREEN}--- Updating sources for XanMod ---${NC}"
    apt update

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
    apt install -y "$XANMOD_PKG_NAME"
    rm -f /tmp/check_x86_v_level.awk
fi

UUID_VLESS=$(uuidgen)
PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
PASSWORD_HYSTERIA=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
PASSWORD_HYSTERIA_OBFS=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
WEBPATH_TROJAN=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9')

echo -e "\n${GREEN}--- Validating DNS Records ---${NC}"
SERVER_IP=$(curl -s https://ipwho.de/ip)
if [[ -z "$SERVER_IP" ]]; then
    echo -e "${RED}ERROR: Could not determine server's public IP address.${NC}" >&2
    exit 1
fi
echo "This server's public IP is: $SERVER_IP"
echo "Please ensure you have an A record for $DOMAIN pointing to this IP in your Cloudflare DNS."
echo "Waiting 60 seconds for DNS to propagate..."

for i in {60..1}; do
    printf "\rWaiting... %2d" "$i"
    sleep 1
done
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
DB_USERS="/etc/xray/users.db"
DB_IPS="/etc/xray/ips.db"
ENABLED_FLAG="/etc/xray/enabled.flag"
BACKUP_DIR="/var/backups/ray-aio"
INSTALL_CONF="/etc/ray-aio/install.conf"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ensure_db(){
    mkdir -p /etc/xray "$BACKUP_DIR"
    touch "$DB_USERS" "$DB_IPS"
    if [ ! -f "$ENABLED_FLAG" ]; then
        echo "disabled" > "$ENABLED_FLAG"
    fi
}

reload_xray(){
    if [[ "$(cat "$ENABLED_FLAG")" == "enabled" ]]; then
        systemctl restart xray
    fi
}

add_user(){
    local type="$1"
    if [[ "$type" == "vless" ]]; then
        local uuid
        uuid=$(uuidgen)
        jq --arg id "$uuid" \
           '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision"}]' \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "vless:$uuid" >> "$DB_USERS"
        echo "Added VLESS user: $uuid"
    elif [[ "$type" == "trojan" ]]; then
        local pass path
        pass=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
        path=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9')
        jq --arg pw "$pass" --arg p "/$path" \
           '.inbounds[1].settings.clients += [{"password":$pw}] |
            .inbounds[1].settings.fallbacks += [{"path":$p,"dest":6001,"xver":1}]' \
           "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "trojan:$pass:$path" >> "$DB_USERS"
        echo "Added Trojan user: $path"
    else
        echo "Usage: raycontrol add-user [vless|trojan]" >&2
        exit 1
    fi
    reload_xray
}

del_user(){
    local id="$1"
    if grep -qE "^(vless|trojan):$id" "$DB_USERS"; then
        # remove from DB
        sed -i "\%^.*:$id.*\$%d" "$DB_USERS"
        # remove from config.json
        jq "walk(
            if . == \"$id\" then empty
            else . end
        ) |
        .inbounds |= map(
            if .settings.clients then
                .settings.clients |= map(select(
                    (has(\"id\") and .id != \"$id\")
                    or (has(\"password\") and .password != \"$id\")
                ))
            else .
            end
        )" \
        "$XCONF" > "$XCONF.tmp" && mv "$XCONF.tmp" "$XCONF"
        echo "Removed user: $id"
        reload_xray
    else
        echo "User not found: $id" >&2
        exit 1
    fi
}

list_users(){
    if [[ ! -s "$DB_USERS" ]]; then
        echo "(none)"
        return
    fi
    echo "TYPE    ID/PASS    PATH"
    while IFS=":" read -r type id rest; do
        if [[ "$type" == "vless" ]]; then
            printf "vless   %s\n" "$id"
        else
            printf "trojan  %s    /%s\n" "$id" "$rest"
        fi
    done < "$DB_USERS"
}

list_ips(){
    echo "=== Whitelisted IPs (with remaining timeout) ==="
    local elements
    elements=$(nft list set $NFT_TABLE $NFT_SET | grep 'elements =' | sed 's/^[ \t]*elements = { //; s/ }$//')
    if [[ -z "$elements" ]]; then
        echo "(none)"
    else
        echo "$elements" | tr ',' '\n' | sed 's/^[ ]*//'
    fi
}

check_conns(){
    local ip="$1"
    if [[ -z "$ip" ]]; then
        echo "Usage: raycontrol check-conns <IP>" >&2
        exit 1
    fi
    if ! command -v conntrack &> /dev/null; then
        echo "Error: conntrack-tools is not installed. (apt install conntrack)" >&2
        exit 1
    fi
    echo "--- Active Connections for $ip ---"
    conntrack -L -s "$ip" -o extended || echo "No active connections found."
}

add_ip(){
    local ip="$1"
    nft add element $NFT_TABLE $NFT_SET { "$ip" }
    echo "$ip" >> "$DB_IPS"
    echo "Whitelisted IP $ip"
}

del_ip(){
    local ip="$1"
    local handle
    handle=$(nft -a list set $NFT_TABLE $NFT_SET | grep "$ip" | awk '{print $NF}')
    if [[ -n "$handle" ]]; then
        nft delete element $NFT_TABLE $NFT_SET { handle $handle }
        sed -i "\%^$ip\$%d" "$DB_IPS"
        echo "Removed IP $ip"
    else
        echo "IP $ip not found in set."
    fi
}

enable_all(){
    echo "enabled" > "$ENABLED_FLAG"
    bash /usr/local/bin/apply_nftables_xray.sh
    systemctl enable nftables
    systemctl start nftables
    systemctl start xray
    systemctl start hysteria-server
    nft -s list ruleset > /etc/nftables.conf
    echo "All services and firewall enabled and persisted."
}

disable_all(){
    echo "disabled" > "$ENABLED_FLAG"
    systemctl stop hysteria-server
    systemctl stop xray
    systemctl stop nftables
    nft flush ruleset
    nft -s list ruleset > /etc/nftables.conf
    echo "All services and firewall disabled. Flushed rules have been persisted."
}

backup_config() {
    local backup_file="$BACKUP_DIR/ray-aio-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    echo "Starting backup..."
    tar -czf "$backup_file" \
        /etc/xray/ \
        /etc/hysteria/ \
        /etc/letsencrypt/ \
        /usr/local/bin/raycontrol \
        /usr/local/bin/apply_nftables_xray.sh \
        /etc/ray-aio/ \
        /etc/nftables.conf \
        /etc/systemd/system/xray.service \
        /etc/systemd/system/hysteria-server.service

    echo -e "${GREEN}Backup complete! File saved to: $backup_file${NC}"
}

restore_config() {
    local backup_file="$1"
    if [[ ! -f "$backup_file" ]]; then
        echo -e "${RED}ERROR: Backup file not found: $backup_file${NC}" >&2
        exit 1
    fi

    echo -e "${YELLOW}WARNING: This will overwrite all current configurations and data.${NC}"
    read -rp "Are you sure you want to restore from $backup_file? [y/N]: " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo "Restore cancelled."
        exit 0
    fi

    echo "Disabling services before restore..."
    disable_all

    echo "Restoring files..."
    tar -xzf "$backup_file" -C /

    echo "Reloading systemd..."
    systemctl daemon-reload

    echo -e "${GREEN}Restore complete!${NC}"
    echo "Please review restored configurations."
    echo "Run 'raycontrol enable' to restart services with the restored configuration."
}

show_status() {
    source "$INSTALL_CONF"

    # Helper for status text
    get_status_text() {
        if systemctl is-active --quiet "$1"; then
            echo -e "${GREEN}active${NC}"
        else
            echo -e "${RED}inactive${NC}"
        fi
    }

    # Helper to get bandwidth
    get_bw() {
        local counter_name=$1
        local bytes
        bytes=$(nft -j list ruleset | jq -r ".nftables[] | select(.rule) | .rule | select(.comment == \"$counter_name\") | .bytes")
        if [[ -n "$bytes" && "$bytes" -gt 0 ]]; then
            echo "$(numfmt --to=iec-i --suffix=B --format="%.2f" "$bytes")"
        else
            echo "0.00B"
        fi
    }

    echo -e "${YELLOW}--- Service Status ---${NC}"
    printf "%-18s: %s\n" "Xray" "$(get_status_text xray)"
    printf "%-18s: %s\n" "Hysteria" "$(get_status_text hysteria-server)"
    printf "%-18s: %s\n" "NFTables Firewall" "$(get_status_text nftables)"

    echo -e "\n${YELLOW}--- Connection Info ---${NC}"
    printf "%-18s: %s\n" "Domain" "$DOMAIN"
    printf "%-18s: %s/tcp\n" "VLESS Port" "$PORT_VLESS"
    printf "%-18s: %s/tcp\n" "Trojan Port" "$PORT_TROJAN"
    printf "%-18s: %s/udp\n" "Hysteria Port" "$PORT_HYSTERIA"
    printf "%-18s: %s/tcp\n" "SSH Port" "$SSH_PORT"

    echo -e "\n${YELLOW}--- Monitoring ---${NC}"
    if systemctl is-active --quiet nftables; then
      local vless_conns trojan_conns hysteria_conns
      vless_conns=$(conntrack -L -p tcp --dport "$PORT_VLESS" 2>/dev/null | grep -c ESTABLISHED || echo 0)
      trojan_conns=$(conntrack -L -p tcp --dport "$PORT_TROJAN" 2>/dev/null | grep -c ESTABLISHED || echo 0)
      hysteria_conns=$(conntrack -L -p udp --dport "$PORT_HYSTERIA" 2>/dev/null | grep -c ASSURED || echo 0)

      printf "%-18s: %d\n" "VLESS Connections" "$vless_conns"
      printf "%-18s: %d\n" "Trojan Connections" "$trojan_conns"
      printf "%-18s: %d\n" "Hysteria Conns" "$hysteria_conns"
      echo
      printf "%-18s: %s\n" "VLESS Bandwidth" "$(get_bw vless_bw)"
      printf "%-18s: %s\n" "Trojan Bandwidth" "$(get_bw trojan_bw)"
      printf "%-18s: %s\n" "Hysteria Bandwidth" "$(get_bw hysteria_bw)"
    else
      echo "Firewall is inactive, cannot report monitoring stats."
    fi
}

help(){
    cat <<MSG
Usage: raycontrol <command> [args]
Services Management:
  enable         Enable all services + firewall and persist rules
  disable        Disable all services + firewall and persist flushed rules
  status         Show service states, connections, and bandwidth usage
  monitor        Live monitor the status command (updates every 5s)

Disaster Recovery:
  backup         Create a full backup of all configurations
  restore <file> Restore configuration from a backup archive

Xray User Management:
  list-users     List VLESS/Trojan users
  add-user [vless|trojan]  Add a new VLESS or Trojan user
  del-user <ID>  Delete a user (automatically updates config.json)

IP Whitelist Management:
  list-ips       List whitelisted IPs and their remaining timeout
  add-ip <IP>    Whitelist an IP
  del-ip <IP>    Remove a whitelisted IP
  check-conns <IP> Check active connections for a specific IP
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

# These variables are populated from the main install script's environment
SSH_PORT="$SSH_PORT"
PORT_VLESS="$PORT_VLESS"
PORT_TROJAN="$PORT_TROJAN"
PORT_HYSTERIA="$PORT_HYSTERIA"
K1="$K1"
K2="$K2"
K3="$K3"

TCP_PORTS_PROTECTED="$SSH_PORT,$PORT_VLESS,$PORT_TROJAN"

nft flush ruleset

nft add table inet filter
nft add chain inet filter input { type filter hook input priority 0; policy drop; }
nft add chain inet filter forward { type filter hook forward priority 0; policy drop; }
nft add chain inet filter output { type filter hook output priority 0; policy accept; }

nft add rule inet filter input iif lo accept
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input ip protocol icmp accept
nft add rule inet filter input ip6 nexthdr ipv6-icmp accept

nft add set inet filter knock_stage1 { type ipv4_addr; flags dynamic; timeout 10s; }
nft add set inet filter knock_stage2 { type ipv4_addr; flags dynamic; timeout 10s; }
nft add set inet filter xray_clients { type ipv4_addr; flags dynamic; timeout 10m; }
nft add chain inet filter knock

nft add rule inet filter input tcp dport $K1 add @knock_stage1 { ip saddr } drop
nft add rule inet filter input tcp dport $K2 ip saddr @knock_stage1 add @knock_stage2 { ip saddr } drop
nft add rule inet filter input tcp dport $K3 ip saddr @knock_stage2 jump knock

nft add rule inet filter knock add @xray_clients { ip saddr }
nft add rule inet filter knock drop

# Add rules with named counters for bandwidth monitoring
nft add rule inet filter input ip saddr @xray_clients tcp dport $PORT_VLESS counter update @xray_clients { ip saddr } accept comment "vless_bw"
nft add rule inet filter input ip saddr @xray_clients tcp dport $PORT_TROJAN counter update @xray_clients { ip saddr } accept comment "trojan_bw"
nft add rule inet filter input ip saddr @xray_clients udp dport $PORT_HYSTERIA counter update @xray_clients { ip saddr } accept comment "hysteria_bw"
nft add rule inet filter input ip saddr @xray_clients tcp dport $SSH_PORT counter update @xray_clients { ip saddr } accept comment "ssh_bw"

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
wget -qO /tmp/Xray-linux-64.zip "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER/Xray-linux-64.zip" \
  && sudo unzip -qo /tmp/Xray-linux-64.zip -d /usr/local/bin \
  && rm /tmp/Xray-linux-64.zip
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
      "settings": {"clients": [{"password": "$PASSWORD_TROJAN"}], "fallbacks": [{"path": "/$WEBPATH_TROJAN", "dest": 6001, "xver": 1}, {"dest": "@blackhole"}]},
      "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}], "alpn": ["h2"]}}
    },
    {"listen": "127.0.0.1", "port": 6001, "protocol": "trojan", "settings": {"clients": [{"password": "$PASSWORD_TROJAN"}]}}
  ],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "@blackhole"}]
}
EOF

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

RAW_TAG=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest \
           | jq -r .tag_name)

ENC_TAG=${RAW_TAG//\//%2F}

DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${ENC_TAG}/hysteria-linux-amd64"

if wget -nv -O /usr/local/bin/hysteria-server "$DOWNLOAD_URL"; then
  echo -e "${GREEN}Downloaded hysteria-server (${RAW_TAG})${NC}"
else
  echo -e "${RED}Failed to download hysteria-server from ${DOWNLOAD_URL}${NC}" >&2
  exit 1
fi

chmod +x /usr/local/bin/hysteria-server
echo -e "${GREEN}Hysteria2 installed successfully!${NC}"

mkdir -p /etc/hysteria
cat > /etc/hysteria/config.yaml <<EOF
listen: :$PORT_HYSTERIA
tls:
  cert: /etc/letsencrypt/live/$DOMAIN/fullchain.pem
  key: /etc/letsencrypt/live/$DOMAIN/privkey.pem
auth:
  type: password
  password: $PASSWORD_HYSTERIA
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
echo -e "\n${GREEN}--- Installation of all files is complete. ---${NC}"

VLESS_URI="vless://${UUID_VLESS}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=xtls&flow=xtls-rprx-vision&alpn=h2&sni=${DOMAIN}#${DOMAIN}-VLESS"
TROJAN_URI="trojan://${PASSWORD_TROJAN}@${DOMAIN}:${PORT_TROJAN}?alpn=h2&sni=${DOMAIN}#${DOMAIN}-Trojan"
HYSTERIA_URI="hysteria2://${PASSWORD_HYSTERIA}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${PASSWORD_HYSTERIA_OBFS}#${DOMAIN}-Hysteria2"

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

echo -e "\n${YELLOW}--- Connection Info (once enabled) ---${NC}"
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
echo "  Auth Pass: $PASSWORD_HYSTERIA"
echo "  OBFS Pass: $PASSWORD_HYSTERIA_OBFS"

if command -v qrencode &> /dev/null; then
  echo -e "\n${YELLOW}--- QR Codes (scan with a client app) ---${NC}"
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