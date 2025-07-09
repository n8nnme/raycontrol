#!/usr/bin/env bash
set -euo pipefail

# --- Colors for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. Ensure running as root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: This script must be run as root.${NC}" >&2
  exit 1
fi

# 2. Prompt for core parameters
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

# Validate port ranges
for P in K1 K2 K3 PORT_VLESS PORT_TROJAN PORT_HYSTERIA; do
  VAL=${!P}
  if ! [[ "$VAL" =~ ^[0-9]+$ ]] || (( VAL<1 || VAL>65535 )); then
    echo -e "${RED}ERROR: Port $P ($VAL) must be a number between 1 and 65535.${NC}" >&2
    exit 1
  fi
done

echo
read -rp "Install XanMod kernel for BBRv3 and other optimizations? [y/N]: " INSTALL_XANMOD

# 3. Pre-flight Checks & Confirmation
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

# 4. Install Dependencies & XanMod
echo -e "\n${GREEN}--- Installing Core Dependencies ---${NC}"
apt update
apt install -y \
  curl wget unzip jq iptables ipset certbot qrencode \
  python3-certbot-dns-cloudflare \
  uuid-runtime openssl socat iptables-persistent gawk dnsutils uuid uuid-dev uuid-runtime uuidcdef

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
    
    XANMOD_PKG_NAME="linux-xanmod-lts-x64v1" # Default
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

# 5. Generate credentials & paths
UUID_VLESS=$(uuidgen)
PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
PASSWORD_HYSTERIA=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
PASSWORD_HYSTERIA_OBFS=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
WEBPATH_TROJAN=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9')

# 6. DNS Validation
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

echo -e "\n${GREEN}--- Creating dedicated group for certificate access ---${NC}"
groupadd --system certs-access || echo "Group 'certs-access' already exists."
usermod -a -G certs-access nobody
echo "Added user 'nobody' to 'certs-access' group for secure certificate reading."

# 7. Write raycontrol CLI
cat > /usr/local/bin/raycontrol <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
XCONF="/etc/xray/config.json"
IPSET="xray_clients"
DB_USERS="/etc/xray/users.db"
DB_IPS="/etc/xray/ips.db"
ENABLED_FLAG="/etc/xray/enabled.flag"

ensure_db(){
  mkdir -p /etc/xray
  touch "$DB_USERS" "$DB_IPS"
  if [ ! -f "$ENABLED_FLAG" ]; then
      echo "disabled" > "$ENABLED_FLAG"
  fi
}
reload_xray(){
  if [[ "$(cat $ENABLED_FLAG)" == "enabled" ]]; then
    systemctl restart xray
  fi
}
add_user(){
  type=${1:-}
  if [[ $type == "vless" ]]; then
    uuid=$(uuidgen)
    jq --arg id "$uuid" '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision"}]' "$XCONF" > tmp && mv tmp "$XCONF"
    echo "vless:$uuid:h2-only" >>"$DB_USERS"
    echo "Added VLESS user $uuid"
  elif [[ $type == "trojan" ]]; then
    pass=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
    path=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9')
    jq --arg pw "$pass" --arg p "/$path" '.inbounds[1].settings.clients += [{"password":$pw}] | .inbounds[1].settings.fallbacks += [{"path":$p,"dest":6001,"xver":1}]' "$XCONF" > tmp && mv tmp "$XCONF"
    echo "trojan:$pass:$path" >>"$DB_USERS"
    echo "Added Trojan user with path /$path"
  else
    echo "Usage: raycontrol add-user [vless|trojan]" >&2; exit 1
  fi
  reload_xray
}
del_user(){
  id=$1; sed -i "\:^.*$id.*\$d" "$DB_USERS"
  echo "Removed user '$id' from DB. Manual edit of $XCONF is required."
}
list_users(){
  echo "=== Xray Users (type:id/pass:path) ==="
  column -t -s: "$DB_USERS" || echo "(none)"
}
list_ips(){
  echo "=== Whitelisted IPs ==="
  ipset list $IPSET | awk '/Members:/{f=1;next} f' || echo "(none)"
}
add_ip(){
  ip=$1; ipset add $IPSET "$ip"; echo "$ip" >>"$DB_IPS"
  echo "Whitelisted IP $ip"
}
del_ip(){
  ip=$1; ipset del $IPSET "$ip"; sed -i "\:^$ip\$d" "$DB_IPS"
  echo "Removed IP $ip"
}
enable_all(){
  echo "enabled" > "$ENABLED_FLAG"
  bash /usr/local/bin/apply_iptables_xray.sh
  systemctl start xray
  systemctl start hysteria-server
  iptables-save > /etc/iptables/rules.v4
  echo "All services and firewall enabled and persisted."
}
disable_all(){
  echo "disabled" > "$ENABLED_FLAG"
  systemctl stop hysteria-server
  systemctl stop xray
  iptables -F
  iptables-save > /etc/iptables/rules.v4
  echo "All services and firewall disabled. Flushed rules have been persisted."
}
help(){
  cat <<MSG
Usage: raycontrol <command> [args]
Services Management:
  enable         Enable all services + firewall and persist rules
  disable        Disable all services + firewall and persist flushed rules
Xray User Management:
  list-users     List VLESS/Trojan users
  add-user [vless|trojan] Add a new VLESS or Trojan user
  del-user <ID>  Delete a user from the local DB (manual xray config edit required)
IP Whitelist Management:
  list-ips       List whitelisted IPs for port knocking
  add-ip <IP>    Whitelist an IP
  del-ip <IP>    Remove a whitelisted IP
MSG
}
ensure_db
case "${1:-help}" in
  help)        help ;;
  enable)      enable_all ;;
  disable)     disable_all ;;
  list-users)  list_users ;;
  add-user)    add_user "${2:-}" ;;
  del-user)    del_user "$2" ;;
  list-ips)    list_ips ;;
  add-ip)      add_ip "$2" ;;
  del-ip)      del_ip "$2" ;;
  *)           help ;;
esac
EOF
chmod +x /usr/local/bin/raycontrol

# 8. Prepare Apply-Firewall script
cat > /usr/local/bin/apply_iptables_xray.sh <<EOF
#!/usr/bin/env bash
set -e
TCP_PORTS="$SSH_PORT $PORT_VLESS $PORT_TROJAN"
UDP_PORTS="$PORT_HYSTERIA"
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
iptables -F && iptables -X
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
ipset create xray_clients hash:ip timeout 600 --exist
iptables -N KNOCK 2>/dev/null || iptables -F KNOCK
iptables -A INPUT -p tcp --dport $K1 -m recent --set --name K1 --rsource -j DROP
iptables -A INPUT -p tcp --dport $K2 -m recent --rcheck --seconds 10 --name K1 --rsource -m recent --set --name K2 --rsource -j DROP
iptables -A INPUT -p tcp --dport $K3 -m recent --rcheck --seconds 10 --name K2 --rsource -j KNOCK
iptables -A KNOCK -m recent --remove --name K1 --rsource -j SET --add-set xray_clients src --exist
iptables -A KNOCK -m recent --remove --name K2 --rsource -j SET --add-set xray_clients src --exist
iptables -A KNOCK -j DROP
for P in \$TCP_PORTS; do
  iptables -A INPUT -p tcp --dport \$P -m set --match-set xray_clients src -j ACCEPT
done
for P in \$UDP_PORTS; do
  iptables -A INPUT -p udp --dport \$P -m set --match-set xray_clients src -j ACCEPT
done
EOF
chmod +x /usr/local/bin/apply_iptables_xray.sh

# 9. Certificate issuance
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

# 10. Create Certbot renewal hook
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

# 11. Install Xray-core
echo -e "\n${GREEN}--- Installing Xray-core ---${NC}"
mkdir -p /etc/xray /var/log/xray
chown -R nobody:nogroup /etc/xray /var/log/xray
XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
wget -qO /tmp/Xray-linux-64.zip "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER/Xray-linux-64.zip" \
  && sudo unzip -qo /tmp/Xray-linux-64.zip -d /usr/local/bin \
  && rm /tmp/Xray-linux-64.zip
chmod +x /usr/local/bin/xray

# 12. Configure Xray
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

# 13. Setup Xray systemd service
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

# 14. Install Hysteria2
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

# 15. Configure Hysteria2
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

# 16. Setup Hysteria2 systemd service
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

# 17. Finalize installation
systemctl daemon-reload
systemctl enable xray
systemctl enable hysteria-server
echo -e "\n${GREEN}--- Installation of all files is complete. ---${NC}"

# 18. Final Info
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

echo -e "\nUse ${GREEN}'raycontrol help'${NC} to manage services and firewall."
echo -e "\n${GREEN}=====================================================${NC}\n"