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
read -rp "Cloudflare Zone ID: " CF_ZONE_ID
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
echo -e "${YELLOW}----------------------------${NC}\n"

read -rp "Proceed with installation? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 1
fi

# 4. Generate credentials & paths
UUID_VLESS=$(uuidgen)
PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
PASSWORD_HYSTERIA=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
PASSWORD_HYSTERIA_OBFS=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
WEBPATH_TROJAN=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9')

# 5. Install dependencies
echo -e "\n${GREEN}--- Installing Dependencies ---${NC}"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt update
apt install -y \
  curl wget unzip jq iptables ipset certbot qrencode \
  python3-certbot-dns-cloudflare \
  uuid-runtime openssl socat iptables-persistent

# 6. Write raycontrol CLI
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
  touch "$DB_USERS" "$DB_IPS" "$ENABLED_FLAG"
}
reload_xray(){
  [[ -f "$ENABLED_FLAG" ]] && systemctl restart xray
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
  touch "$ENABLED_FLAG"
  bash /usr/local/bin/apply_iptables_xray.sh
  systemctl restart xray
  systemctl restart hysteria-server
  iptables-save > /etc/iptables/rules.v4
  echo "All services and firewall enabled and persisted."
}
disable_all(){
  rm -f "$ENABLED_FLAG"
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

# 7. Prepare Apply-Firewall script
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

# 8. Certificate issuance
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

# 9. Create Certbot renewal hook
echo -e "\n${GREEN}--- Configuring Automatic Certificate Renewal ---${NC}"
mkdir -p /etc/letsencrypt/renewal-hooks/post
cat > /etc/letsencrypt/renewal-hooks/post/reload_services.sh <<'EOF'
#!/usr/bin/env bash
systemctl restart xray
systemctl restart hysteria-server
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/reload_services.sh

# 10. Install Xray-core
echo -e "\n${GREEN}--- Installing Xray-core ---${NC}"
mkdir -p /etc/xray /var/log/xray
chown -R nobody:nogroup /etc/xray /var/log/xray
XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
wget -qO- "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VER/Xray-linux-64.zip" | funzip >/usr/local/bin/xray
chmod +x /usr/local/bin/xray

# 11. Configure Xray
cat > /etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": $PORT_VLESS, "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID_VLESS", "flow": "xtls-rprx-vision"}], "decryption": "none"},
      "streamSettings": {"network": "tcp", "security": "xtls", "xtlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}], "alpn": ["h2"]}}
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

# 12. Setup Xray systemd service
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

# 13. Install Hysteria2
echo -e "\n${GREEN}--- Installing Hysteria2 ---${NC}"
HY_VER=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r .tag_name | sed 's/v//')
wget -qO /usr/local/bin/hysteria-server "https://github.com/apernet/hysteria/releases/download/v$HY_VER/hysteria-linux-amd64"
chmod +x /usr/local/bin/hysteria-server

# 14. Configure Hysteria2
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
  type: password
  password: $PASSWORD_HYSTERIA_OBFS
masquerade:
  type: proxy
  proxy:
    url: https://1.1.1.1
    rewriteHost: true
EOF

# 15. Setup Hysteria2 systemd service
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

# 16. Start services
systemctl daemon-reload
systemctl enable xray
systemctl enable hysteria-server
echo
read -rp "Apply firewall rules and start all services now? [y/N]: " RESP
if [[ "${RESP,,}" == "y" ]]; then
  echo -e "${GREEN}Applying firewall and starting services...${NC}"
  raycontrol enable
else
  echo -e "${YELLOW}To apply later, run: raycontrol enable${NC}"
fi

# 17. Final Info
VLESS_URI="vless://${UUID_VLESS}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=xtls&flow=xtls-rprx-vision&alpn=h2&sni=${DOMAIN}#${DOMAIN}-VLESS"
TROJAN_URI="trojan://${PASSWORD_TROJAN}@${DOMAIN}:${PORT_TROJAN}?alpn=h2&sni=${DOMAIN}#${DOMAIN}-Trojan"
HYSTERIA_URI="hysteria2://${PASSWORD_HYSTERIA}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=password&obfs-password=${PASSWORD_HYSTERIA_OBFS}#${DOMAIN}-Hysteria2"

echo -e "\n\n${GREEN}=====================================================${NC}"
echo -e "${GREEN}                 Installation Complete                 ${NC}"
echo -e "${GREEN}=====================================================${NC}\n"
echo -e "${YELLOW}--- Connection Info ---${NC}"
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