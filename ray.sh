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

# 1. Prompt for core parameters
read -rp "Domain (e.g. your.domain.com): " DOMAIN
read -rp "Cloudflare API Token: " CF_API_TOKEN
read -rp "Cloudflare Zone ID: " CF_ZONE_ID
read -rp "Let’s Encrypt email: " EMAIL

echo
echo -e "${YELLOW}Specify three distinct TCP ports for Port Knocking (e.g. 10001 10002 10003):${NC}"
read -rp "Knock ports: " K1 K2 K3

# Validate distinct knock ports
if [[ "$K1" == "$K2" || "$K2" == "$K3" || "$K1" == "$K3" || -z "$K1" || -z "$K2" || -z "$K3" ]]; then
  echo -e "${RED}ERROR: Knock ports must be three distinct numbers.${NC}" >&2
  exit 1
fi

read -rp "Port for VLESS/XTLS (200–65535, default 443): " PORT_NAIVE
PORT_NAIVE=${PORT_NAIVE:-443}
read -rp "Port for Trojan (200–65535, default 8443): " PORT_TROJAN
PORT_TROJAN=${PORT_TROJAN:-8443}

# Validate port ranges
for P in K1 K2 K3 PORT_NAIVE PORT_TROJAN; do
  VAL=${!P}
  if ! [[ "$VAL" =~ ^[0-9]+$ ]] || (( VAL<1 || VAL>65535 )); then
    echo -e "${RED}ERROR: Port $P ($VAL) must be a number between 1 and 65535.${NC}" >&2
    exit 1
  fi
done

# 2. Pre-flight Checks & Confirmation
echo -e "\n${GREEN}--- Pre-flight Checks ---${NC}"
for P in PORT_NAIVE PORT_TROJAN; do
    VAL=${!P}
    if ss -tlpn | grep -q ":$VAL\s"; then
        echo -e "${RED}ERROR: Port $VAL is already in use. Please choose another.${NC}" >&2
        exit 1
    fi
    echo -e "Port $VAL is available."
done

SSH_PORT=$(ss -tnlp | awk '/sshd/ && /LISTEN/ { sub(".*:", "", $4); print $4; exit }')
echo "Detected SSH port: $SSH_PORT"

echo -e "\n${YELLOW}--- Installation Summary ---${NC}"
echo "Domain:             $DOMAIN"
echo "Email:              $EMAIL"
echo "SSH Port:           $SSH_PORT"
echo "VLESS Port:         $PORT_NAIVE"
echo "Trojan Port:        $PORT_TROJAN"
echo "Knock Ports:        $K1, $K2, $K3"
echo "Cloudflare Zone ID and API Token will be used."
echo -e "${YELLOW}----------------------------${NC}\n"

read -rp "Proceed with installation? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 1
fi

# 3. Generate credentials & paths
UUID_NAIVE=$(uuidgen)
PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
WEBPATH_TROJAN=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9') # Still needed for Trojan fallback

# 4. Install dependencies
echo -e "\n${GREEN}--- Installing Dependencies ---${NC}"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt update
apt install -y \
  curl wget unzip jq iptables ipset certbot qrencode \
  python3-certbot-dns-cloudflare \
  uuid-runtime openssl socat iptables-persistent

# 5. Write raycontrol CLI
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
    jq --arg id "$uuid" \
       '.inbounds[0].settings.clients += [{"id":$id,"flow":"xtls-rprx-vision"}]' \
      "$XCONF" > tmp && mv tmp "$XCONF"
    echo "vless:$uuid:h2-only" >>"$DB_USERS"
    echo "Added VLESS user $uuid (H2 Only)"
  elif [[ $type == "trojan" ]]; then
    pass=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
    path=$(head -c64 /dev/urandom | tr -dc 'A-Za-z0-9')
    jq --arg pw "$pass" --arg p "/$path" \
       '.inbounds[1].settings.clients += [{"password":$pw}] |
        .inbounds[1].settings.fallbacks += [{"path":$p,"dest":6001,"xver":1}]' \
      "$XCONF" > tmp && mv tmp "$XCONF"
    echo "trojan:$pass:$path" >>"$DB_USERS"
    echo "Added Trojan user with password $pass and path /$path"
  else
    echo "Usage: raycontrol add-user [vless|trojan]" >&2
    exit 1
  fi
  reload_xray
}

del_user(){
  id=$1
  sed -i "\:^.*$id.*\$d" "$DB_USERS"
  echo "Removed user containing '$id' from database."
  echo "You must manually edit $XCONF to remove the user from Xray and then restart the service."
}

list_users(){
  echo "=== Users (type:id/pass:path) ==="
  column -t -s: "$DB_USERS" || echo "(none)"
}

list_ips(){
  echo "=== Whitelisted IPs ==="
  ipset list $IPSET | awk '/Members:/{f=1;next} f' || echo "(none)"
}

add_ip(){
  ip=$1
  ipset add $IPSET "$ip"
  echo "$ip" >>"$DB_IPS"
  echo "Whitelisted IP $ip"
}

del_ip(){
  ip=$1
  ipset del $IPSET "$ip"
  sed -i "\:^$ip\$d" "$DB_IPS"
  echo "Removed IP $ip"
}

enable_all(){
  touch "$ENABLED_FLAG"
  bash /usr/local/bin/apply_iptables_xray.sh
  systemctl restart xray
  iptables-save > /etc/iptables/rules.v4
  echo "Xray and firewall enabled and persisted."
}

disable_all(){
  rm -f "$ENABLED_FLAG"
  systemctl stop xray
  iptables -F
  iptables-save > /etc/iptables/rules.v4
  echo "Xray and firewall disabled. Flushed rules have been persisted."
}

help(){
  cat <<MSG
Usage: raycontrol <command> [args]
Commands:
  help           Show this help
  enable         Enable Xray + firewall and persist rules
  disable        Disable Xray + firewall and persist flushed rules
  list-users     List proxy users
  add-user [vless|trojan]
                 Add a new user
  del-user <ID>  Delete a user from the local DB (manual edit required for xray)
  list-ips       List whitelisted IPs
  add-ip <IP>    Whitelist an IP
  del-ip <IP>    Remove IP
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

# 6. Prepare Apply-Firewall script
cat > /usr/local/bin/apply_iptables_xray.sh <<EOF
#!/usr/bin/env bash
set -e
# Base policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
# Clear previous rules
iptables -F
iptables -X
# Allow Loopback & established connections
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT
# Port Knocking setup
ipset create xray_clients hash:ip timeout 600 --exist
iptables -N KNOCK 2>/dev/null || iptables -F KNOCK
iptables -A INPUT -p tcp --dport $K1 -m recent --set --name K1 --rsource -j DROP
iptables -A INPUT -p tcp --dport $K2 -m recent --rcheck --seconds 10 --name K1 --rsource -m recent --set --name K2 --rsource -j DROP
iptables -A INPUT -p tcp --dport $K3 -m recent --rcheck --seconds 10 --name K2 --rsource -j KNOCK
iptables -A KNOCK -m recent --remove --name K1 --rsource -j SET --add-set xray_clients src --exist
iptables -A KNOCK -m recent --remove --name K2 --rsource -j SET --add-set xray_clients src --exist
iptables -A KNOCK -j DROP # Drop if knock sequence was only partially completed
# Allow services for whitelisted IPs (from the xray_clients ipset)
for P in $SSH_PORT $PORT_NAIVE $PORT_TROJAN; do
  iptables -A INPUT -p tcp --dport \$P -m set --match-set xray_clients src -j ACCEPT
done
EOF
chmod +x /usr/local/bin/apply_iptables_xray.sh

# 7. Certificate issuance
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

# 8. Create Certbot renewal hook for Xray
echo -e "\n${GREEN}--- Configuring Automatic Certificate Renewal ---${NC}"
mkdir -p /etc/letsencrypt/renewal-hooks/post
cat > /etc/letsencrypt/renewal-hooks/post/xray_restart.sh <<'EOF'
#!/usr/bin/env bash
systemctl restart xray
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/xray_restart.sh

# 9. Install Xray-core
echo -e "\n${GREEN}--- Installing Xray-core ---${NC}"
mkdir -p /etc/xray /var/log/xray
chown -R nobody:nogroup /etc/xray /var/log/xray
VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
wget -qO- "https://github.com/XTLS/Xray-core/releases/download/$VER/Xray-linux-64.zip" | funzip >/usr/local/bin/xray
chmod +x /usr/local/bin/xray

# 10. Configure Xray
cat > /etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log"},
  "inbounds": [
    {
      "port": $PORT_NAIVE,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$UUID_NAIVE", "flow": "xtls-rprx-vision"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
          "certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}],
          "alpn": ["h2"]
        }
      },
      "tag": "vless-in"
    },
    {
      "port": $PORT_TROJAN,
      "protocol": "trojan",
      "settings": {
        "clients": [{"password": "$PASSWORD_TROJAN"}],
        "fallbacks": [{"path": "/$WEBPATH_TROJAN", "dest": 6001, "xver": 1}]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem", "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"}],
          "alpn": ["h2"]
        }
      },
      "tag": "trojan-gateway"
    },
    {
      "listen": "127.0.0.1",
      "port": 6001,
      "protocol": "trojan",
      "settings": {"clients": [{"password": "$PASSWORD_TROJAN"}]},
      "streamSettings": {"network": "tcp"},
      "tag": "trojan-in"
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

# 11. Setup systemd service
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable xray

# 12. Prompt to apply firewall & start Xray
echo
read -rp "Apply firewall rules and start Xray now? [y/N]: " RESP
if [[ "${RESP,,}" == "y" ]]; then
  echo -e "${GREEN}Applying firewall and starting Xray...${NC}"
  bash /usr/local/bin/apply_iptables_xray.sh
  iptables-save > /etc/iptables/rules.v4
  systemctl start xray
  touch /etc/xray/enabled.flag
  echo "Firewall applied and persisted; Xray started."
else
  echo -e "${YELLOW}To apply later, run: raycontrol enable${NC}"
fi

# 13. Final Info
# *** MODIFICATION HERE: Updated VLESS URI to include alpn=h2 parameter for clients that support it ***
VLESS_URI="vless://${UUID_NAIVE}@${DOMAIN}:${PORT_NAIVE}?type=tcp&security=xtls&flow=xtls-rprx-vision&alpn=h2&sni=${DOMAIN}#${DOMAIN}-VLESS-H2"
TROJAN_URI="trojan://${PASSWORD_TROJAN}@${DOMAIN}:${PORT_TROJAN}?alpn=h2&sni=${DOMAIN}#${DOMAIN}-Trojan-H2"

echo -e "\n\n${GREEN}=====================================================${NC}"
echo -e "${GREEN}                 Installation Complete                 ${NC}"
echo -e "${GREEN}=====================================================${NC}\n"

echo -e "${YELLOW}--- Connection Info (H2 Only) ---${NC}"
echo "VLESS (XTLS-Vision):"
echo "  Address:  $DOMAIN"
echo "  Port:     $PORT_NAIVE"
echo "  UUID:     $UUID_NAIVE"
echo "  Flow:     xtls-rprx-vision"
echo "  ALPN:     h2"
echo
echo "Trojan:"
echo "  Address:  $DOMAIN"
echo "  Port:     $PORT_TROJAN"
echo "  Password: $PASSWORD_TROJAN"
echo "  ALPN:     h2"
echo
echo "SSH via knock: port $SSH_PORT"
echo "Knock sequence: knock ports $K1, $K2, then $K3"
echo

if command -v qrencode &> /dev/null; then
  echo -e "${YELLOW}--- QR Codes (scan with a client app) ---${NC}"
  echo "VLESS Configuration (H2 Only):"
  qrencode -t ANSIUTF8 "$VLESS_URI"
  echo "Trojan Configuration (H2 Only):"
  qrencode -t ANSIUTF8 "$TROJAN_URI"
else
  echo -e "${YELLOW}--- Configuration URIs (install 'qrencode' to display QR codes) ---${NC}"
  echo "VLESS URI: $VLESS_URI"
  echo "Trojan URI: $TROJAN_URI"
fi

echo -e "\nUse ${GREEN}'raycontrol help'${NC} to manage users, IPs, and services."
echo -e "Firewall rules are now persistent across reboots."
echo -e "The Xray service will restart automatically after certificate renewals."
echo -e "\n${GREEN}=====================================================${NC}\n"