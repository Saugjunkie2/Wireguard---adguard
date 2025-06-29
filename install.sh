#!/usr/bin/env bash
# Vollständiges Installer- und Management-Skript für WireGuard + AdGuard Home auf Debian 12
# Inklusive interaktivem Menü für alle Konzept-Funktionen
set -euo pipefail

# --- Standard-Parameter (anpassbar im Menü) ---
# Falls keine Netzwerkschnittstelle vorgegeben ist, automatisch diejenige mit
# dem Standardgateway ermitteln. Das vermeidet feste Namen wie "eth0" oder
# "ens18", die auf verschiedenen Systemen variieren können.
HOST_IFACE="${HOST_IFACE:-$(ip -o -4 route show to default | awk '{print $5; exit}')}"
WG_IFACE="wg0"
WG_IPV4_BASE="10.66.66"
WG_IPV6_BASE="fd00:dead:beef"
VPN_IPV4="${WG_IPV4_BASE}.1"

ADGUARD_UI_PORT=3000
ADGUARD_DNS_PORT=5353
UNBOUND_PORT=5335

declare -A GROUP_NETS=( [guest]="0/26" [member]="64/26" [vip]="128/26" [admin]="192/26" )
declare -A GROUP_SPEED=( [guest]=5 [member]=20 [vip]=100 [admin]=0 )
declare -A GROUP_QUOTA=( [guest]=$((50*1024**3)) [member]=$((200*1024**3)) [vip]=$((1024*1024**3)) [admin]=0 )

BACKUP_DIR="/var/backups/vpn"
LANDING_DIR="/var/www/expired"
LOGFILE="/var/log/vpn_installer.log"
PEERS_DIR="/etc/wireguard/peers"
MANUAL_BLACKLIST_FILE="/opt/AdGuardHome/manual_blacklist.txt"
GEO_BLACKLIST_FILE="/etc/nftables/geo_blacklist.conf"
EXPIRY_NFT_FILE="/etc/nftables/expiry_blacklist.conf"

mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

# Fallback for environments ohne systemd
safe_systemctl() {
  if command -v systemctl >/dev/null && [ "$(ps -p 1 -o comm=)" = systemd ]; then
    systemctl "$@"
  else
    echo "systemctl $* skipped (systemd not available)" >&2
  fi
}

# --- Paketinstallation ---
install_packages() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    wireguard nftables unbound iproute2 qrencode nginx curl wget

  # AdGuard Home herunterladen & installieren
[[ -x /usr/bin/AdGuardHome ]] && return
  tmpdir=$(mktemp -d)
  curl -L https://static.adguard.com/adguardhome/release/AdGuardHome_linux_amd64.tar.gz -o "$tmpdir/adguard.tar.gz"
  tar -xzf "$tmpdir/adguard.tar.gz" -C "$tmpdir"
  "$tmpdir/AdGuardHome/AdGuardHome" -s install
  rm -rf "$tmpdir"
  safe_systemctl enable AdGuardHome
  safe_systemctl start AdGuardHome

  # Verzeichnisse & Dateien anlegen
  mkdir -p "$PEERS_DIR" "$BACKUP_DIR" "$LANDING_DIR" "/etc/nftables"
  touch "$MANUAL_BLACKLIST_FILE" "$GEO_BLACKLIST_FILE" "$PEERS_DIR/metadata.csv"
  # IP-Forwarding dauerhaft aktivieren
  echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-vpn-forward.conf
  echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-vpn-forward.conf
  sysctl -p /etc/sysctl.d/99-vpn-forward.conf
}

# --- WireGuard konfigurieren ---
configure_wireguard() {
  cat > /etc/wireguard/${WG_IFACE}.conf <<EOF
[Interface]
Address = ${VPN_IPV4}/26, ${WG_IPV6_BASE}::1/64
ListenPort = 51820
SaveConfig = true
PrivateKey = $(wg genkey)
PostUp = nft -f /etc/nftables.conf
PostUp = sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
PostUp = iptables -t nat -A POSTROUTING -o ${HOST_IFACE} -j MASQUERADE
PostUp = /usr/local/bin/configure_tc.sh
PostDown = iptables -t nat -D POSTROUTING -o ${HOST_IFACE} -j MASQUERADE
EOF
  safe_systemctl enable wg-quick@${WG_IFACE}
  wg-quick up ${WG_IFACE}
}

# --- Unbound mit DNSSEC ---
configure_unbound() {
  cat > /etc/unbound/unbound.conf <<EOF
server:
  interface: 127.0.0.1
  port: ${UNBOUND_PORT}
  do-ip4: yes
  do-ip6: yes
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  val-permissive-mode: no
  verbosity: 1
EOF
  safe_systemctl enable unbound
  safe_systemctl restart unbound
}

# --- AdGuard Home konfigurieren ---
configure_adguard() {
  # UI und DNS nur über VPN binden
  sed -i "s|^bind_host:.*|bind_host: ${VPN_IPV4}|" /opt/AdGuardHome/AdGuardHome.yaml
  sed -i "s|^bind_port:.*|bind_port: ${ADGUARD_UI_PORT}|" /opt/AdGuardHome/AdGuardHome.yaml
  # DNS-Server
  sed -i '/^dns:/,/^  upstream_dns:/d' /opt/AdGuardHome/AdGuardHome.yaml
  cat >> /opt/AdGuardHome/AdGuardHome.yaml <<EOF
dns:
  bind_hosts:
    - ${VPN_IPV4}
  port: ${ADGUARD_DNS_PORT}
  upstream_dns:
    - 127.0.0.1#${UNBOUND_PORT}
EOF
  safe_systemctl enable AdGuardHome
  safe_systemctl restart AdGuardHome
}

# --- nftables-Regeln ---
configure_nftables() {
  cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

# NAT-Tabelle für Ablauf/Expiry
table ip nat {
  chain prerouting { type nat hook prerouting priority 0; policy accept;
    include "$EXPIRY_NFT_FILE"
  }
  chain postrouting { type nat hook postrouting priority 100; policy accept;
    oifname "$HOST_IFACE" masquerade
  }
}

# Haupt-Tabelle für VPN-Sicherheit
table inet vpn {
  chain input { type filter hook input priority 0; policy accept; }
  chain output { type filter hook output priority 0; policy drop; }
  chain forward { type filter hook forward priority 0; policy accept; }
  # Kill-Switch
  oifname "${WG_IFACE}" accept
  # DNS-Zwang
  tcp dport 53 redirect to :${ADGUARD_DNS_PORT}
  udp dport 53 redirect to :${ADGUARD_DNS_PORT}
  # Geo-IP Blacklist
  include "$GEO_BLACKLIST_FILE"
  # Gruppen-Markierung, Isolation & Quota
  include "/etc/nftables/groups.conf"
}
EOF

  # Geo-IP Blacklist (leer)
  cat > "$GEO_BLACKLIST_FILE" <<EOF
# Hier CIDR-Blöcke eintragen, die gesperrt werden sollen
EOF

  # Gruppen.conf generieren
  cat > /etc/nftables/groups.conf <<EOF
# Gruppe: Markierung, Isolation, Quota
EOF
  for grp in "${!GROUP_NETS[@]}"; do
    cidr="${GROUP_NETS[$grp]}"
    base4="${WG_IPV4_BASE}.${cidr%%/*}"
    # Markierung für QoS
    mark=$(case $grp in guest) echo 1;; member) echo 2;; vip) echo 3;; admin) echo 4;; esac)
    echo "    ip saddr $base4/26 meta mark set $mark" >> /etc/nftables/groups.conf
    # Isolation gegen andere Gruppen
    for other in "${!GROUP_NETS[@]}"; do
      [[ "$other" == "$grp" ]] && continue
      other4="${WG_IPV4_BASE}.${GROUP_NETS[$other]%%/*}"
      echo "    ip saddr $base4/26 ip daddr $other4/26 drop" >> /etc/nftables/groups.conf
    done
    # Quota-Regel
    quota=${GROUP_QUOTA[$grp]}
    [[ $quota -gt 0 ]] && echo "    ip saddr $base4/26 quota $quota drop" >> /etc/nftables/groups.conf
  done

  # Expiry-Datei initial leer
  cat > "$EXPIRY_NFT_FILE" <<EOF
# Generiert von expiry_check.sh, dnat-Regeln für abgelaufene Peers
EOF

  safe_systemctl enable nftables
  safe_systemctl restart nftables
}

# --- Traffic-Shaping (tc) ---
configure_tc() {
  tc qdisc del dev ${WG_IFACE} root 2>/dev/null || true
  tc qdisc add dev ${WG_IFACE} root handle 1: htb default 999
  for grp in "${!GROUP_NETS[@]}"; do
    speed=${GROUP_SPEED[$grp]}
    mark=$(case $grp in guest) echo 1;; member) echo 2;; vip) echo 3;; admin) echo 4;; esac)
    if [[ $speed -gt 0 ]]; then
      tc class add dev ${WG_IFACE} parent 1: classid 1:"$mark" htb rate "${speed}"mbit ceil "${speed}"mbit burst 15k
      tc filter add dev ${WG_IFACE} protocol ip parent 1: prio 1 handle "$mark" fw flowid 1:"$mark"
    fi
  done
  cat > /usr/local/bin/configure_tc.sh <<'EOF'
#!/usr/bin/env bash
$(declare -f configure_tc)
configure_tc
EOF
  chmod +x /usr/local/bin/configure_tc.sh
}

# --- Landingpage für abgelaufene Peers ---
configure_landingpage() {
  cat > "${LANDING_DIR}/index.html" <<EOF
<html><body>
<h1>VPN-Zugang abgelaufen</h1>
<p>Ihr Gratis-Jahr ist beendet.</p>
<p>Kontaktieren Sie den Support für Verlängerung.</p>
</body></html>
EOF
  cat > /etc/nginx/sites-available/expired <<EOF
server {
    listen ${VPN_IPV4}:80;
    root ${LANDING_DIR};
}
EOF
  ln -sf /etc/nginx/sites-available/expired /etc/nginx/sites-enabled/expired
  rm -f /etc/nginx/sites-enabled/default
  safe_systemctl restart nginx
}

# --- Backup & Restore Skripte ---
# shellcheck disable=SC2120
configure_backup_scripts() {
  cat > /usr/local/bin/backup_vpn.sh <<EOF
#!/usr/bin/env bash
DEST="${BACKUP_DIR}/backup_$(date +%F_%H%M).tar.gz"
tar czf "$DEST" \
  /etc/wireguard /etc/wireguard/peers /etc/unbound \
  /opt/AdGuardHome /var/lib/AdGuardHome \
  /etc/nftables.conf /etc/nftables/geo_blacklist.conf /etc/nftables/groups.conf \
  /etc/nftables/expiry_blacklist.conf /etc/nginx/sites-available/expired
echo "Backup gespeichert: $DEST"
EOF
  chmod +x /usr/local/bin/backup_vpn.sh
  cat > /usr/local/bin/restore_vpn.sh <<EOF
#!/usr/bin/env bash
[ -f "$1" ] || { echo "Backup nicht gefunden"; exit 1; }
tar xzf "$1" -C /
safe_systemctl restart wg-quick@${WG_IFACE} unbound AdGuardHome nftables nginx
/usr/local/bin/configure_tc.sh
echo "Restore abgeschlossen"
EOF
  chmod +x /usr/local/bin/restore_vpn.sh
}

# --- Timer-Skripte für Quota-Reset & Ablauf-Check ---
configure_timer_scripts() {
  # Quota-Reset
  cat > /usr/local/bin/quota_reset.sh <<'EOF'
#!/usr/bin/env bash
# Quotas zurücksetzen durch Neubau der nft-Regeln
nft flush table inet vpn
nft -f /etc/nftables.conf
EOF
  chmod +x /usr/local/bin/quota_reset.sh

  # Ablauf-Check
  # shellcheck disable=SC2154
  cat > /usr/local/bin/expiry_check.sh <<EOF
#!/usr/bin/env bash
# Erzeuge dnat-Regeln für abgelaufene Peers
EXP_FILE="${EXPIRY_NFT_FILE}"
: > "$EXP_FILE"
today=$(date +%Y-%m-%d)
while IFS='|' read -r name grp ip4 ip6 expires; do
  # shellcheck disable=SC2154
  if [[ "$expires" < "$today" ]]; then
    echo "ip saddr $ip4 dnat to $VPN_IPV4:80" >> "$EXP_FILE"
  fi
done < "$PEERS_DIR/metadata.csv"
# Reload nftables only NAT table
nft -f /etc/nftables.conf
EOF
  chmod +x /usr/local/bin/expiry_check.sh

  # cron jobs
  echo "0 0 1 * * root /usr/local/bin/quota_reset.sh" > /etc/cron.d/quota_reset
  echo "0 1 * * * root /usr/local/bin/expiry_check.sh" > /etc/cron.d/expiry_check
}

# --- Peer Management ---
create_peer() {
  read -r -p "Peer-Name: " peer_name
  echo "Gruppen: ${!GROUP_NETS[*]}"
  read -r -p "Gruppe: " grp
  [[ -z "${GROUP_NETS[$grp]:-}" ]] && { echo "Ungültige Gruppe"; return; }
  read -r -p "Ablaufdatum (YYYY-MM-DD): " expires
  priv=$(wg genkey); pub=$(echo "$priv"|wg pubkey); psk=$(wg genpsk)
  # IP finden
  mapfile -t used < <(grep -h "Address" "$PEERS_DIR"/*.conf 2>/dev/null | grep -o "10\.66\.66\.[0-9]*" | cut -d '.' -f4)
  for i in {2..62}; do [[ ! " ${used[*]} " =~ $i ]] && oct=$i && break; done
  ip4="${WG_IPV4_BASE}.$oct"; ip6="${WG_IPV6_BASE}::$oct"
  # Konfig erzeugen
  conf="$PEERS_DIR/$peer_name.conf"
  cat > "$conf" <<EOF
[Interface]
PrivateKey = $priv
Address = $ip4/26, $ip6/64
DNS = $VPN_IPV4

[Peer]
PublicKey = $(wg show $WG_IFACE public-key)
PresharedKey = $psk
Endpoint = $(curl -s ifconfig.me):51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
  # aktivieren
  wg set "$WG_IFACE" peer "$pub" preshared-key <(echo "$psk") allowed-ips "$ip4"/32,"$ip6"/128
  wg-quick save $WG_IFACE
  qrencode -t ansiutf8 < "$conf"
  echo "$peer_name|$grp|$ip4|$ip6|$expires" >> $PEERS_DIR/metadata.csv
  echo "Peer erstellt: $conf"
}

# --- Hauptinstallation ---
main_install() {
  install_packages
  configure_wireguard
  configure_unbound
  configure_adguard
  configure_nftables
  configure_tc
  configure_landingpage
  # shellcheck disable=SC2119
  configure_backup_scripts
  configure_timer_scripts
  echo "Installation & Basis-Konfiguration abgeschlossen"
}

# --- Menü ---
show_menu() {
  clear
  echo "=== VPN Setup & Manager ==="
  echo "1) Vollständige Installation"
  echo "2) Peer erstellen"
  echo "3) Backup ausführen"
  echo "4) Backup wiederherstellen"
  echo "5) Geo-IP-Blacklist anpassen"
  echo "6) Manuelle Blacklist bearbeiten"
  echo "7) Konfiguration neu laden (nft, tc, nginx)"
  echo "8) Beenden"
  read -r -p "Wahl [1-8]: " opt
  case $opt in
    1) main_install;;
    2) create_peer;;
    3) /usr/local/bin/backup_vpn.sh;;
    4) read -r -p "Backup-Datei: " b; /usr/local/bin/restore_vpn.sh "$b";;
    5) ${EDITOR:-vi} "$GEO_BLACKLIST_FILE"; safe_systemctl restart nftables;;
    6) ${EDITOR:-vi} "$MANUAL_BLACKLIST_FILE"; safe_systemctl restart AdGuardHome;;
    7) safe_systemctl restart nftables nginx; configure_tc; echo "Konfig neu geladen";;
    8) exit 0;;
    *) echo "Ungültig"; sleep 1;;
  esac
  read -n1 -r -p "Drücke eine Taste..." _
  show_menu
}

# Start
show_menu
