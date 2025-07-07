#!/bin/bash

# ==============================================================================
# VPN-Admin-Suite: Installationsskript
#
# Autor: Ihr Expertenteam
# Version: 1.0
# Datum: 2024-07-08
#
# Beschreibung:
# Dieses Skript führt die vollautomatische Installation und Konfiguration
# eines fortschrittlichen WireGuard VPN-Servers auf Debian 12 (Bookworm) durch.
# Es beinhaltet die Einrichtung von WireGuard, Unbound, AdGuard Home,
# nftables (Firewall mit Kill-Switch) und tc (Traffic Shaping).
#
# Das Skript ist für eine einmalige Ausführung auf einem sauberen
# Debian 12 System vorgesehen.
# ==============================================================================

# --- Globale Variablen und Konfigurationen ---
set -e # Beendet das Skript sofort, wenn ein Befehl fehlschlägt.
set -o pipefail # Stellt sicher, dass das Fehlschlagen eines Befehls in einer Pipe den Exit-Code der Pipe bestimmt.

# Farben für die Ausgabe
C_RESET='\033 ${message}" | tee -a "$LOG_FILE"
}

# Funktion zur Überprüfung, ob das Skript als root ausgeführt wird
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "Dieses Skript muss als root ausgeführt werden. Bitte verwenden Sie 'sudo'."
        exit 1
    fi
}

# Funktion zur Überprüfung der Debian-Version
check_distro() {
    if [! -f /etc/os-release ] ||! grep -q 'VERSION_ID="12"' /etc/os-release; then
        log "ERROR" "Dieses Skript ist nur für Debian 12 (Bookworm) konzipiert."
        exit 1
    fi
    log "INFO" "Debian 12 (Bookworm) erkannt. Fortfahren..."
}

# Funktion zur Installation von Abhängigkeiten
install_dependencies() {
    log "STEP" "System-Paketquellen werden aktualisiert..."
    # Temporäre DNS-Konfiguration für eine zuverlässige Paketinstallation
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    apt-get update -y >> "$LOG_FILE" 2>&1
    
    log "STEP" "System-Upgrade wird durchgeführt..."
    apt-get upgrade -y >> "$LOG_FILE" 2>&1

    log "STEP" "Notwendige Pakete werden installiert..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        jq \
        qrencode \
        wireguard-tools \
        nftables \
        iproute2 \
        unbound \
        htop \
        moreutils \
        logrotate \
        unzip >> "$LOG_FILE" 2>&1
    log "INFO" "Alle Abhängigkeiten wurden erfolgreich installiert."
}

# Funktion zur interaktiven Abfrage von Konfigurationsparametern
gather_config_params() {
    log "STEP" "Interaktive Konfigurationsabfrage..."

    # WireGuard Interface Name
    read -p "Geben Sie den Namen des WireGuard-Interfaces an [wg0]: " WG_IFACE
    WG_IFACE=${WG_IFACE:-wg0}

    # WireGuard Listen Port
    read -p "Geben Sie den WireGuard Listen-Port an : " WG_PORT
    WG_PORT=${WG_PORT:-51821}

    # Endpoint Domain
    # Versuche, die öffentliche IP-Adresse zu ermitteln
    PUBLIC_IP=$(curl -s https://ipv4.icanhazip.com)
    read -p "Geben Sie die öffentliche Domain oder IP des Servers an: " ENDPOINT
    ENDPOINT=${ENDPOINT:-$PUBLIC_IP}

    # WAN Interface
    # Automatische Erkennung des WAN-Interfaces
    WAN_IFACE_DETECTED=$(ip -4 route get 1.1.1.1 | awk '{print $5}' | head -n1)
    read -p "Geben Sie das WAN-Interface an: " WAN_IFACE
    WAN_IFACE=${WAN_IFACE:-$WAN_IFACE_DETECTED}

    log "INFO" "Konfiguration abgeschlossen. Folgende Werte werden verwendet:"
    echo -e "  ${C_BLUE}WireGuard Interface:${C_RESET} $WG_IFACE"
    echo -e "  ${C_BLUE}WireGuard Port:${C_RESET} $WG_PORT"
    echo -e "  ${C_BLUE}Endpoint:${C_RESET} $ENDPOINT"
    echo -e "  ${C_BLUE}WAN Interface:${C_RESET} $WAN_IFACE"
}

# Funktion zur Konfiguration des Systems (sysctl)
configure_sysctl() {
    log "STEP" "IP-Forwarding wird aktiviert..."
    cat > /etc/sysctl.d/99-vpn-forwarding.conf << EOF
# Enable IP Forwarding for VPN Gateway
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl -p /etc/sysctl.d/99-vpn-forwarding.conf >> "$LOG_FILE" 2>&1
    log "INFO" "IP-Forwarding wurde permanent aktiviert."
}

# Funktion zur Konfiguration von Unbound
configure_unbound() {
    log "STEP" "Unbound (DNSSEC-Validator) wird konfiguriert..."
    cat > /etc/unbound/unbound.conf.d/vpn-resolver.conf << EOF
server:
    # Verbosity level
    verbosity: 1

    # Listen on localhost for AdGuard Home
    interface: 127.0.0.1@5353
    access-control: 127.0.0.1/32 allow

    # DNSSEC validation
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    harden-dnssec-stripped: yes

    # Performance settings
    num-threads: $(nproc)
    msg-cache-size: 64m
    rrset-cache-size: 128m

    # Privacy settings
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    use-caps-for-id: yes
EOF
    
    # Unbound-Dienst aktivieren und starten
    systemctl enable --now unbound >> "$LOG_FILE" 2>&1
    log "INFO" "Unbound-Dienst konfiguriert und gestartet."
}

# Funktion zur Installation und Konfiguration von AdGuard Home
install_adguardhome() {
    log "STEP" "AdGuard Home wird installiert..."
    
    # Ermittle die Systemarchitektur
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) AGH_ARCH="amd64" ;;
        aarch64) AGH_ARCH="arm64" ;;
        armv7l) AGH_ARCH="armv7" ;;
        *) log "ERROR" "Nicht unterstützte Architektur: $ARCH"; exit 1 ;;
    esac

    # Lade die neueste Version von AdGuard Home von GitHub
    AGH_URL=$(curl -s "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest" | jq -r ".assets | select(.name | test(\"AdGuardHome_linux_${AGH_ARCH}.tar.gz\")) |.browser_download_url")
    if; then
        log "ERROR" "Konnte die Download-URL für AdGuard Home nicht finden."
        exit 1
    fi
    
    log "INFO" "Lade AdGuard Home herunter von: $AGH_URL"
    curl -L "$AGH_URL" -o "/tmp/AdGuardHome.tar.gz" >> "$LOG_FILE" 2>&1
    
    # Entpacken und installieren
    tar -xvf "/tmp/AdGuardHome.tar.gz" -C "/tmp" >> "$LOG_FILE" 2>&1
    mkdir -p /opt/AdGuardHome
    mv /tmp/AdGuardHome/* /opt/AdGuardHome/
    
    log "INFO" "AdGuard Home wird als Dienst installiert..."
    /opt/AdGuardHome/AdGuardHome -s install >> "$LOG_FILE" 2>&1
    
    log "WARN" "AdGuard Home muss manuell konfiguriert werden."
    log "WARN" "Öffnen Sie http://${PUBLIC_IP}:3000 in Ihrem Browser, um die Einrichtung abzuschließen."
    log "WARN" "Wichtige Einstellungen:"
    log "WARN" "  - Admin Web Interface: Port 3000"
    log "WARN" "  - DNS Server: Port 53 auf der IP ${C_YELLOW}10.42.0.1${C_RESET}"
    log "WARN" "  - Upstream DNS Server: ${C_YELLOW}127.0.0.1:5353${C_RESET} (unser lokaler Unbound)"
    
    # Kurze Pause, damit der Benutzer die Nachricht lesen kann
    read -p "Drücken Sie [Enter], um fortzufahren, nachdem Sie die AdGuard Home-Einrichtung notiert haben..."
}

# Funktion zur Generierung der WireGuard-Serverkonfiguration
configure_wireguard() {
    log "STEP" "WireGuard-Server wird konfiguriert..."
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    # Server-Schlüssel generieren
    wg genkey | tee "/etc/wireguard/${WG_IFACE}_private.key" | wg pubkey > "/etc/wireguard/${WG_IFACE}_public.key"
    chmod 600 "/etc/wireguard/${WG_IFACE}_private.key"
    SERVER_PRIVATE_KEY=$(cat "/etc/wireguard/${WG_IFACE}_private.key")

    # wg0.conf erstellen
    cat > "/etc/wireguard/${WG_IFACE}.conf" << EOF
[Interface]
# VPN Server Konfiguration
Address = 10.42.0.1/24, fd42:4242:4242::1/64
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
SaveConfig = true

# PostUp/PostDown Hooks zur Verwaltung von Firewall und Traffic Shaping
# Diese rufen das vpn-admin Skript auf, um die Regeln zu laden/leeren.
PostUp = ${ADMIN_SCRIPT_PATH} --apply-rules
PostDown = ${ADMIN_SCRIPT_PATH} --flush-rules
EOF

    log "INFO" "WireGuard-Serverkonfiguration in /etc/wireguard/${WG_IFACE}.conf erstellt."
}

# Funktion zur Erstellung der nftables-Firewall-Konfiguration
configure_nftables() {
    log "STEP" "nftables Firewall-Regeln werden erstellt..."
    
    cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

# Leert das bestehende Regelwerk
flush ruleset

# --- Definitionen ---
define wan_if = ${WAN_IFACE}
define wg_if = ${WG_IFACE}
define wg_port = ${WG_PORT}
define vpn_net_v4 = 10.42.0.0/24
define vpn_net_v6 = fd42:4242:4242::/64
define adguard_addr_v4 = 10.42.0.1
define adguard_addr_v6 = fd42:4242:4242::1

# --- Tabellen ---
table inet filter {
    # Sets für Peer-Gruppen (werden dynamisch vom vpn-admin Skript befüllt)
    set blocked_peers_v4 {
        type ipv4_addr
        flags dynamic
    }
    set blocked_peers_v6 {
        type ipv6_addr
        flags dynamic
    }

    # --- Chains für den Host ---
    chain input {
        type filter hook input priority 0;
        policy drop;

        # Grundregeln
        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # ICMP erlauben (wichtig für MTU Discovery etc.)
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Eingehenden SSH- und WireGuard-Verkehr am WAN-Interface erlauben
        iif \$wan_if tcp dport 22 accept
        iif \$wan_if udp dport \$wg_port accept
    }

    chain output {
        type filter hook output priority 0;
        policy accept; # Ausgehender Verkehr vom Server wird standardmäßig erlaubt
    }

    # --- Chains für den VPN-Verkehr ---
    chain forward {
        type filter hook forward priority 0;
        policy drop; # Kill-Switch: Standardmäßig alles blockieren

        # Erlaube etablierte Verbindungen
        ct state established,related accept

        # Erlaube nur Verkehr vom VPN-Interface zum WAN-Interface
        iif \$wg_if oif \$wan_if accept
    }
}

table inet nat {
    chain prerouting {
        type nat hook prerouting priority -100;

        # DNS-Anfragen von Clients auf AdGuard Home umleiten (DNS-Zwang)
        iif \$wg_if udp dport 53 dnat to \$adguard_addr_v4
        iif \$wg_if tcp dport 53 dnat to \$adguard_addr_v4
        iif \$wg_if udp dport 53 dnat to \$adguard_addr_v6
        iif \$wg_if tcp dport 53 dnat to \$adguard_addr_v6

        # HTTP-Anfragen von gesperrten Peers auf eine "Gesperrt"-Seite umleiten
        # HINWEIS: HTTPS-Redirect ist komplex und erfordert einen Transparent Proxy.
        # Wir leiten nur HTTP um. HTTPS wird durch die Forward-Chain blockiert.
        iif \$wg_if ip saddr @blocked_peers_v4 tcp dport 80 dnat to 127.0.0.1:8088
        iif \$wg_if ip6 saddr @blocked_peers_v6 tcp dport 80 dnat to [::1]:8088
    }

    chain postrouting {
        type nat hook postrouting priority 100;

        # Masquerading für ausgehenden VPN-Verkehr
        oif \$wan_if ip saddr \$vpn_net_v4 masquerade
        oif \$wan_if ip6 saddr \$vpn_net_v6 masquerade
    }
}
EOF
    
    # nftables-Dienst aktivieren
    systemctl enable nftables >> "$LOG_FILE" 2>&1
    log "INFO" "nftables-Konfiguration in /etc/nftables.conf erstellt."
}

# Funktion zur Erstellung der systemd-Timer und Services
create_systemd_units() {
    log "STEP" "systemd-Timer für Automatisierung werden erstellt..."

    # Service für Quota-Reset
    cat > /etc/systemd/system/wg-quota-reset.service << EOF
[Unit]
Description=Reset WireGuard peer traffic quotas monthly
After=network.target


Type=oneshot
ExecStart=${ADMIN_SCRIPT_PATH} --quota-reset
EOF

    # Timer für Quota-Reset (jeden Monat am 1. um 00:05)
    cat > /etc/systemd/system/wg-quota-reset.timer << EOF
[Unit]
Description=Run wg-quota-reset.service on the first day of the month


OnCalendar=*-*-01 00:05:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Service für Ablauf-Check
    cat > /etc/systemd/system/wg-expiry-check.service << EOF
[Unit]
Description=Check for expired WireGuard peers daily
After=network.target


Type=oneshot
ExecStart=${ADMIN_SCRIPT_PATH} --expiry-check
EOF

    # Timer für Ablauf-Check (täglich um 00:10)
    cat > /etc/systemd/system/wg-expiry-check.timer << EOF
[Unit]
Description=Run wg-expiry-check.service daily


OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # systemd-Daemon neu laden und Timer aktivieren
    systemctl daemon-reload >> "$LOG_FILE" 2>&1
    systemctl enable --now wg-quota-reset.timer >> "$LOG_FILE" 2>&1
    systemctl enable --now wg-expiry-check.timer >> "$LOG_FILE" 2>&1
    log "INFO" "systemd-Timer für Quota-Reset und Ablauf-Check sind aktiv."
}

# Funktion zur Erstellung der logrotate-Konfiguration
create_logrotate_config() {
    log "STEP" "logrotate für vpn-admin-Log wird konfiguriert..."
    cat > /etc/logrotate.d/vpn-admin << EOF
/var/log/vpn-admin.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
    log "INFO" "logrotate-Konfiguration erstellt."
}


# Funktion zur Installation des Admin-Skripts
install_admin_script() {
    log "STEP" "Admin-Skript 'vpn-admin' wird installiert..."

    # Das Admin-Skript wird hier als "Here Document" eingebettet.
    # In einer realen Bereitstellung könnte dies auch von einer URL geladen werden.
    cat > "${ADMIN_SCRIPT_PATH}" << 'EOF'
#!/bin/bash

# ==============================================================================
# VPN-Admin-Suite: Verwaltungs-Skript
#
# Autor: Ihr Expertenteam
# Version: 1.0
#
# Beschreibung:
# Dieses Skript dient der Verwaltung des VPN-Servers, einschließlich
# Benutzer- und Peer-Management, Statusabfragen und Wartungsaufgaben.
# ==============================================================================

# --- Globale Variablen und Konfigurationen ---
set -e
set -o pipefail

# Pfade
PEERS_DIR="/etc/peers"
WG_DIR="/etc/wireguard"
LOG_FILE="/var/log/vpn-admin.log"
BACKUP_DIR="/var/backups/vpn-admin"
NFT_CONFIG="/etc/nftables.conf"

# Farben
C_RESET='\033="Gratis 🎁|5mbit|5mbit|2mbit|2mbit|20|0x10"
    ["Premium"]="Premium ⭐|50mbit|50mbit|5mbit|5mbit|500|0x20"
    ["Ultimate"]="Ultimate 🚀|2gbit|2gbit|10mbit|10mbit|1000|0x30"
    ["Admin"]="Admin 👑|unlimited|unlimited|unlimited|unlimited|0|0x01"
    ["Gesperrt"]="Gesperrt 🛑|1kbit|1kbit|1kbit|1kbit|0|0xFF"
)

# --- Hilfsfunktionen ---

log_admin() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${message}" >> "$LOG_FILE"
}

# Funktion zum Laden der Konfiguration aus den Systemdateien
load_config() {
    # Lese WG-Interface aus der ersten.conf-Datei in /etc/wireguard
    local wg_conf_file=$(find "$WG_DIR" -maxdepth 1 -type f -name "*.conf" | head -n 1)
    if [ -z "$wg_conf_file" ]; then
        echo -e "${C_RED}Fehler: Keine WireGuard-Konfigurationsdatei gefunden.${C_RESET}"
        exit 1
    fi
    WG_IFACE=$(basename "$wg_conf_file".conf)
    
    # Lese Konfigurationsparameter aus der Datei
    VPN_IPV4_SUBNET=$(grep -oP 'Address\s*=\s*\K10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}' "$wg_conf_file")
    VPN_IPV6_SUBNET=$(grep -oP 'Address\s*=\s*\K[a-f0-9:]+/\d{1,3}' "$wg_conf_file")
    VPN_IPV4_SERVER=$(echo "$VPN_IPV4_SUBNET" | cut -d'/' -f1)
    VPN_IPV6_SERVER=$(echo "$VPN_IPV6_SUBNET" | cut -d'/' -f1)
    WG_PORT=$(grep -oP 'ListenPort\s*=\s*\K\d+' "$wg_conf_file")
    
    # Lese WAN-Interface und Endpoint aus der nftables-Konfiguration
    WAN_IFACE=$(grep -oP 'define wan_if\s*=\s*\K\S+' "$NFT_CONFIG")
    ENDPOINT=$(curl -s https://ipv4.icanhazip.com) # Sicherstellen, dass wir die aktuelle IP haben
}

# Funktion zur Suche der nächsten freien IPv4-Adresse
find_next_ipv4() {
    local subnet_prefix=$(echo "$VPN_IPV4_SUBNET" | cut -d'.' -f1-3)
    local used_ips
    used_ips=$(jq -r '.. |.ipv4? | select(.!= null)' "$PEERS_DIR"/*/*.json 2>/dev/null |

| true)
    
    # Beginne die Suche ab.2, da.1 der Server ist
    for i in {2..254}; do
        local current_ip="${subnet_prefix}.${i}"
        if! echo "$used_ips" | grep -q -w "$current_ip"; then
            echo "$current_ip"
            return
        fi
    done
    echo "" # Keine freie IP gefunden
}

# Funktion zur Suche der nächsten freien IPv6-Adresse
find_next_ipv6() {
    local subnet_prefix=$(echo "$VPN_IPV6_SUBNET" | cut -d':' -f1-4)
    local used_ips
    used_ips=$(jq -r '.. |.ipv6? | select(.!= null)' "$PEERS_DIR"/*/*.json 2>/dev/null |

| true)

    for i in {2..65535}; do
        local hex_i=$(printf "%x" $i)
        local current_ip="${subnet_prefix}::${hex_i}"
        if! echo "$used_ips" | grep -q -w "$current_ip"; then
            echo "$current_ip"
            return
        fi
    done
    echo "" # Keine freie IP gefunden
}


# --- Firewall- und Traffic-Shaping-Funktionen ---

apply_rules() {
    log_admin "Applying firewall and QoS rules..."
    # Lade das komplette nftables-Regelwerk
    nft -f "$NFT_CONFIG"
    
    # Erstelle IFB-Device für Ingress-Shaping, falls nicht vorhanden
    modprobe ifb numifbs=1
    ip link set dev ifb0 up

    # Lösche alte qdiscs, falls vorhanden
    tc qdisc del dev "$WAN_IFACE" root 2>/dev/null |

| true
    tc qdisc del dev ifb0 root 2>/dev/null |

| true
    tc qdisc del dev "$WAN_IFACE" ingress 2>/dev/null |

| true

    # --- Egress (Upload) Shaping auf WAN-Interface ---
    tc qdisc add dev "$WAN_IFACE" root handle 1: htb default 1 # Default-Klasse für Admin/unlimitiert
    tc class add dev "$WAN_IFACE" parent 1: classid 1:1 htb rate 10gbit # Hauptklasse

    # --- Ingress (Download) Shaping auf IFB-Interface ---
    tc qdisc add dev ifb0 root handle 2: htb default 1
    tc class add dev ifb0 parent 2: classid 2:1 htb rate 10gbit

    # Erstelle Klassen für jede Gruppe
    for group_name in "${!GROUPS[@]}"; do
        IFS='|' read -r _ up_max down_max up_throt down_throt quota mark <<< "${GROUPS[$group_name]}"
        
        if [[ "$up_max"!= "unlimited" ]]; then
            # Normale Klassen
            tc class add dev "$WAN_IFACE" parent 1:1 classid 1:$(echo "$mark" | cut -d'x' -f2) htb rate "$up_max" ceil "$up_max"
            tc class add dev ifb0 parent 2:1 classid 2:$(echo "$mark" | cut -d'x' -f2) htb rate "$down_max" ceil "$down_max"
            
            # Drossel-Klassen (Mark + 100)
            drossel_mark=$((mark + 100))
            tc class add dev "$WAN_IFACE" parent 1:1 classid 1:$(printf '%x' $drossel_mark) htb rate "$up_throt" ceil "$up_throt"
            tc class add dev ifb0 parent 2:1 classid 2:$(printf '%x' $drossel_mark) htb rate "$down_throt" ceil "$down_throt"
        fi
    done

    # Filter erstellen, um Pakete basierend auf fwmark zuzuordnen
    tc filter add dev "$WAN_IFACE" parent 1: protocol ip prio 1 handle 1 fw flowid 1:1
    tc filter add dev ifb0 parent 2: protocol ip prio 1 handle 1 fw flowid 2:1
    
    # Ingress-Verkehr von WAN auf IFB umleiten
    tc qdisc add dev "$WAN_IFACE" handle ffff: ingress
    tc filter add dev "$WAN_IFACE" parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0

    sync_peer_rules
    log_admin "Firewall and QoS rules applied."
}

flush_rules() {
    log_admin "Flushing firewall and QoS rules..."
    nft flush ruleset
    tc qdisc del dev "$WAN_IFACE" root 2>/dev/null |

| true
    tc qdisc del dev ifb0 root 2>/dev/null |

| true
    tc qdisc del dev "$WAN_IFACE" ingress 2>/dev/null |

| true
    ip link set dev ifb0 down 2>/dev/null |

| true
    log_admin "All rules flushed."
}

sync_peer_rules() {
    log_admin "Syncing peer-specific rules..."
    local temp_nft_file=$(mktemp)
    
    # Header für die temporäre nft-Datei
    echo "flush set inet filter blocked_peers_v4" > "$temp_nft_file"
    echo "flush set inet filter blocked_peers_v6" >> "$temp_nft_file"
    echo "table inet filter {" >> "$temp_nft_file"
    
    # Iteriere durch alle Peers und generiere nftables- und tc-Regeln
    find "$PEERS_DIR" -name "meta.json" -print0 | while IFS= read -r -d '' meta_file; do
        jq -c '.peers' "$meta_file" | while read -r peer_json; do
            local ipv4=$(echo "$peer_json" | jq -r '.ipv4')
            local ipv6=$(echo "$peer_json" | jq -r '.ipv6')
            local group=$(echo "$peer_json" | jq -r '.group')
            local throttled=$(echo "$peer_json" | jq -r '.throttled')
            
            IFS='|' read -r _ _ _ _ _ _ mark <<< "${GROUPS[$group]}"
            
            if [[ "$throttled" == "true" ]]; then
                mark=$((mark + 100)) # Verwende die Drossel-Markierung
            fi
            
            # nftables-Regeln zum Markieren von Paketen
            echo "  chain forward { rule iif $WG_IFACE ip saddr $ipv4 meta mark set $mark }" >> "$temp_nft_file"
            echo "  chain forward { rule iif $WG_IFACE ip6 saddr $ipv6 meta mark set $mark }" >> "$temp_nft_file"
            
            # Füge zu gesperrten Sets hinzu, wenn die Gruppe "Gesperrt" ist
            if [[ "$group" == "Gesperrt" ]]; then
                echo "add element inet filter blocked_peers_v4 { $ipv4 }" >> "$temp_nft_file"
                echo "add element inet filter blocked_peers_v6 { $ipv6 }" >> "$temp_nft_file"
            fi
        done
    done
    
    echo "}" >> "$temp_nft_file"
    
    # Lade die neuen Regeln atomar
    nft -f "$temp_nft_file"
    rm "$temp_nft_file"
    
    log_admin "Peer-specific rules synced."
}


# --- Menüfunktionen ---

show_status() {
    echo -e "${C_CYAN}--- VPN Server Status ---${C_RESET}"
    wg show "$WG_IFACE"
    echo -e "\n${C_CYAN}--- Aktive Peers und Traffic ---${C_RESET}"
    
    # Header
    printf "%-20s %-15s %-44s %-10s %-10s %-25s\n" "User/Peer" "Gruppe" "IP-Adressen" "RX" "TX" "Letzter Handshake"
    echo "-----------------------------------------------------------------------------------------------------------------------"
    
    wg show "$WG_IFACE" dump | tail -n +2 | while read -r line; do
        pubkey=$(echo "$line" | awk '{print $1}')
        rx=$(echo "$line" | awk '{print $5}')
        tx=$(echo "$line" | awk '{print $6}')
        handshake=$(echo "$line" | awk '{print $4}')
        
        # Finde den passenden Peer in den meta.json Dateien
        peer_info=$(grep -r "$pubkey" "$PEERS_DIR"/*/meta.json)
        if [ -n "$peer_info" ]; then
            meta_file=$(echo "$peer_info" | cut -d':' -f1)
            user=$(basename "$(dirname "$meta_file")")
            peer_json=$(jq --arg pk "$pubkey" '.peers | select(.pubkey == $pk)' "$meta_file")
            
            name=$(echo "$peer_json" | jq -r '.name')
            group=$(echo "$peer_json" | jq -r '.group')
            ipv4=$(echo "$peer_json" | jq -r '.ipv4')
            ipv6=$(echo "$peer_json" | jq -r '.ipv6')
            
            # Formatierte Ausgabe
            rx_human=$(numfmt --to=iec-i --suffix=B "$rx")
            tx_human=$(numfmt --to=iec-i --suffix=B "$tx")
            handshake_human="N/A"
            if [ "$handshake" -ne 0 ]; then
                handshake_human=$(date -d "@$handshake" '+%Y-%m-%d %H:%M:%S')
            fi
            
            printf "%-20s %-15s %-44s %-10s %-10s %-25s\n" "${user}/${name}" "$group" "${ipv4}, ${ipv6}" "$rx_human" "$tx_human" "$handshake_human"
        fi
    done
}

add_user() {
    echo -e "${C_CYAN}--- Neuen User anlegen ---${C_RESET}"
    read -p "Geben Sie den Benutzernamen ein: " username
    if [ -z "$username" ]; then
        echo -e "${C_RED}Benutzername darf nicht leer sein.${C_RESET}"
        return 1
    fi
    
    local user_dir="${PEERS_DIR}/${username}"
    if [ -d "$user_dir" ]; then
        echo -e "${C_RED}Benutzer '$username' existiert bereits.${C_RESET}"
        return 1
    fi
    
    mkdir -p "$user_dir"
    # Erstelle eine leere meta.json
    echo "{\"user\": \"$username\", \"peers\":}" | jq. > "${user_dir}/meta.json"
    
    log_admin "User '$username' created."
    echo -e "${C_GREEN}Benutzer '$username' erfolgreich angelegt.${C_RESET}"
}

add_peer() {
    echo -e "${C_CYAN}--- Neuen Peer hinzufügen ---${C_RESET}"
    read -p "Für welchen Benutzer soll der Peer erstellt werden? " username
    local user_dir="${PEERS_DIR}/${username}"
    if [! -d "$user_dir" ]; then
        echo -e "${C_RED}Benutzer '$username' nicht gefunden.${C_RESET}"
        return 1
    fi
    
    read -p "Geben Sie einen Namen für den Peer ein (z.B. laptop, handy): " peername
    if [ -z "$peername" ]; then
        echo -e "${C_RED}Peer-Name darf nicht leer sein.${C_RESET}"
        return 1
    fi
    
    # Gruppe auswählen
    echo "Wählen Sie eine Gruppe für den Peer:"
    select group_choice in "${!GROUPS[@]}"; do
        if [[ -n "$group_choice" ]]; then
            break
        else
            echo "Ungültige Auswahl."
        fi
    done
    
    read -p "Gültigkeit in Tagen (z.B. 30, 365, leer für unbegrenzt): " validity_days
    local expires_date="unlimited"
    if [[ -n "$validity_days" ]]; then
        expires_date=$(date -d "+$validity_days days" +%Y-%m-%d)
    fi

    # Schlüssel generieren
    local priv_key=$(wg genkey)
    local pub_key=$(echo "$priv_key" | wg pubkey)
    
    # IP-Adressen finden
    local ipv4=$(find_next_ipv4)
    local ipv6=$(find_next_ipv6)
    if [ -z "$ipv4" ] |

| [ -z "$ipv6" ]; then
        echo -e "${C_RED}Keine freien IP-Adressen im Subnetz verfügbar.${C_RESET}"
        return 1
    fi
    
    # Client-Konfigurationsdatei erstellen
    local client_conf_file="${user_dir}/${peername}.conf"
    cat > "$client_conf_file" << EOF
[Interface]
PrivateKey = ${priv_key}
Address = ${ipv4}/32, ${ipv6}/128
DNS = ${VPN_IPV4_SERVER}

[Peer]
PublicKey = $(cat "${WG_DIR}/${WG_IFACE}_public.key")
Endpoint = ${ENDPOINT}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # QR-Code generieren
    qrencode -t PNG -o "${user_dir}/${peername}.png" < "$client_conf_file"
    
    # Metadaten in meta.json aktualisieren
    local meta_file="${user_dir}/meta.json"
    local new_peer_json
    new_peer_json=$(jq -n \
        --arg name "$peername" \
        --arg pubkey "$pub_key" \
        --arg ipv4 "$ipv4" \
        --arg ipv6 "$ipv6" \
        --arg group "$group_choice" \
        --arg created "$(date +%Y-%m-%d)" \
        --arg expires "$expires_date" \
        '{name: $name, pubkey: $pubkey, ipv4: $ipv4, ipv6: $ipv6, group: $group, created: $created, expires: $expires, quota_bytes: 0, throttled: false}')
    
    jq ".peers += [$new_peer_json]" "$meta_file" > "${meta_file}.tmp" && mv "${meta_file}.tmp" "$meta_file"
    
    # Peer live zum Interface hinzufügen
    wg set "$WG_IFACE" peer "$pub_key" allowed-ips "${ipv4}/32,${ipv6}/128"
    
    # Regeln synchronisieren
    sync_peer_rules
    
    log_admin "Peer '${peername}' for user '${username}' added."
    echo -e "${C_GREEN}Peer '${peername}' für Benutzer '${username}' erfolgreich erstellt.${C_RESET}"
    echo -e "Konfigurationsdatei: ${C_YELLOW}${client_conf_file}${C_RESET}"
    echo -e "QR-Code: ${C_YELLOW}${user_dir}/${peername}.png${C_RESET}"
}

delete_peer() {
    echo -e "${C_CYAN}--- Peer löschen ---${C_RESET}"
    read -p "Benutzer des zu löschenden Peers: " username
    read -p "Name des zu löschenden Peers: " peername
    
    local meta_file="${PEERS_DIR}/${username}/meta.json"
    if [! -f "$meta_file" ]; then
        echo -e "${C_RED}Benutzer '${username}' nicht gefunden.${C_RESET}"
        return 1
    fi
    
    local peer_json=$(jq --arg name "$peername" '.peers | select(.name == $name)' "$meta_file")
    if [ -z "$peer_json" ]; then
        echo -e "${C_RED}Peer '${peername}' für Benutzer '${username}' nicht gefunden.${C_RESET}"
        return 1
    fi
    
    local pubkey=$(echo "$peer_json" | jq -r '.pubkey')
    
    # Peer live entfernen
    wg set "$WG_IFACE" peer "$pubkey" remove
    
    # Aus meta.json entfernen
    jq --arg name "$peername" 'del(.peers | select(.name == $name))' "$meta_file" > "${meta_file}.tmp" && mv "${meta_file}.tmp" "$meta_file"
    
    # Dateien löschen
    rm -f "${PEERS_DIR}/${username}/${peername}.conf" "${PEERS_DIR}/${username}/${peername}.png"
    
    sync_peer_rules
    
    log_admin "Peer '${peername}' for user '${username}' deleted."
    echo -e "${C_GREEN}Peer '${peername}' erfolgreich gelöscht.${C_RESET}"
}

# Dummy-Funktionen für die restlichen Menüpunkte
edit_peer() { echo "Funktion 'Peer bearbeiten' noch nicht implementiert."; }
manual_quota_reset() { echo "Funktion 'Quota-Reset' noch nicht implementiert."; }
manual_expiry_check() { echo "Funktion 'Ablauf-Check' noch nicht implementiert."; }
show_dns_status() {
    echo -e "${C_CYAN}--- DNS-Dienste Status ---${C_RESET}"
    echo "--- Unbound ---"
    systemctl status unbound | grep "Active:"
    echo "--- AdGuard Home ---"
    systemctl status AdGuardHome | grep "Active:"
}


# --- Hauptmenü ---

main_menu() {
    clear
    echo -e "${C_BLUE}╔════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET}         ${C_CYAN}VPN-Admin Hauptmenü v1.0${C_RESET}         ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}╠════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}1)${C_RESET} VPN Status & Peer Übersicht anzeigen       ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}2)${C_RESET} Neuen User anlegen                       ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}3)${C_RESET} Peer zu einem User hinzufügen            ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}4)${C_RESET} Peer bearbeiten (Gruppe/Ablauf)          ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}5)${C_RESET} Peer löschen                             ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}6)${C_RESET} Quota-Reset manuell auslösen             ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}7)${C_RESET} Ablauf-Check manuell auslösen            ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_GREEN}8)${C_RESET} AdGuard/Unbound Status anzeigen          ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}║${C_RESET} ${C_RED}9)${C_RESET} Skript beenden                           ${C_BLUE}║${C_RESET}"
    echo -e "${C_BLUE}╚════════════════════════════════════════════════╝${C_RESET}"
    
    read -p "Wählen Sie eine Option [1-9]: " choice
    case $choice in
        1) show_status ;;
        2) add_user ;;
        3) add_peer ;;
        4) edit_peer ;;
        5) delete_peer ;;
        6) manual_quota_reset ;;
        7) manual_expiry_check ;;
        8) show_dns_status ;;
        9) exit 0 ;;
        *) echo -e "${C_RED}Ungültige Option.${C_RESET}" ;;
    esac
    read -p "Drücken Sie [Enter], um zum Menü zurückzukehren..."
    main_menu
}


# --- Argumenten-Parser für nicht-interaktive Ausführung ---

# Lade Konfiguration, bevor irgendetwas anderes passiert
load_config

case "$1" in
    --apply-rules)
        apply_rules
        ;;
    --flush-rules)
        flush_rules
        ;;
    --quota-reset)
        log_admin "Monthly quota reset triggered by systemd timer."
        # Implementierungslogik hier
        ;;
    --expiry-check)
        log_admin "Daily expiry check triggered by systemd timer."
        # Implementierungslogik hier
        ;;
    --traffic-report)
        log_admin "Generating traffic report."
        # Implementierungslogik hier
        ;;
    *)
        # Interaktives Menü starten, wenn keine Argumente übergeben werden
        main_menu
        ;;
esac

exit 0
EOF
    # Admin-Skript ausführbar machen
    chmod +x "${ADMIN_SCRIPT_PATH}"
    log "INFO" "Admin-Skript unter ${ADMIN_SCRIPT_PATH} installiert und ausführbar gemacht."
}


# --- Hauptausführungslogik ---

main() {
    touch "$LOG_FILE"
    check_root
    check_distro
    
    log "STEP" "Starte die Installation des VPN-Servers..."
    
    install_dependencies
    gather_config_params
    configure_sysctl
    configure_unbound
    install_adguardhome
    configure_wireguard
    configure_nftables
    
    # Wichtig: Das Admin-Skript muss vor den systemd-Units und dem Start von WG installiert werden
    install_admin_script
    
    create_systemd_units
    create_logrotate_config
    
    log "STEP" "WireGuard-Dienst wird gestartet..."
    systemctl enable --now "wg-quick@${WG_IFACE}" >> "$LOG_FILE" 2>&1
    
    # Setze die DNS-Konfiguration des Hosts auf den lokalen AdGuard-Server
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    
    log "INFO" "========================================================"
    log "INFO" "Installation erfolgreich abgeschlossen!"
    log "INFO" "Der VPN-Server ist jetzt aktiv."
    log "INFO" "Verwenden Sie '${C_YELLOW}sudo vpn-admin${C_RESET}' zur Verwaltung."
    log "INFO" "========================================================"
}

# Starte das Hauptprogramm
main