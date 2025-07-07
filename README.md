## Konzept für das VPN-Admin-Bash-Skript auf Debian 12 (Bookworm)


Dieses Dokument beschreibt im Detail die Architektur und alle funktionalen Anforderungen für ein umfangreiches Bash-Skript („vpn-admin“), das folgende Hauptfunktionen abdeckt:


1. **Basis-System & Vorbereitung**


   * **Betriebssystem**: Debian 12 (Codename „Bookworm").

   * **Paketquellen & Updates**:


     * apt update && apt upgrade -y

     * Sicherstellen, dass /etc/resolv.conf zunächst auf einen funktionierenden DNS (z. B. 8.8.8.8 oder Unbound) zeigt, damit apt zuverlässig Pakete ziehen kann.

   * **Installation notwendiger Basis-Tools**:


     * curl für Downloads und API-Abfragen.

     * jq für JSON-Verarbeitung.

     * qrencode zur Erzeugung von QR-Codes (PNG).

     * wireguard-tools für Key-Generierung, wg, wg-quick.

     * nftables als modernes Paketfilter-Framework.

     * iproute2 für tc (Traffic Control).

     * unbound als DNSSEC-Validator.

     * adguardhome (optional aus offizieller Quelle oder manuelle Installation).

     * htop und Standard-Tools (bash, sed, grep, coreutils).


2. **WireGuard VPN mit Dual-Stack & Kill-Switch**


   * **Parameter-Abfrage** (interaktiv):


     1. **Interface-Name** (Default: wg0, editierbar).

     2. **Listener-Port** (Default: 51821, editierbar).

     3. **Endpoint-Domain** (z. B. vpn001.domain.de): Abfrage + Bestätigung/Korrektur.

     4. **WAN-Interface** (z. B. eth0, ens5): Automatische Erkennung mit ip route get 1.1.1.1, anschließend interaktive Korrektur/Bestätigung.

   * **Netzwerk-Subnetze**:


     * IPv4-Subnetz Clients: 10.42.0.0/24 (Server = 10.42.0.1).

     * IPv6-Subnetz Clients: fd42:4242:4242::/64 (Server = fd42:4242:4242::1).

   * **Server-Konfiguration**:


     * **Schlüssel**: Check/Generierung von Server-Privat/Public-Key in /etc/wireguard/.

     * **wg0.conf** erstellen mit:


       * [Interface]: Address, ListenPort, PrivateKey, PostUp/PostDown Hooks (nftables-, sysctl-Regeln).

       * Optional: SaveConfig = true.

   * **NAT & Routing via nftables**:


     * Tabelle inet nat, Chain postrouting: masquerade für IPv4.

     * IPv6-Forwarding aktivieren (sysctl net.ipv6.conf.all.forwarding=1).

   * **Kill-Switch & Leak-Protection**:


     * Default POLICY DROP in inet filter für Chain forward und output (Clients).

     * Exceptions:


       * Erlaube Verkehr über wg0.

       * Erlaube auf dem Host: LOOPBACK und Outbound über WAN-Interface für SSH, apt, DNS etc.

     * **DNS-Zwang**:  auf AdGuard umleiten 


3. **DNS-Stack**


   * **Unbound** (nur DNSSEC-Validator):


     * Konfiguration in /etc/unbound/unbound.conf.d/dnssec.conf:


       * auto-trust-anchor-file: "/var/lib/unbound/root.key"

       * do-serve-ixfr: yes, do-ip4: yes, do-ip6: yes, do-udp: yes, do-tcp: yes, harden-dnssec-stripped: yes.

     * Dienste aktivieren: systemctl enable --now unbound.

     * Sicherstellen, dass /etc/resolv.conf auf 127.0.0.1 zeigt.

   * **AdGuard Home**:


     * Installation (Deb-Paket oder GitHub-Releases), Installation in /opt/AdGuardHome oder /usr/local/AdGuardHome.

     * Autostart-Service adguardhome.service.

     * Konfiguration via Web-UI oder AdGuardHome.yaml: Upstream  (Unbound).

     * Standard-Blocklisten aktivieren (Werbung & Tracker).


4. **Firewall mit nftables**


   * **Tabellen & Chains**:


     * table inet filter → chain input, forward, output.

     * Spezielle Chains:


       * vpn-client (FORWARD-Regeln für wg0).

       * vpn-server (INPUT/OUTPUT-Regeln für Host).

       * dns-redirect (PREROUTING DNAT Port 53 → AdGuard).

       * expiry-redirect (HTTP/S Redirect für gesperrte Peers).

   * **Regelsatz**:


     1. **INPUT**:


        * Allow LOOPBACK.

        * Allow ESTABLISHED,RELATED.

        * Allow SSH und wg-Port am WAN.

     2. **OUTPUT** (Host)


        * Allow LOOPBACK.

        * Allow ESTABLISHED.

        * Allow WAN: SSH, HTTP(S), DNS.

     3. **FORWARD** (Clients)


        * Policy DROP.

        * Jump zu vpn-client:


          * Erlaube wg0 → WAN.

          * Jump zu dns-redirect für Port 53.

          * Jump zu expiry-redirect für Mark blocked (HTTP/S Redirect auf [https://meine.seite](https://meine.seite)).

   * **Marking**:


     * nftables meta mark setzen je nach Peer-Gruppe.


5. **Traffic-Shaping & Gruppen-Quotas (tc/HTB)**


   * **Gruppen-Definitionen**:


     | Gruppe      | Up/Down Max   | Volumen/Monat | Nach Verbrauch Drosselung |

     | ----------- | ------------- | ------------- | ------------------------- |

     | Gratis 🎁   | 5 Mbit/s      | 20 GB         | 2 Mbit/s                  |

     | Premium ⭐   | 50 Mbit/s     | 500 GB        | 5 Mbit/s                  |

     | Ultimate 🚀 | 2 Gbit/s      | 1000 GB       | 10 Mbit/s                 |

     | Admin       | Unlimited     | Unlimited     | –                         |

     | Gesperrt 🛑 | 0 (blockiert) | –             | Redirect auf Landingpage  |

   * **Implementation**:


     * \tc qdisc add dev <WAN> root handle 1: htb default 999:

     * tc class add für jede Gruppe (Haupt- und Drossel-Rate), IDs z. B. 1:10 = Gratis, 1:11 = Gratis-Drossel.

     * tc filter add mit fw (fwmark) → entsprechende Klasse.

     * Download-Shaping: Mirror/Ingress Policer oder IFB-Gerät.


6. **Peer-Management & Datenspeicherung**


   * **Verzeichnisstruktur**:


     


bash

     /etc/peers/

       └─ <username>/

           ├─ <peername>.conf    # WireGuard-Client-Konfiguration

           ├─ <peername>.png     # QR-Code der Client-Konfiguration

           └─ meta.json          # {"peer":"...","ipv4":"...","ipv6":"...","group":"...","created":"YYYY-MM-DD","expires":"YYYY-MM-DD"}



   * **Metadaten**:


     * peer: Name des Peers (z. B. laptop, handy).

     * ipv4, ipv6: Zugewiesene Adressen.

     * group: Eine der Gruppen (Gratis, Premium, Ultimate, Admin, Gesperrt).

     * created: Erstellungsdatum.

     * expires: Ablaufdatum (z. B. Monatsende).

   * **Interaktive Menü-Funktionen**:


     1. **User anlegen**:


        * Ordner /etc/peers/<username> erstellen.

        * Leeres oder Basis-meta.json anlegen.

     2. **Peer hinzufügen**:


        * Public/Private-Key generieren (wg genkey | tee priv.key | wg pubkey > pub.key).

        * Nächstverfügbare IPv4/IPv6 aus Subnetz finden (z. B. via ipcalc / gespeicherte Map).

        * /etc/peers/<user>/<peer>.conf schreiben.

        * QR-Code erzeugen: qrencode -t png -o <peername>.png < <peername>.conf.

        * meta.json aktualisieren (created, expires z. B. Monatsende).

        * nftables-Markierung und tc-Klassen aktualisieren.

     3. **Peer bearbeiten**:


        * Gruppe ändern.

        * Ablaufdatum manuell setzen.

        * Sofortige Neuanwendung von Mark/TC.

     4. **Peer löschen**:


        * WireGuard-Remove (live via wg set wg0 peer <pubkey> remove).

        * Dateien <peer>.conf und <peer>.png löschen.

        * Eintrag aus meta.json oder ganzes Verzeichnis entfernen.

     5. **Status & Übersicht**:


        * Tabellarische Ausgabe aller Peers, IPv4/IPv6, Gruppe, Verbrauch (wg show dump), created/expires.

     6. **Manueller Quota-Reset**:


        * Setzt Volumenzähler zurück, Gruppe = Ursprungsgruppe (bzw. Drossel lösen).

     7. **Manueller Ablauf-Check**:


        * Vergleich expires mit aktuellem Datum; abgelaufene Peers → Gruppe Gesperrt verschieben.

     8. **AdGuard/Unbound Status & Logs** anzeigen.


7. **Automatisierung mit systemd-Timer**


   * **wg-quota-reset.timer**:


     * **Schedule**: OnCalendar=*-*-01 00:05:00 (1. Tag jedes Monats um 00:05).

     * Service: wg-quota-reset.service ruft vpn-admin --quota-reset auf.

   * **wg-expiry-check.timer**:


     * **Schedule**: OnCalendar=*-*-* 00:10:00 (täglich um 00:10).

     * Service: wg-expiry-check.service ruft vpn-admin --expiry-check auf.

   * **Logging**: Alle Aktionen und Ausgaben an journalctl -u wg-quota-reset und journalctl -u wg-expiry-check.


8. **Interaktives Hauptmenü (vpn-admin)**

   Beim Aufruf ohne Parameter öffnet das Skript ein Menü mit folgenden Optionen:


   


text

   ╔════════════════════════════════╗

   ║      VPN-Admin Hauptmenü       ║

   ╠════════════════════════════════╣

   ║ 1) VPN starten / Status        ║

   ║ 2) Neuen User anlegen          ║

   ║ 3) Peer hinzufügen             ║

   ║ 4) Peer bearbeiten             ║

   ║ 5) Peer löschen                ║

   ║ 6) Quota-Reset manuell auslösen║

   ║ 7) Ablauf-Check manuell auslösen║

   ║ 8) AdGuard/Unbound Status      ║

   ║ 9) Script beenden              ║

   ╚════════════════════════════════╝




   * **Implementierung**:


     * Menü via select oder read -p + case.

     * Nach jeder Aktion: nftables- und tc-Sync, Meta-Update, Live-WG-Reload falls nötig.


9. **Logging, Backup & Reporting**


   * **Logging**:


     * Alle Skript-Aktionen mit Zeitstempel in /var/log/vpn-admin.log.

     * Logrotate-Eintrag: Wochenweise Rotation, 4 Rotationszyklen.

   * **Backup**:


     * Vor jeder Änderung (add, edit, delete): Backup von /etc/wireguard/wg0.conf, /etc/peers/, nftables-Regeln (nft list ruleset > /var/backups/nftables-YYYYMMDD.rules), AdGuard/Unbound-Konfiguration.

     * Backup-Verzeichnis: /var/backups/vpn-admin/ mit Datum.

     * Wiederherstellungs-Skript: vpn-admin --restore YYYYMMDD.

   * **Traffic-Reporting (CSV)**:


     * Skript vpn-traffic-report.sh:


       * wg show wg0 dump auslesen (PublicKey, transfer\_rx, transfer\_tx).

       * Zuordnung PublicKey → Peer über meta.json.

       * CSV in /var/log/vpn-traffic-YYYY-MM-DD.csv mit Spalten: Datum, User, Peer, Gruppe, Bytes RX, Bytes TX, letzter Handshake.

     * systemd-Timer: wöchentlich (z. B. Montag 01:00) für Reporting.