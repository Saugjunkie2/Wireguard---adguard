# WireGuard + AdGuard Home VPN

## Übersicht

Dieses Repository enthält ein **Installer- und Management-Skript** für Debian 12, das in einem Schritt Folgendes aufsetzt:

* **WireGuard VPN** mit Dual-Stack (IPv4 & IPv6) und Kill-Switch
* **AdGuard Home** als privater DNS-Resolver mit Werbung‑/Tracker‑Blocklisten und manueller Blacklist-Integration
* **Unbound** für DNSSEC-Validierung
* **nftables**-Regeln für:

  * Leak-Protection & DNS-Zwang
  * Geo‑IP‑Blacklist
  * Gruppen‑Isolation und Monats‑Quotas
  * Ablauf‑Umleitung (Expiry) auf interne Landingpage
* **Traffic-Shaping (TC/HTB)** für gruppenbasierte Speed-Limits
* **Backup & Restore** aller Konfigurationsdaten und Peers
* **Cron-Jobs** für automatischen Quota-Reset und Peer‑Expiry-Check
* **Peer-Management**: Interaktive Erstellung von Peers (Schlüssel, IP‑Zuweisung, QR-Code, Ablaufdatum)
* **Interaktives Menü** zur Verwaltung aller Funktionen

## Ziele / Konzept

Wir verfolgen folgende Hauptziele:

1. **Sicherheit & Leak-Protection**

   * Nur VPN‑vermittelter Traffic (Kill-Switch)
   * Zwangs‑DNS über AdGuard Home
2. **Ad‑Blocking & Datenschutz**

   * Werbe‑/Tracker‑Block via AdGuard-Filtration
   * DNSSEC für verlässliche Namensauflösung
3. **Gruppenbasierte Zugangssteuerung**

   * Vier Gruppen (Guest, Member, VIP, Admin) mit eigenen Subnetzen
   * Bandbreiten- und Volumen‑Limits pro Gruppe
   * Peer-Ablauf nach 12 Monaten und Umleitung auf Info-Landingpage
4. **Automatisierung & Bare-Metal**

   * Kein Docker – alles nativ auf Debian 12
   * systemd‑Timer/Cron für wiederkehrende Aufgaben
   * One‑Shot Installer für schnelle Inbetriebnahme
5. **User‑freundlichkeit**

   * QR‑Code‑Generierung für mobile Clients
   * Interaktives CLI‑Menü für Admins

## Bereits umgesetzt

* Vollständiges Bash‑Skript (`install.sh`) mit allen oben genannten Funktionen
* Einbinden von AdGuard Home per offiziellem Service-Installer (Installation unter `/opt/AdGuardHome`)
* Automatische Installation aller benötigten Pakete, inklusive `iptables`
* Vollständige nftables-Konfiguration mit Syntax‑Checks und Service–Integration
* Interaktives Menü mit Punkten für Installation, Peer-Erstellung, Backup/Restore, Blacklist‑Editing, Reload

## Noch offen / To‑Do

* **Web‑Portal & Management‑API**: Dashboard zur Nutzer‑Selbst­verwaltung (Verbrauch, Ablaufdatum, Peer-Download)
* **SIEM‑Integration**: Log‑Forwarding an zentrale Security-Plattform
* **Role‑Based Access Controls**: Feingranulare Rechtevergabe im Portal
* **Push-/E‑Mail-Alerts**: Optional bei hoher Quota‑Auslastung oder Ablauf‑Erinnerungen
* **Staging‑Umgebung**: Automatisierte Tests und Staging-Server via LXC/VM

## Installation

1. Auf einem frischen Debian 12-Server als `root` kopieren:

   ```bash
   curl  -O  https://raw.githubusercontent.com/Saugjunkie2/Wireguard---adguard/main/install.sh
   chmod +x install.sh
   ./install.sh
   ```
2. VPN‑Client konfigurieren, AdGuard Home‑UI über VPN erreichen:

   * Setup: `http://10.66.66.1:3000` (Einrichtung des Admin-Accounts)
   * Landingpage: `http://10.66.66.1:80` (für abgelaufene Peers)
3. Im CLI‑Menü Peers anlegen, Quotas prüfen und Blacklists verwalten.

## Konfiguration

Die Firewall erlaubt nun zusätzlich den Loopback‑Verkehr sowie Zugriffe auf die
DNS‑Ports `5335` (Unbound) und `5353` (AdGuard). Die relevanten Regeln finden
sich in `install.sh` innerhalb der Funktion `configure_nftables`:

```nft
oifname "lo" accept
ip protocol udp udp dport {5335,5353} accept
ip protocol tcp tcp dport {5335,5353} accept
```

## Lizenz

MIT © DeinName

---

*contributors welcome!*
