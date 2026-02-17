# WLAN Monitor

Ein kleiner Python-Monitor, der **WLAN-/LAN-Teilnehmer im lokalen /24‑Netz** überwacht, An-/Abmeldungen protokolliert und Events in eine MySQL‑Datenbank schreibt.

## Features

- **IP priorisiert**: Geräte werden primär über die **IP-Adresse** erkannt (MAC wird mitgeloggt, wenn verfügbar).
- **Robuster Dauerbetrieb**: Fehler (ARP/DB/Dateisystem) werden abgefangen, der Monitor läuft weiter.
- **Log-Datei begrenzt**: `wlan_connection_log.txt` wird automatisch rotiert, sobald sie **≥ 500 KB** ist (Backup mit Timestamp).
- **Status-Datei**: Aktueller Stand wird in `wlan_status.json` gespeichert (atomar geschrieben).
- **Heartbeat**: **Jede volle Stunde** wird in die Datenbank geschrieben: `ich bin noch aktiv [timestamp]`.

## Voraussetzungen

- Python **3.10+**
- Zugriff auf `ping` und `arp` (Windows/Linux)
- Python-Pakete:
  - `mysql-connector-python`
  - `python-dotenv`

Installation (Beispiel):

```bash
pip install mysql-connector-python python-dotenv
```

## Datenbank

Das Script schreibt Textmeldungen in folgende Tabelle/Spalte:

- Tabelle: `organisation`
- Spalte: `main_content`

## .env Konfiguration

Lege im gleichen Ordner eine Datei `.env` an:

```env
DB_HOST=localhost
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=h17386_org301747
DB_PORT=3306
```

Hinweis: `DB_NAME` und `DB_PORT` sind optional (Default: `h17386_org301747`, `3306`). Wenn `DB_HOST/DB_USER/DB_PASSWORD` fehlen, wird DB‑Logging still deaktiviert.

## Nutzung

### Monitor starten (Dauerbetrieb)

```bash
python wlan_monitor.py --subnet 192.168.178.0 --interval 10
```

### Nur einmal scannen

```bash
python wlan_monitor.py --subnet 192.168.178.0 --once
```

### Aktuellen Status anzeigen

```bash
python wlan_monitor.py --status
```

### Parameter

- `--subnet` / `-s`: Subnetz (z.B. `192.168.178.0` oder `192.168.178`)
- `--interval` / `-i`: Scan-Intervall in Sekunden
- `--once` / `-o`: einmal scannen und beenden
- `--status`: nur Status anzeigen

## Hintergrundbetrieb

### Windows (ohne Konsolenfenster)

Option 1: `pythonw` verwenden:

```bash
pythonw wlan_monitor.py --subnet 192.168.178.0 --interval 10
```

Option 2: Aufgabenplanung (Task Scheduler):
- Trigger: „Beim Systemstart“ oder „Bei Anmeldung“
- Aktion: `pythonw.exe` mit Argumenten `wlan_monitor.py ...`
- „Unabhängig von der Benutzeranmeldung ausführen“ (optional)

## Dateien

- `wlan_connection_log.txt`: Event-Log (rotiert bei ≥ 500 KB)
- `wlan_status.json`: letzter bekannter Online-Status

## Hinweise / Grenzen

- Die Erkennung basiert auf `ping` + `arp` (ARP-Cache). Manche Geräte antworten ggf. nicht auf Ping → Events können dadurch unvollständig sein.
- Das Script ist für **/24 Netze** ausgelegt (`x.y.z.1` bis `x.y.z.254`).

