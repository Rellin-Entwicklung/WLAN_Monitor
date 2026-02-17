"""
WLAN Teilnehmer-Monitor
Überwacht welche Geräte sich im WLAN an- und abmelden.
Protokolliert Verbindungen/Abmeldungen und pflegt einen aktuellen Status.
Robust für Hintergrundbetrieb mit umfassender Fehlerbehandlung.
"""

import subprocess
import re
import json
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
import platform
import argparse
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os
import time
import locale

# Konfiguration
CONFIG = {
    "scan_interval": 10,  # Sekunden zwischen Scans
    "state_file": "wlan_status.json",
    "log_file": "wlan_connection_log.txt",
    "subnet": "192.168.178.0",  # Standard-Subnetz (Fritz!Box etc.)
    "max_log_size_kb": 500,  # Maximale Log-Dateigröße in KB
    "ping_workers": 50,  # Anzahl paralleler Ping-Threads
    "ping_timeout": 2,  # Timeout für Ping in Sekunden
}

# Lade Umgebungsvariablen aus .env Datei
load_dotenv()


# Datenbank-Konfiguration aus Umgebungsvariablen mit Validierung
def get_db_config():
    """Lädt und validiert DB-Konfiguration."""
    host = os.getenv("DB_HOST")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    database = os.getenv("DB_NAME", "h17386_org")
    port_str = os.getenv("DB_PORT", "3306")

    if not host or not user or not password:
        return None

    try:
        port = int(port_str)
    except (ValueError, TypeError):
        port = 3306

    return {
        "host": host,
        "user": user,
        "password": password,
        "database": database,
        "port": port
    }


DB_CONFIG = get_db_config()


def get_db_connection():
    """Erstellt eine Datenbankverbindung."""
    if not DB_CONFIG:
        return None
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Exception as e:
        # Stille Fehlerbehandlung für Hintergrundbetrieb
        pass
    return None


def write_to_database(message: str) -> bool:
    """Schreibt einen String in die Datenbank. Robuste Fehlerbehandlung."""
    if not DB_CONFIG:
        return False

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if not connection:
            return False

        cursor = connection.cursor()
        query = "INSERT INTO organisation (main_content) VALUES (%s)"
        cursor.execute(query, (message,))
        connection.commit()
        return True
    except Exception as e:
        # Fehler werden still behandelt für Hintergrundbetrieb
        return False
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass
        if connection and connection.is_connected():
            try:
                connection.close()
            except:
                pass


def get_system_encoding() -> str:
    """Ermittelt das System-Encoding."""
    try:
        if platform.system() == "Windows":
            return locale.getpreferredencoding() or "cp850"
        return "utf-8"
    except:
        return "utf-8"


def get_network_info() -> tuple[Optional[str], Optional[str]]:
    """Ermittelt Subnetz und lokale IP des Systems. Robuste Fehlerbehandlung."""
    try:
        encoding = get_system_encoding()
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                encoding=encoding,
                timeout=5,
            )
            output = result.stdout + result.stderr
        else:
            result = subprocess.run(
                ["ip", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout

        # Suche nach IPv4-Adresse im typischen Format
        ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}"
        match = re.search(ip_pattern, output)
        if match:
            base = match.group(1)
            return f"{base}.0", base
    except Exception:
        pass
    return None, None


def ping_host(ip: str) -> bool:
    """Pingt eine IP und gibt True zurück, wenn erreichbar. Robuste Fehlerbehandlung."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=CONFIG["ping_timeout"],
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_arp_table() -> Dict[str, Dict]:
    """
    Liest die ARP-Tabelle und gibt Geräte zurück.
    Priorisiert IP-Erkennung, MAC ist optional.
    Gibt {ip: {mac, last_seen}} zurück (IP-basiert).
    """
    devices = {}
    try:
        encoding = get_system_encoding()
        if platform.system() == "Windows":
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                encoding=encoding,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout or ""
        else:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout or ""

        # Format: IP-Adresse  MAC-Adresse  Typ
        # Windows: "  192.168.1.1           00-11-22-33-44-55     dynamic"
        pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F\-:]{17})\s+"
        for match in re.finditer(pattern, output):
            ip = match.group(1)
            mac_raw = match.group(2).upper().replace("-", ":")

            # Filtere Broadcast-Adressen
            if mac_raw != "FF:FF:FF:FF:FF:FF" and not mac_raw.startswith("FF:"):
                # Normalisiere MAC-Format
                mac = mac_raw if len(mac_raw) == 17 else "UNKNOWN"
                # IP-basierte Struktur (IP ist Primärschlüssel)
                devices[ip] = {
                    "mac": mac,
                    "last_seen": datetime.now().isoformat()
                }
    except Exception:
        # Stille Fehlerbehandlung für Hintergrundbetrieb
        pass

    return devices


def discover_devices(subnet_base: str) -> Dict[str, Dict]:
    """
    Pingt alle IPs im Subnetz und liest danach die ARP-Tabelle.
    Robuste Fehlerbehandlung, IP-basierte Erkennung.
    """
    devices = {}
    try:
        ips = [f"{subnet_base}.{i}" for i in range(1, 255)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["ping_workers"]) as executor:
            try:
                list(executor.map(ping_host, ips))
            except Exception:
                pass

        # Kurze Pause damit ARP-Tabelle aktualisiert wird
        time.sleep(0.5)

        devices = scan_arp_table()
    except Exception:
        # Bei Fehlern leeres Dict zurückgeben
        pass

    return devices


def rotate_log_file(log_path: Path) -> None:
    """Rotiert Log-Datei wenn sie zu groß wird (max 500KB)."""
    try:
        if not log_path.exists():
            return

        max_size_bytes = CONFIG["max_log_size_kb"] * 1024
        current_size = log_path.stat().st_size

        if current_size >= max_size_bytes:
            # Erstelle Backup-Dateiname mit Timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = log_path.parent / f"{log_path.stem}_{timestamp}{log_path.suffix}"

            # Verschiebe aktuelle Log-Datei
            if log_path.exists():
                log_path.rename(backup_path)
    except Exception:
        # Stille Fehlerbehandlung
        pass


def load_state(path: Path) -> Dict:
    """Lädt den letzten bekannten Gerätestatus. Robuste Fehlerbehandlung."""
    try:
        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
                # Konvertiere alte MAC-basierte Struktur zu IP-basierter Struktur falls nötig
                if "devices" in data:
                    devices = data["devices"]
                    # Prüfe ob alte Struktur (MAC-basiert)
                    if devices and isinstance(list(devices.values())[0], dict) and "ip" in list(devices.values())[0]:
                        # Alte Struktur: {mac: {ip, ...}} -> neue: {ip: {mac, ...}}
                        new_devices = {}
                        for mac, info in devices.items():
                            ip = info.get("ip")
                            if ip:
                                new_devices[ip] = {"mac": mac,
                                                   "last_seen": info.get("last_seen", datetime.now().isoformat())}
                        data["devices"] = new_devices
                return data
    except Exception:
        pass
    return {"devices": {}, "last_scan": None}


def save_state(path: Path, devices: Dict) -> bool:
    """Speichert den aktuellen Gerätestatus. Robuste Fehlerbehandlung."""
    try:
        data = {
            "devices": devices,
            "last_scan": datetime.now().isoformat(),
        }
        # Atomares Schreiben: zuerst in temporäre Datei, dann umbenennen
        temp_path = path.with_suffix(path.suffix + ".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        temp_path.replace(path)
        return True
    except Exception:
        return False


def append_log(log_path: Path, event: str, ip: str, mac: Optional[str] = None):
    """Schreibt einen Eintrag ins Verbindungs-Log und in die Datenbank. IP-basiert, MAC optional."""
    try:
        # Prüfe Log-Größe und rotiere falls nötig
        rotate_log_file(log_path)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mac_str = mac if mac and mac != "UNKNOWN" else "UNKNOWN"
        line = f"[{timestamp}] {event}: IP={ip} MAC={mac_str}\n"

        # Schreibe ins lokale Log
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass  # Stille Fehlerbehandlung

        # Erstelle Datenbankstring (IP priorisiert)
        event_type = "anmeldung" if event == "VERBUNDEN" else "abmeldung"
        if mac_str != "UNKNOWN":
            db_message = f"IP={ip} MAC={mac_str} {event_type} [{timestamp}]"
        else:
            db_message = f"IP={ip} {event_type} [{timestamp}]"

        # Schreibe in Datenbank (nicht-blockierend)
        write_to_database(db_message)

        # Konsolenausgabe (nur wenn nicht im Hintergrund)
        try:
            msg = "ANGEMELDET" if event == "VERBUNDEN" else "ABGEMELDET"
            print(f">>> Gerät {msg}: IP={ip} MAC={mac_str}")
        except Exception:
            pass
    except Exception:
        # Absolutes Fail-Safe: keine Exceptions weiterwerfen
        pass


def normalize_subnet(subnet: Optional[str]) -> Optional[str]:
    """Normalisiert Subnetz-String zu Basis (z.B. 192.168.178)."""
    if not subnet:
        return None

    # Entferne CIDR-Notation
    if "/" in subnet:
        subnet = subnet.split("/")[0]

    # Extrahiere ersten 3 Oktette
    parts = subnet.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    elif len(parts) == 1:
        # Falls nur Basis angegeben (z.B. "192.168.178")
        return subnet

    return None


def run_monitor(subnet: Optional[str] = None, once: bool = False):
    """
    Hauptschleife: Scannt periodisch und protokolliert Änderungen.
    IP-basierte Erkennung, stündlicher Heartbeat, robuste Fehlerbehandlung.
    """
    base_path = Path(__file__).parent
    state_path = base_path / CONFIG["state_file"]
    log_path = base_path / CONFIG["log_file"]

    # Subnetz ermitteln
    subnet_base = normalize_subnet(subnet or CONFIG.get("subnet"))
    if not subnet_base:
        _, subnet_base = get_network_info()
        subnet_base = normalize_subnet(subnet_base)

    if not subnet_base:
        print("Fehler: Subnetz konnte nicht ermittelt werden. Bitte mit --subnet 192.168.178 angeben.")
        return

    try:
        print(f"WLAN-Monitor gestartet. Subnetz: {subnet_base}.0/24")
        print(f"Status: {state_path}")
        print(f"Log: {log_path} (max {CONFIG['max_log_size_kb']}KB)")
        print("-" * 50)
    except Exception:
        pass  # Für Hintergrundbetrieb

    # Schreibe "gestartet" in Datenbank
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        startup_message = f"gestartet [{timestamp}]"
        write_to_database(startup_message)
    except Exception:
        pass

    # Heartbeat-Tracking: letzte volle Stunde
    last_heartbeat_hour = datetime.now().hour

    scan_count = 0
    consecutive_errors = 0
    max_consecutive_errors = 10

    while True:
        try:
            # Geräte scannen
            current = discover_devices(subnet_base)
            previous = load_state(state_path)

            prev_devices = previous.get("devices", {})
            prev_ips = set(prev_devices.keys())
            curr_ips = set(current.keys())

            # Neue Verbindungen (IP-basiert)
            for ip in curr_ips - prev_ips:
                device_info = current.get(ip, {})
                mac = device_info.get("mac", "UNKNOWN")
                append_log(log_path, "VERBUNDEN", ip, mac)

            # Abmeldungen (IP-basiert)
            for ip in prev_ips - curr_ips:
                device_info = prev_devices.get(ip, {})
                mac = device_info.get("mac", "UNKNOWN")
                append_log(log_path, "GETRENNT", ip, mac)

            # Status speichern
            if not save_state(state_path, current):
                consecutive_errors += 1
            else:
                consecutive_errors = 0

            # Heartbeat: Jede volle Stunde
            current_hour = datetime.now().hour
            if current_hour != last_heartbeat_hour:
                try:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    heartbeat_message = f"ich bin noch aktiv [{timestamp}]"
                    write_to_database(heartbeat_message)
                    last_heartbeat_hour = current_hour
                except Exception:
                    pass

            scan_count += 1

            # Zu viele Fehler -> Warnung aber weiterlaufen
            if consecutive_errors >= max_consecutive_errors:
                consecutive_errors = 0  # Reset nach Warnung
                try:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    error_message = f"Warnung: {max_consecutive_errors} aufeinanderfolgende Fehler beim Speichern [{timestamp}]"
                    write_to_database(error_message)
                except Exception:
                    pass

            if once:
                try:
                    print(f"\nAktuell {len(current)} Gerät(e) online.")
                except Exception:
                    pass
                break

            time.sleep(CONFIG["scan_interval"])

        except KeyboardInterrupt:
            # Graceful shutdown
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                shutdown_message = f"beendet [{timestamp}]"
                write_to_database(shutdown_message)
            except Exception:
                pass
            break
        except Exception as e:
            # Absolutes Fail-Safe: Script läuft weiter
            consecutive_errors += 1
            try:
                time.sleep(CONFIG["scan_interval"])
            except Exception:
                time.sleep(10)  # Fallback-Intervall


def show_status():
    """Zeigt den aktuellen Status (verbundene Geräte) an. IP-basiert."""
    try:
        base_path = Path(__file__).parent
        state_path = base_path / CONFIG["state_file"]
        data = load_state(state_path)
        devices = data.get("devices", {})
        last_scan = data.get("last_scan", "-")

        print("=" * 60)
        print("AKTUELLER WLAN-STATUS")
        print("=" * 60)
        print(f"Letzter Scan: {last_scan}")
        print(f"Aktive Geräte: {len(devices)}")
        print("-" * 60)
        # IP-basierte Ausgabe
        for ip, info in sorted(devices.items()):
            mac = info.get("mac", "UNKNOWN")
            if mac != "UNKNOWN":
                print(f"  IP={ip}  MAC={mac}")
            else:
                print(f"  IP={ip}  MAC=UNKNOWN")
        print("=" * 60)
    except Exception as e:
        print(f"Fehler beim Anzeigen des Status: {e}")


def main():
    parser = argparse.ArgumentParser(description="WLAN Teilnehmer-Monitor")
    parser.add_argument("--subnet", "-s", default="192.168.178.0", help="Subnetz (z.B. 192.168.178.0)")
    parser.add_argument("--once", "-o", action="store_true", help="Nur einmal scannen und beenden")
    parser.add_argument("--status", action="store_true", help="Nur aktuellen Status anzeigen")
    parser.add_argument("--interval", "-i", type=int, default=10, help="Scan-Intervall in Sekunden")

    args = parser.parse_args()
    CONFIG["scan_interval"] = args.interval

    if args.status:
        show_status()
    else:
        run_monitor(subnet=args.subnet, once=args.once)


if __name__ == "__main__":
    main()
