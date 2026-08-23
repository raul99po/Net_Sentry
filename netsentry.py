import time
import os
import html
import socket
import json
import ipaddress
import threading
import sqlite3
import concurrent.futures
import subprocess
import psutil
from datetime import datetime, timedelta
import requests
from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv

# ==========================================
# 1. CONFIGURACIÓN Y CONSTANTES
# ==========================================
# Cargar variables de entorno (busca el archivo .env)
load_dotenv('/etc/sentry-telegram.env')

INTERVAL_SECONDS = 600              # Frecuencia del escaneo periódico (10 min)
OFFLINE_THRESHOLD_CYCLES = 2        # Ciclos sin responder antes de marcar Offline
DB_FILE = "netsentry.db"            # Base de datos SQLite

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

COMMON_PORTS = [22, 53, 80, 443, 445, 3389, 8080, 8443]

IGNORED_MAC_PREFIXES = (
    "ff:ff:ff:ff:ff:ff",  # Broadcast
    "01:00:5e",           # IPv4 Multicast
    "33:33",              # IPv6 Multicast
    "00:00:5e:00:01",     # VRRP
    "00:00:0c:07:ac",     # HSRP
)

# --- Base de datos OUI local (fabricantes) ---
OUI_META_FILE = "oui_last_update.json"
OUI_UPDATE_INTERVAL_DAYS = 7
OUI_UPDATE_TIMEOUT_SECONDS = 60

mac_lookup = MacLookup()

# Variables globales de control y concurrencia
db_lock = threading.Lock()
scan_trigger_event = threading.Event()
gateway_info = {"ip": None, "mac": None}
silence_until = None  # Control del modo No Molestar

# ==========================================
# 2. DETECCIÓN DE RED Y GATEWAY
# ==========================================
def get_auto_subnet_and_gw() -> tuple:
    local_ip = None
    gw_ip = None
    detected_subnet = "192.168.1.0/24"

    try:
        _, local_ip, gw_ip = conf.route.route("8.8.8.8")
        for net, mask, gw, dev, addr, _ in conf.route.routes:
            if addr == local_ip and (gw in ("0.0.0.0", "0", "") or gw is None):
                mask_str = socket.inet_ntoa(mask.to_bytes(4, "big")) if isinstance(mask, int) else str(mask)
                interface = ipaddress.IPv4Interface(f"{local_ip}/{mask_str}")
                
                # PARCHE: Si detecta /32 (ej. Hostspot iPhone), forzamos /24
                if interface.network.prefixlen == 32:
                    detected_subnet = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
                else:
                    detected_subnet = str(interface.network)
                break
    except Exception:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            detected_subnet = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        except Exception:
            pass

    return detected_subnet, gw_ip

# ==========================================
# 3. UTILIDADES DE ANÁLISIS DE HOSTS Y WOL
# ==========================================
def is_locally_administered_mac(mac: str) -> bool:
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False

def quick_port_scan(ip: str, ports: list = COMMON_PORTS) -> list:
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.35)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(str(port))
        except Exception:
            continue
    return open_ports

def send_wol_packet(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    try:
        clean_mac = mac_address.replace(":", "").replace("-", "").replace(".", "").strip()
        if len(clean_mac) != 12:
            return False

        mac_bytes = bytes.fromhex(clean_mac)
        magic_packet = b"\xff" * 6 + mac_bytes * 16

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic_packet, (broadcast_ip, port))
        return True
    except Exception as e:
        print(f"[!] Error enviando WoL: {e}")
        return False

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Desconocido"

def get_vendor(mac: str) -> str:
    if is_locally_administered_mac(mac):
        return "🔒 MAC Privada / Aleatoria"
    try:
        return mac_lookup.lookup(mac)
    except KeyError:
        return "Fabricante no identificado"
    except Exception:
        return "No disponible / Descargando base..."

def is_ignored_mac(mac: str) -> bool:
    return any(mac.lower().startswith(p) for p in IGNORED_MAC_PREFIXES)

def esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=False)

# ==========================================
# 3.1 ACTUALIZACIÓN DE BASE OUI (IEEE)
# ==========================================
def should_update_oui() -> bool:
    if not os.path.exists(OUI_META_FILE):
        return True
    try:
        with open(OUI_META_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        last_update = datetime.fromisoformat(data["last_update"])
        return (datetime.now() - last_update).days >= OUI_UPDATE_INTERVAL_DAYS
    except Exception:
        return True

def mark_oui_updated():
    try:
        with open(OUI_META_FILE, "w", encoding="utf-8") as f:
            json.dump({"last_update": datetime.now().isoformat()}, f)
    except Exception as e:
        print(f"[!] No se pudo guardar la marca de actualización OUI: {e}")

def safe_update_vendors(timeout: int = OUI_UPDATE_TIMEOUT_SECONDS) -> bool:
    def _do_update():
        mac_lookup.update_vendors()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_update)
            future.result(timeout=timeout)
        mark_oui_updated()
        print("[*] Base OUI actualizada correctamente.")
        return True
    except concurrent.futures.TimeoutError:
        print(f"[!] Actualización OUI cancelada: superó {timeout}s. Se usará la caché local.")
        return False
    except Exception as e:
        print(f"[!] Error actualizando base OUI: {e}. Se usará la caché local.")
        return False

# ==========================================
# 4. PERSISTENCIA (SQLITE) Y ALERTAS TELEGRAM
# ==========================================
def send_telegram_msg(text: str):
    """Envío genérico de texto en HTML a Telegram."""
    global silence_until
    
    # Comprobar si estamos en modo "No Molestar"
    if silence_until and datetime.now() < silence_until:
        # Solo silenciamos los avisos automáticos, permitimos respuestas a comandos interactivos si empiezan por ciertos emojis
        if not text.startswith(("✅", "❌", "📊", "📡", "🗑️", "🔇", "🔄", "ℹ️", "🟢", "🛠️", "⚠️", "⚡")):
            return

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[LOG LOCAL - FALTAN CREDENCIALES TELEGRAM]\n{text}\n")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"[!] Error enviando a Telegram: {e}")

def init_db():
    """Inicializa la base de datos SQLite y crea la tabla si no existe."""
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                alias TEXT,
                status TEXT,
                missed_cycles INTEGER,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        conn.commit()
        conn.close()

def load_known_devices() -> dict:
    """Carga los dispositivos desde SQLite a un diccionario en memoria."""
    devices = {}
    if not os.path.exists(DB_FILE):
        return devices

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Permite acceder por nombre de columna
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices")
        
        for row in cursor.fetchall():
            devices[row["mac"]] = dict(row)
        conn.close()
    except Exception as e:
        print(f"[!] Error leyendo base de datos SQLite: {e}")
    return devices

def save_known_devices(devices: dict):
    """Guarda/actualiza el diccionario de dispositivos en SQLite (UPSERT)."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        sql = '''
            INSERT INTO devices 
            (mac, ip, hostname, vendor, alias, status, missed_cycles, first_seen, last_seen) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = excluded.hostname,
                vendor = excluded.vendor,
                alias = excluded.alias,
                status = excluded.status,
                missed_cycles = excluded.missed_cycles,
                last_seen = excluded.last_seen
        '''
        
        for mac, data in devices.items():
            cursor.execute(sql, (
                mac,
                data.get("ip"),
                data.get("hostname"),
                data.get("vendor"),
                data.get("alias", ""),
                data.get("status"),
                data.get("missed_cycles", 0),
                data.get("first_seen"),
                data.get("last_seen")
            ))
            
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error guardando en base de datos SQLite: {e}")

# ==========================================
# 5. MOTOR DE ESCANEO ARP
# ==========================================
def scan_network(subnet: str) -> list:
    arp_request = ARP(pdst=subnet)
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast_frame / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    discovered = []
    for _, received in answered:
        discovered.append({
            "ip": received.psrc,
            "mac": received.hwsrc.lower()
        })
    return discovered

# ==========================================
# 6. CICLO DE MONITORIZACIÓN Y SEGURIDAD
# ==========================================
def perform_audit_cycle(subnet: str):
    global gateway_info
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_scan = scan_network(subnet)

    with db_lock:
        devices_snapshot = load_known_devices()

    scanned_macs = set()
    pending_new = {}
    pending_updates = {}
    messages_to_send = []

    for dev in current_scan:
        mac = dev["mac"]
        ip = dev["ip"]

        if is_ignored_mac(mac):
            continue

        scanned_macs.add(mac)

        if gateway_info["ip"] and ip == gateway_info["ip"]:
            if gateway_info["mac"] is None:
                gateway_info["mac"] = mac
            elif gateway_info["mac"] != mac:
                messages_to_send.append(
                    "🚨🚨 <b>ALERTA CRÍTICA: POSIBLE ARP SPOOFING / MITM</b> 🚨🚨\n\n"
                    f"El Gateway (<code>{esc(ip)}</code>) cambió de MAC:\n"
                    f"• <b>MAC Legítima:</b> <code>{esc(gateway_info['mac'])}</code>\n"
                    f"• <b>MAC Atacante:</b> <code>{esc(mac)}</code>\n"
                    f"⏰ <b>Hora:</b> {timestamp}"
                )

        if mac not in devices_snapshot:
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)
            ports = quick_port_scan(ip)
            ports_str = ", ".join(ports) if ports else "Ninguno detectado"

            messages_to_send.append(
                "🚨 <b>Nuevo dispositivo detectado</b>\n\n"
                f"🌐 <b>IP:</b> <code>{esc(ip)}</code>\n"
                f"🏷️ <b>MAC:</b> <code>{esc(mac)}</code>\n"
                f"🏭 <b>Fabricante:</b> {esc(vendor)}\n"
                f"💻 <b>Hostname:</b> <code>{esc(hostname)}</code>\n"
                f"🔌 <b>Puertos abiertos:</b> <code>{esc(ports_str)}</code>\n"
                f"⏰ <b>Hora:</b> {timestamp}"
            )

            pending_new[mac] = {
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "alias": "",
                "status": "online",
                "missed_cycles": 0,
                "first_seen": timestamp,
                "last_seen": timestamp
            }
        else:
            record = devices_snapshot[mac]
            changes = {"status": "online", "missed_cycles": 0, "last_seen": timestamp}
            name = record.get("alias") or record.get("hostname") or mac

            if record.get("ip") != ip:
                messages_to_send.append(
                    "🔄 <b>Cambio de IP detectado</b>\n\n"
                    f"💻 <b>Equipo:</b> {esc(name)}\n"
                    f"🏷️ <b>MAC:</b> <code>{esc(mac)}</code>\n"
                    f"🌐 <b>IP anterior:</b> <code>{esc(record.get('ip'))}</code>\n"
                    f"🌐 <b>IP nueva:</b> <code>{esc(ip)}</code>\n"
                    f"⏰ <b>Hora:</b> {timestamp}"
                )
                changes["ip"] = ip

            if record.get("status") == "offline":
                messages_to_send.append(
                    "🟢 <b>Dispositivo Reconectado</b>\n\n"
                    f"💻 <b>Equipo:</b> {esc(name)}\n"
                    f"🌐 <b>IP:</b> <code>{esc(ip)}</code>\n"
                    f"🏷️ <b>MAC:</b> <code>{esc(mac)}</code>\n"
                    f"⏰ <b>Hora:</b> {timestamp}"
                )

            pending_updates[mac] = changes

    offline_updates = {}
    for mac, record in devices_snapshot.items():
        if mac not in scanned_macs and record.get("status") == "online":
            missed = record.get("missed_cycles", 0) + 1
            if missed >= OFFLINE_THRESHOLD_CYCLES:
                name = record.get("alias") or record.get("hostname") or mac
                messages_to_send.append(
                    "🔴 <b>Dispositivo Desconectado (Offline)</b>\n\n"
                    f"💻 <b>Equipo:</b> {esc(name)}\n"
                    f"🌐 <b>Última IP:</b> <code>{esc(record.get('ip'))}</code>\n"
                    f"🏷️ <b>MAC:</b> <code>{esc(mac)}</code>\n"
                    f"⏰ <b>Visto por última vez:</b> {esc(record.get('last_seen'))}"
                )
                offline_updates[mac] = {"status": "offline", "missed_cycles": missed}
            else:
                offline_updates[mac] = {"missed_cycles": missed}

    for msg in messages_to_send:
        send_telegram_msg(msg)
        time.sleep(0.3)

    with db_lock:
        devices = load_known_devices()

        for mac, data in pending_new.items():
            if mac not in devices:
                devices[mac] = data
            else:
                devices[mac].update({
                    "ip": data["ip"], "status": "online",
                    "missed_cycles": 0, "last_seen": data["last_seen"]
                })

        for mac, changes in pending_updates.items():
            if mac in devices:
                devices[mac].update(changes)

        for mac, changes in offline_updates.items():
            if mac in devices:
                devices[mac].update(changes)

        save_known_devices(devices)

def background_monitor(subnet: str):
    while True:
        try:
            perform_audit_cycle(subnet)
        except Exception as e:
            print(f"[!] Error en monitor de fondo: {e}")
        scan_trigger_event.wait(timeout=INTERVAL_SECONDS)
        scan_trigger_event.clear()

# ==========================================
# 7. BOT INTERACTIVO TELEGRAM (COMANDOS)
# ==========================================
def telegram_listener(subnet: str):
    if not TELEGRAM_BOT_TOKEN:
        return

    offset = None
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"

    while True:
        try:
            params = {"timeout": 20, "offset": offset}
            res = requests.get(url, params=params, timeout=25)
            if res.status_code != 200:
                time.sleep(3)
                continue

            updates = res.json().get("result", [])
            for update in updates:
                offset = update["update_id"] + 1
                msg = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id"))
                text = msg.get("text", "").strip()

                if chat_id != str(TELEGRAM_CHAT_ID):
                    continue

                handle_telegram_command(text, subnet)

        except Exception:
            time.sleep(3)

def handle_telegram_command(text: str, subnet: str):
    parts = text.split(maxsplit=2)
    cmd = parts[0].lower() if parts else ""

    if cmd == "/start" or cmd == "/help":
        help_msg = (
            "🛠️ <b>Comandos NetSentry:</b>\n\n"
            "• <code>/status</code>: Lista los equipos online.\n"
            "• <code>/scan</code>: Fuerza barrido ARP inmediato.\n"
            "• <code>/wol &lt;MAC/Alias/IP&gt;</code>: Wake On LAN.\n"
            "• <code>/alias &lt;MAC&gt; &lt;Nombre&gt;</code>: Asigna alias.\n"
            "• <code>/info &lt;IP/MAC&gt;</code>: Detalle de un host.\n"
            "• <code>/sysinfo</code>: Estado del servidor (CPU/RAM/Temp).\n"
            "• <code>/ping &lt;IP&gt;</code>: Prueba conexión ICMP.\n"
            "• <code>/forget &lt;MAC/Alias&gt;</code>: Borra dispositivo de la BD.\n"
            "• <code>/silence &lt;minutos&gt;</code>: Pausa notificaciones.\n"
            "• <code>/reboot_host confirm</code>: Reinicia el servidor físico.\n"
            "• <code>/portscan &lt;IP/Alias&gt;</code>: Análisis de puertos del dispositivo.\n"
            "• <code>/osdetect &lt;IP/Alias&gt;</code>: Detecta el sistema operativo."

        )
        send_telegram_msg(help_msg)

    elif cmd == "/scan":
        send_telegram_msg("🔍 <i>Iniciando escaneo manual de red...</i>")
        scan_trigger_event.set()

    elif cmd == "/status":
        with db_lock:
            devices = load_known_devices()

        online_hosts = [
            f"• <b>{esc(d.get('alias') or d.get('hostname'))}</b>\n  └ <code>{esc(d.get('ip'))}</code> | <code>{esc(mac)}</code>"
            for mac, d in devices.items() if d.get("status") == "online"
        ]

        if online_hosts:
            res = f"🟢 <b>Equipos Online ({len(online_hosts)}):</b>\n\n" + "\n".join(online_hosts)
        else:
            res = "ℹ️ No hay equipos marcados como online."
        send_telegram_msg(res)

    elif cmd == "/wol":
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/wol &lt;MAC, Alias o IP&gt;</code>")
            return

        query = parts[1].strip()
        target_mac = None
        target_name = query

        with db_lock:
            devices = load_known_devices()

        clean_query = query.replace(":", "").replace("-", "").replace(".", "").lower()
        if len(clean_query) == 12 and all(c in "0123456789abcdef" for c in clean_query):
            target_mac = query.lower()
            if target_mac in devices:
                target_name = devices[target_mac].get("alias") or devices[target_mac].get("hostname") or target_mac
        else:
            for mac, d in devices.items():
                if (d.get("alias") and d.get("alias").lower() == query.lower()) or \
                   (d.get("hostname") and d.get("hostname").lower() == query.lower()) or \
                   (d.get("ip") == query):
                    target_mac = mac
                    target_name = d.get("alias") or d.get("hostname") or mac
                    break

        if target_mac:
            success = send_wol_packet(target_mac)
            if success:
                send_telegram_msg(f"⚡ <b>Magic Packet (WoL) enviado</b> con éxito a <b>{esc(target_name)}</b> (<code>{esc(target_mac)}</code>).")
            else:
                send_telegram_msg(f"❌ Error al generar o transmitir el paquete WoL para <code>{esc(target_mac)}</code>.")
        else:
            send_telegram_msg(f"❌ No se encontró ningún dispositivo asociado a '<code>{esc(query)}</code>'. Especifica una MAC válida o asígnale un alias.")

    elif cmd == "/alias":
        if len(parts) < 3:
            send_telegram_msg("⚠️ <b>Uso incorrecto:</b> <code>/alias &lt;MAC&gt; &lt;Nombre&gt;</code>")
            return

        target_mac = parts[1].lower()
        new_alias = parts[2]

        with db_lock:
            devices = load_known_devices()
            if target_mac in devices:
                devices[target_mac]["alias"] = new_alias
                save_known_devices(devices)
                send_telegram_msg(f"✅ Alias guardado: <code>{esc(target_mac)}</code> ➔ <b>{esc(new_alias)}</b>")
            else:
                send_telegram_msg(f"❌ La MAC <code>{esc(target_mac)}</code> no existe en la base de datos.")

    elif cmd == "/info":
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/info &lt;IP o MAC&gt;</code>")
            return

        query = parts[1].lower()
        with db_lock:
            devices = load_known_devices()

        target_dev = None
        target_mac = None
        for mac, d in devices.items():
            if mac == query or d.get("ip") == query:
                target_dev = d
                target_mac = mac
                break

        if target_dev:
            name = target_dev.get("alias") or target_dev.get("hostname")
            info_msg = (
                f"📋 <b>Detalle del Host:</b>\n\n"
                f"• <b>Nombre:</b> {esc(name)}\n"
                f"• <b>IP:</b> <code>{esc(target_dev.get('ip'))}</code>\n"
                f"• <b>MAC:</b> <code>{esc(target_mac)}</code>\n"
                f"• <b>Estado:</b> {esc(target_dev.get('status', '').upper())}\n"
                f"• <b>Fabricante:</b> {esc(target_dev.get('vendor'))}\n"
                f"• <b>Primera vez:</b> {esc(target_dev.get('first_seen'))}\n"
                f"• <b>Última vez:</b> {esc(target_dev.get('last_seen'))}"
            )
            send_telegram_msg(info_msg)
        else:
            send_telegram_msg("❌ Host no encontrado en la base de datos.")

    elif cmd == "/sysinfo":
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            temp = "N/A"
            
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if "cpu_thermal" in temps:
                    temp = f"{temps['cpu_thermal'][0].current}°C"
                elif "coretemp" in temps:
                    temp = f"{temps['coretemp'][0].current}°C"
                    
            send_telegram_msg(
                f"📊 <b>Estado del Servidor:</b>\n\n"
                f"🌡️ <b>Temperatura:</b> {temp}\n"
                f"🧠 <b>CPU:</b> {cpu}%\n"
                f"🐏 <b>RAM:</b> {ram}%\n"
                f"💾 <b>Disco Libre:</b> {100 - disk}%"
            )
        except Exception as e:
            send_telegram_msg(f"❌ Error leyendo hardware: {e}")

    elif cmd == "/ping":
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/ping &lt;IP&gt;</code>")
            return
        target = parts[1]
        send_telegram_msg(f"📡 Haciendo ping a <code>{esc(target)}</code>...")
        try:
            res = subprocess.run(["ping", "-c", "4", target], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                stats = res.stdout.strip().split('\n')[-1]
                send_telegram_msg(f"✅ <b>Ping exitoso:</b>\n<code>{esc(stats)}</code>")
            else:
                send_telegram_msg(f"❌ <b>Error:</b> El host {esc(target)} no responde al ping.")
        except Exception:
             send_telegram_msg("❌ Error al ejecutar el ping.")

    elif cmd == "/forget":
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/forget &lt;MAC o Alias&gt;</code>")
            return
        query = parts[1].lower()
        target_mac = None
        
        with db_lock:
            devices = load_known_devices()
            for mac, d in list(devices.items()):
                if mac == query or (d.get("alias") and d.get("alias").lower() == query):
                    target_mac = mac
                    break
                    
            if target_mac:
                conn = sqlite3.connect(DB_FILE)
                conn.execute("DELETE FROM devices WHERE mac = ?", (target_mac,))
                conn.commit()
                conn.close()
                send_telegram_msg(f"🗑️ Dispositivo <code>{target_mac}</code> eliminado de la base de datos.")
            else:
                send_telegram_msg("❌ No se encontró el dispositivo en el registro.")

    elif cmd == "/silence":
        global silence_until
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/silence &lt;minutos&gt;</code> (Ej: /silence 60)")
            return
        try:
            minutos = int(parts[1])
            silence_until = datetime.now() + timedelta(minutes=minutos)
            send_telegram_msg(f"🔇 <b>Modo Silencio Activado</b>\nNo enviaré alertas automáticas durante {minutos} minutos (hasta las {silence_until.strftime('%H:%M')}).\nLos comandos manuales seguirán funcionando.")
        except ValueError:
            send_telegram_msg("❌ Debes indicar un número entero de minutos.")

    elif cmd == "/reboot_host":
        if len(parts) < 2 or parts[1] != "confirm":
            send_telegram_msg("⚠️ <b>Peligro:</b> Para reiniciar el sistema operativo escribe: <code>/reboot_host confirm</code>")
            return
            
        send_telegram_msg("🔄 Reiniciando el servidor en 5 segundos. El bot se desconectará temporalmente...")
        
        # Creamos una función que espere 5 segundos antes de apagar
        def delayed_reboot():
            time.sleep(5)
            subprocess.Popen(["sudo", "reboot"])
            
        # Lo lanzamos en un hilo paralelo. 
        # Así el script principal sigue corriendo, confirma la lectura a Telegram, y luego el PC se reinicia.
        threading.Thread(target=delayed_reboot).start()

    elif cmd == "/portscan":
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/portscan &lt;IP o Alias&gt;</code>")
            return

        query = parts[1].strip()
        target_ip = None

        with db_lock:
            devices = load_known_devices()
            # Si introdujo un Alias o una MAC, resolvemos la IP
            for mac, d in devices.items():
                if query.lower() in (mac.lower(), (d.get("alias") or "").lower(), (d.get("hostname") or "").lower()):
                    target_ip = d.get("ip")
                    break
            if not target_ip:
                target_ip = query  # Asumimos que pasó la IP directamente

        send_telegram_msg(f"🔍 <i>Escaneando los 100 puertos principales en <code>{esc(target_ip)}</code>...</i>")
        try:
            # -sS: SYN Stealth Scan, --top-ports 100: los 100 puertos más comunes, -T4: rápido
            res = subprocess.run(
                ["nmap", "-sS", "-sV", "--top-ports", "100", "-T4", target_ip],
                capture_output=True, text=True, timeout=60
            )
            
            lines = res.stdout.split("\n")
            # Filtramos solo las líneas que contienen puertos abiertos
            open_services = [l for l in lines if "/tcp" in l and "open" in l]

            if open_services:
                result_text = "\n".join([f"• <code>{esc(s)}</code>" for s in open_services])
                send_telegram_msg(f"🔌 <b>Puertos abiertos en {esc(target_ip)}:</b>\n\n{result_text}")
            else:
                send_telegram_msg(f"🔒 No se encontraron puertos abiertos comunes en <code>{esc(target_ip)}</code>.")
        except subprocess.TimeoutExpired:
            send_telegram_msg("⏱️ El escaneo tardó demasiado tiempo (timeout 60s).")
        except Exception as e:
            send_telegram_msg(f"❌ Error ejecutando Nmap: {e}")

    elif cmd == "/osdetect":
        if len(parts) < 2:
            send_telegram_msg("⚠️ <b>Uso:</b> <code>/osdetect &lt;IP o Alias&gt;</code>")
            return

        query = parts[1].strip()
        target_ip = None

        with db_lock:
            devices = load_known_devices()
            for mac, d in devices.items():
                if query.lower() in (mac.lower(), (d.get("alias") or "").lower(), (d.get("hostname") or "").lower()):
                    target_ip = d.get("ip")
                    break
            if not target_ip:
                target_ip = query

        send_telegram_msg(f"🕵️‍♂️ <i>Analizando huella TCP/IP de <code>{esc(target_ip)}</code>... (puede tardar ~15s)</i>")
        try:
            # -O: Detección de OS, --osscan-guess: estimación agresiva si hay dudas
            res = subprocess.run(
                ["nmap", "-O", "--osscan-guess", "-F", "-T4", target_ip],
                capture_output=True, text=True, timeout=60
            )

            os_details = []
            for line in res.stdout.split("\n"):
                if "OS details:" in line or "Running:" in line or "Aggressive OS guesses:" in line:
                    os_details.append(line.strip())

            if os_details:
                formatted_os = "\n".join([f"• {esc(o)}" for o in os_details])
                send_telegram_msg(f"💻 <b>Estimación de SO ({esc(target_ip)}):</b>\n\n{formatted_os}")
            else:
                send_telegram_msg(f"❓ No se pudo determinar el SO de <code>{esc(target_ip)}</code> (puede tener firewall activo o estar filtrando paquetes ICMP/TCP).")
        except subprocess.TimeoutExpired:
            send_telegram_msg("⏱️ El análisis superó el tiempo límite.")
        except Exception as e:
            send_telegram_msg(f"❌ Error en detección de SO: {e}")

# ==========================================
# 8. ARRANQUE
# ==========================================
def main():
    global gateway_info
    
    init_db()

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] ADVERTENCIA: Faltan credenciales de Telegram en el entorno. Las notificaciones se mostrarán solo en consola.")

    subnet, gw_ip = get_auto_subnet_and_gw()
    gateway_info["ip"] = gw_ip

    print("=" * 50)
    print("🛡️  NETSENTRY MONITOR & AUDIT (SQLite) 🛡️")
    print(f"[*] Subred objetivo: {subnet}")
    print(f"[*] Gateway detectado: {gw_ip}")
    print(f"[*] Frecuencia automática: {INTERVAL_SECONDS}s")
    print("=" * 50)

    if should_update_oui():
        print(f"[*] Han pasado {OUI_UPDATE_INTERVAL_DAYS}+ días, actualizando base OUI en segundo plano...")
        threading.Thread(target=safe_update_vendors, daemon=True).start()
    else:
        print("[*] Base OUI actualizada recientemente, se omite descarga.")

    bot_thread = threading.Thread(target=telegram_listener, args=(subnet,), daemon=True)
    bot_thread.start()

    background_monitor(subnet)

if __name__ == "__main__":
    main()
