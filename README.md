# 🛡️ NetSentry - Network Monitor & Telegram Bot

Este script de Python proporciona una capa de seguridad y control total para tu red local mediante escaneos periódicos ARP. Cuando se detecta un nuevo dispositivo, un cambio de IP, un equipo desconectado o un ataque MITM (ARP Spoofing), el script extrae automáticamente la IP, MAC y fabricante, enviando una alerta instantánea a un bot de Telegram. Además, puedes enviarle comandos para escanear puertos, detectar SO o hacer Wake-On-LAN.

![GitHub](https://img.shields.io/badge/Version-1.2.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ Características Principales

- 🔍 **Monitorización Proactiva:** Realiza barridos ARP silenciosos para detectar cualquier host nuevo, cambios de IP o dispositivos que se desconectan.
- 🧠 **Persistencia Inteligente:** Base de datos SQLite para recordar dispositivos y guardado de estado en disco (`silence_state.json`) para sobrevivir a reinicios.
- 🚨 **Anti-Spoofing Avanzado:** Verificación cruzada en el arranque (ARP directo + Caché del Kernel) para detectar ataques MITM preexistentes y alertar de cambios en el Gateway.
- 🤖 **Bot Interactivo Asíncrono:** Responde a comandos sin bloquearse. Los escaneos pesados (Nmap, Ping) se ejecutan en hilos en segundo plano (Threading), permitiendo usar el bot de forma continua.
- ⚡ **Conexión Optimizada y Resiliente:** Utiliza sesiones HTTP (Keep-Alive) y un sistema de *Exponential Backoff* para gestionar cortes de red locales sin saturar la CPU.
- 📝 **Logging y Apagado Seguro:** Registro local en `netsentry.log` con rotación automática (5MB) y manejo de señales (SIGTERM/SIGINT) para un cierre ordenado con aviso por Telegram.
- 🔒 **Seguridad Mejorada:** Escaneos de red (Nmap) restringidos estrictamente a la subred local, validación de inputs y protección con PIN obligatorio para el reinicio físico del servidor.
- 📊 **Monitor de Hardware:** Integración con psutil para vigilar el estado del servidor host (CPU, RAM, Temperaturas y Disco) vía Telegram.

## 📦 Requisitos

- Sistema operativo Linux (Debian/Ubuntu/Raspberry Pi OS recomendado).
- Python 3.x y gestor de paquetes pip.
- Privilegios de superusuario (sudo) obligatorios para inyectar paquetes ARP (Scapy) y Nmap.
- Nmap instalado en el sistema (`sudo apt install nmap`).
- Un bot de Telegram configurado.

## 🚀 Instalación

1. **Clona el repositorio**:
 ```bash
  git clone https://github.com/raul99po/Net_Sentry.git
cd NetSentry
 ```

2. **Instala las dependencias necesarias:**:
  El proyecto utiliza un archivo requirements.txt para gestionar las librerías de Python.
  ```bash
  sudo apt update && sudo apt install nmap -y
  pip3 install -r requirements.txt
  ```

3. **Edita tus credenciales (BOT_TOKEN y CHAT_ID):**:
  Crea el archivo .env en la ruta segura configurada en el script:
  ```bash
  sudo nano /etc/sentry-telegram.env
  ```
  Añade lo siguiente y guarda:
  ```bash
  TELEGRAM_BOT_TOKEN=tu_token_aqui
  TELEGRAM_CHAT_ID=tu_chat_id_aqui
  REBOOT_PIN=tu_PIN_aqui
  ```
 
4. **Permisos de ejecución y prueba manual (Requiere Root)**:
El script necesita acceso de root para que Nmap y Scapy funcionen correctamente. Dale permisos de ejecución al archivo y haz una prueba manual usando sudo:
```bash
sudo chown root:root netsentry.py
sudo chmod +x netsentry.py
sudo python3 netsentry.py
```
(Si todo funciona correctamente, verás la inicialización en consola. Presiona Ctrl+C para detenerlo y pasa al siguiente paso para dejarlo fijo en segundo plano).

5. **Ejecución como servicio systemd (Recomendado):**:
Para asegurar que la monitorización sea constante (24x7) y arranque automáticamente, crearemos un servicio. Al poner User=root en la configuración, systemd ya se encargará de darle los permisos necesarios.

```bash
sudo nano /etc/systemd/system/netsentry.service
```
Pega el siguiente contenido (asegúrate de cambiar /ruta/absoluta/a/tu/NetSentry por la ruta real donde clonaste el repositorio):
```bash
[Unit]
Description=NetSentry Network Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/ruta/absoluta/a/tu/NetSentry
ExecStart=/usr/bin/python3 /ruta/absoluta/a/tu/NetSentry/netsentry.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```
6. **Activa y arranca el servicio:**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable netsentry
sudo systemctl start netsentry
sudo systemctl status netsentry
```

# COMANDOS:
NetSentry v1.2.0 incluye los siguientes comandos integrados:
- /status: Lista los equipos online.
- /scan: Fuerza barrido ARP inmediato.
- /wol <MAC/Alias/IP>: Wake On LAN.
- /alias <MAC> <Nombre>: Asigna alias.
- /info <IP/MAC>: Detalle de un host.
- /sysinfo: Estado del servidor (CPU/RAM/Temp).
- /ping <IP>: Prueba conexión ICMP (Asíncrono).
- /forget <MAC/Alias>: Borra dispositivo de la BD.
- /silence <minutos>: Pausa notificaciones automáticamente.
- /silence off: Cancela el silencio antes de tiempo.
- /reboot_host confirm <PIN>: Reinicia el servidor físico.
- /portscan <IP/Alias>: Análisis de puertos del dispositivo (Asíncrono).
- /osdetect <IP/Alias>: Detecta el sistema operativo (Asíncrono).
- /version: Muestra la versión actual de NetSentry.
- /uptime: Muestra el tiempo que lleva corriendo el servicio.

# 🛠️ Cómo obtener tu BOT_TOKEN y CHAT_ID
1. **Crear un bot con @BotFather**
  Habla con @BotFather
  Envía /newbot y sigue los pasos.
  Guarda el TOKEN que te da.

2. **Obtener tu CHAT_ID**
Habla con tu bot (envía cualquier mensaje)
Luego ve a:
https://api.telegram.org/bot<BOT_TOKEN>/getUpdates
Busca tu id en "chat":{"id":XXXXXXXX}

## 🔐 Seguridad
No publiques tu BOT_TOKEN ni CHAT_ID en GitHub. Usa variables de entorno o un archivo .env si vas a subirlo públicamente. Configura siempre tu REBOOT_PIN para evitar reinicios no deseados del servidor host.
