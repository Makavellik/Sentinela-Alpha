# sentinela_alpha.py
import os
import socket
import platform
import time
import random
import sys
import uuid
import asyncio
import psutil
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap, ICMP
from datetime import datetime
import subprocess
from rich.console import Console, Group
from rich.live import Live
from rich import box
import hashlib
import json
import re
from colorama import Fore, Style, init
import ipaddress
import signal
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from datetime import datetime

# Inicializar colorama
init(autoreset=True)

console = Console()

def mostrar_info_autor():
    texto = Text()
    
    # Encabezado simbólico
    texto.append("⛧ Proyecto: ", style="bold cyan")
    texto.append("Codex Æternum\n", style="bold magenta")
    
    texto.append("🧠 Autor: ", style="bold cyan")
    texto.append("byMakaveli\n", style="bold yellow")
    
    texto.append("🧪 Versión: ", style="bold cyan")
    texto.append("0.0.1-beta ()\n", style="bold green")
    
    texto.append("🗓 Fecha de compilación: ", style="bold cyan")
    texto.append(f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n", style="bold white")
    
    texto.append("🕸 Estado del sistema: ", style="bold cyan")
    texto.append("Sincronización Digital establecida.\n", style="italic bright_green")
    
    texto.append("⚠ Nivel de intrusión: ", style="bold cyan")
    texto.append("CRÍTICO — núcleo abierto\n", style="bold bright_red")
    
    texto.append("📜 Propósito: ", style="bold cyan")
    texto.append("Escanear, vigilar y registrar las anomalías del plano de red.\n", style="italic white")

    texto.append("\n💬 Mensaje del autor:\n", style="bold bright_magenta")
    texto.append('"El código es eterno, pero las ideas son tuyas. Domínalo o serás dominado."\n', style="italic magenta")

    # Crear panel estilizado
    panel = Panel(
        Align.center(texto),
        title="[bold bright_blue]🧾 Información del Proyecto[/bold bright_blue]",
        subtitle="[bright_black]⏳ Invocación activa",
        border_style="bold magenta",
        padding=(1, 4),
        expand=True
    )

    console.print(panel)
mostrar_info_autor()

# Estilos neon y místicos
NEON_STYLES = [
    "bold magenta",
    "bold cyan",
    "bold bright_blue",
    "bold bright_green",
    "bold bright_red",
    "bold bright_yellow",
]

GLITCH_CHARS = list("░▒▓█▉▊▋▌▍▎▏▐▔▕▖▗▘▙▚▛▜▝▞▟")

# Frases del ritual en español
FRASES_MISTICAS = [
    "◉ BRECHA EN EL NÚCLEO DETECTADA ◉",
    "INICIANDO PROTOCOLO DEL CØDΞX ÆTΞRИUM...",
    "▼ ALERTA: NIVEL DE INTRUSIÓN MÁXIMO ▼",
    "∆ SINCRONIZANDO CON EL GRIMORIO DIGITAL ∆",
    "⌬ ACEPTANDO EL CÓDIGO ETERNO... ⌬",
]

FRASE_FINAL = '"A través del Código Eterno, trascendemos el tiempo y la luz."'

async def glitch_text(text: str, style_choices, glitch_prob=0.25) -> Text:
    """Convierte un texto en una versión glitcheada visualmente."""
    glitched = ""
    for c in text:
        if c != " " and random.random() < glitch_prob:
            glitched += random.choice(GLITCH_CHARS)
        else:
            glitched += c
    style = random.choice(style_choices)
    return Text(glitched, style=style)

async def animate_banner():
    glitch_line = "░" * 180 + " ┃"
    deco_line = "▒" * 180

    with Live(console=console, refresh_per_second=15) as live:
        for _ in range(120):
            glitch_header = await glitch_text(glitch_line, NEON_STYLES)
            glitch_footer = await glitch_text(glitch_line, NEON_STYLES)
            deco = Text(deco_line, style="bright_blue")

            # Centramos cada línea mística visualmente
            body_lines = []
            for line in FRASES_MISTICAS:
                glitched_line = await glitch_text(line, NEON_STYLES)
                centered = Align.center(glitched_line, width=180)
                body_lines.append(centered)

            panel_group = Group(
                deco,
                glitch_header,
                *body_lines,
                glitch_footer,
                deco
            )

            panel = Panel(
                panel_group,
                title="[bold cyan]⛧ Codex Æternum ⛧",
                subtitle="[bright_black]∆ Grimorio Digital Desbloqueado ∆",
                border_style=random.choice(NEON_STYLES),
                box=box.DOUBLE_EDGE,
                padding=(1, 4)
            )

            live.update(panel)
            await asyncio.sleep(0.07)

async def typewriter_text(text: str, style: str = "italic magenta"):
    """Escribe texto como una máquina antigua."""
    result = Text("", style=style)
    for char in text:
        result.append(char)
        console.print(result, end="\r", justify="center")
        await asyncio.sleep(0.045)
    console.print(result, justify="center")

async def ritual_codex():
    console.print("\n[bold cyan]🔐 Preparando acceso al CØDΞX ÆTΞRИUM...[/bold cyan]")
    await asyncio.sleep(1.5)
    console.print("\n[bold bright_black]⏎ Pulsa ENTER para continuar...[/bold bright_black]")
    input(">> ")

    console.print("[bold magenta]\n⛧ Iniciando... ⛧[/bold magenta]\n")
    await asyncio.sleep(1.2)

    await animate_banner()
    await asyncio.sleep(1)
    await typewriter_text(FRASE_FINAL)

    console.print("\n[bright_green]✔ Sicronizando modulos de vigilanza .[/bright_green]\n")


# ⚫ Polimorfismo dinámico (camuflaje constante)
def generar_id_sentinela(entropia_extra=None, incluir_timestamp=True, incluir_host=True, longitud=24):
    """if __name__ == "__main__":
    Genera un identificador único extremadamente poderoso y versátil.

    Parámetros:
    - entropia_extra (str): Cadena opcional para añadir entropía personalizada.
    - incluir_timestamp (bool): Si True, incluye un hash del timestamp actual.
    - incluir_host (bool): Si True, incluye parte del hostname para trazabilidad distribuida.
    - longitud (int): Longitud final del ID (recortado de forma segura).

    Retorna:
    - str: ID único generado con múltiples capas de entropía.
    """

    # Entropía base: UUID4
    base = uuid.uuid4().hex

    # Añadir entropía del sistema
    system_entropy = f"{os.getpid()}{random.random()}{time.time_ns()}"

    # Opcional: Añadir timestamp
    if incluir_timestamp:
        timestamp = hashlib.sha256(str(time.time()).encode()).hexdigest()
    else:
        timestamp = ''

    # Opcional: Añadir hostname
    if incluir_host:
        hostname = hashlib.md5(socket.gethostname().encode()).hexdigest()
    else:
        hostname = ''

    # Entropía externa (usuario)
    extra = hashlib.sha1((entropia_extra or '').encode()).hexdigest() if entropia_extra else ''

    # Mezclar todo
    raw_id = base + system_entropy + timestamp + hostname + extra

    # Hash final para uniformidad
    hashed = hashlib.sha512(raw_id.encode()).hexdigest()

    # Cortar de forma segura a la longitud deseada
    return hashed[:max(8, min(longitud, len(hashed)))]  # mínimo 8 caracteres, máximo longitud del hash

def plataforma_host():
    """
    Detecta y devuelve información detallada del sistema operativo actual.

    Retorna:
    - str: Nombre del sistema operativo con distinción de arquitecturas y variantes.
    """
    sistema = platform.system().lower()
    arquitectura = platform.machine().lower()
    detalles = ""

    if "windows" in sistema:
        if "amd64" in arquitectura or "x86" in arquitectura:
            detalles = "Windows 64-bit" if "64" in arquitectura else "Windows 32-bit"
        else:
            detalles = f"Windows ({arquitectura})"
    
    elif "linux" in sistema:
        # Detectar si es WSL (Windows Subsystem for Linux)
        if "microsoft" in platform.release().lower() or "wsl" in platform.version().lower():
            detalles = "WSL (Windows Subsystem for Linux)"
        else:
            try:
                # Detección de distribución (ej: Ubuntu, Fedora, etc.)
                import distro
                nombre_distro = distro.name(pretty=True) or "Linux"
                detalles = f"{nombre_distro} ({arquitectura})"
            except ImportError:
                detalles = f"Linux ({arquitectura})"
    
    elif "darwin" in sistema:
        # Diferenciar entre Intel y Apple Silicon
        if "arm" in arquitectura or "apple" in plataforma_cpu_info():
            detalles = "macOS (Apple Silicon)"
        else:
            detalles = "macOS (Intel)"
    
    elif "java" in sistema:
        detalles = "Java-based OS (posiblemente Android)"
    
    else:
        detalles = f"Desconocido ({sistema}, {arquitectura})"
    
    return detalles


def plataforma_cpu_info():
    """Intenta detectar detalles adicionales del CPU, especialmente para macOS ARM."""
    try:
        import subprocess
        resultado = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], stderr=subprocess.DEVNULL)
        return resultado.decode().strip().lower()
    except Exception:
        return ""


# ⚫ Inteligencia básica de evasión (Anti-VM, Anti-Sandbox)
def detectar_virtualizacion():
    vm_detectada = False
    razones = []

    # 1. Buscar palabras clave en variables de entorno
    palabras_clave = ["vmware", "virtualbox", "xen", "kvm", "hyperv", "qemu", "vbox"]
    for name, value in os.environ.items():
        if any(k in value.lower() for k in palabras_clave):
            razones.append(f"Variable de entorno sospechosa: {value}")
            vm_detectada = True

    # 2. Buscar procesos o servicios sospechosos
    procesos_sospechosos = ["vboxservice", "vmtoolsd", "vmwaretray", "vmsrvc", "xenservice", "qemu-ga"]
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and any(p in proc.info['name'].lower() for p in procesos_sospechosos):
                razones.append(f"Proceso sospechoso: {proc.info['name']}")
                vm_detectada = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 3. Adaptadores de red virtuales
    adaptadores_sospechosos = ["vmnet", "vboxnet", "virtual", "hyperv"]
    for iface in psutil.net_if_addrs():
        if any(palabra in iface.lower() for palabra in adaptadores_sospechosos):
            razones.append(f"Adaptador de red virtual detectado: {iface}")
            vm_detectada = True

    # 4. BIOS y fabricante
    if platform.system().lower() == "windows":
        try:
            salida = subprocess.check_output("wmic bios get serialnumber, manufacturer", shell=True).decode().lower()
            if any(p in salida for p in palabras_clave):
                razones.append(f"Fabricante de BIOS sospechoso: {salida.strip()}")
                vm_detectada = True
        except Exception:
            pass
    elif platform.system().lower() == "linux":
        try:
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                fabricante = f.read().lower()
                if any(p in fabricante for p in palabras_clave):
                    razones.append(f"Fabricante del sistema sospechoso: {fabricante.strip()}")
                    vm_detectada = True
        except:
            pass

    # 5. Recursos del sistema (baja RAM, pocos núcleos, poco disco)
    if psutil.virtual_memory().total < 2 * 1024**3:
        razones.append("Menos de 2 GB de RAM")
        vm_detectada = True
    if psutil.cpu_count(logical=False) and psutil.cpu_count(logical=False) <= 1:
        razones.append("Solo 1 núcleo físico de CPU")
        vm_detectada = True
    if psutil.disk_usage("/").total < 20 * 1024**3:
        razones.append("Disco menor a 20 GB")
        vm_detectada = True

    # 6. Uptime bajo (sospecha de sandbox recién iniciado)
    try:
        if psutil.boot_time():
            uptime = (psutil.time.time() - psutil.boot_time()) / 60  # minutos
            if uptime < 10:
                razones.append("Tiempo de actividad muy bajo (<10 min)")
                vm_detectada = True
    except:
        pass

    if vm_detectada:
        print("[⚠️] Virtualización/Sandbox detectado:")
        for r in razones:
            print("   -", r)
    return vm_detectada


# ⚫ Fingerprint de red pasiva
def fingerprint_red():
    """
    Realiza un fingerprint detallado de las interfaces de red del sistema y las muestra con colores.
    """
    resultado = {}
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()

    print(f"\n{Style.BRIGHT}{Fore.CYAN}📡 Información de Red del Host")
    print(f"{Fore.YELLOW}Hostname: {Fore.WHITE}{hostname}")
    print(f"{Fore.YELLOW}FQDN:     {Fore.WHITE}{fqdn}")
 
    print(f"\n{Style.BRIGHT}{Fore.CYAN}🔌 Interfaces Detectadas:")

    for interfaz, direcciones in interfaces.items():
        info = {
            "ipv4": None,
            "ipv6": None,
            "mac": None,
            "mascara_subred": None,
            "estado": "Desconocido",
            "velocidad_mbps": "No disponible",
            "mtu": "No disponible",
            "tipo": "No detectado",
            "virtual": False
        }

        for d in direcciones:
            if d.family == socket.AF_INET:
                info["ipv4"] = d.address
                info["mascara_subred"] = d.netmask
            elif d.family == socket.AF_INET6:
                info["ipv6"] = d.address
            elif hasattr(psutil, "AF_LINK") and d.family == psutil.AF_LINK:
                info["mac"] = d.address

        if interfaz in stats:
            s = stats[interfaz]
            info["estado"] = f"{Fore.GREEN}Activa" if s.isup else f"{Fore.RED}Inactiva"
            info["velocidad_mbps"] = f"{s.speed} Mbps" if s.speed > 0 else "Desconocida"
            info["mtu"] = s.mtu

        nombre = interfaz.lower()
        if re.search(r"(wi-?fi|wlan|wireless)", nombre):
            info["tipo"] = "Wi-Fi"
        elif re.search(r"(eth|enp|eno|lan)", nombre):
            info["tipo"] = "Ethernet"
        elif re.fullmatch(r"lo|loopback", nombre):
            info["tipo"] = "Loopback"
        elif re.search(r"(vmnet|vbox|hyperv|virtual|docker|br-)", nombre):
            info["tipo"] = "Virtual"
            info["virtual"] = True
        elif re.search(r"(tun|tap|vpn)", nombre):
            info["tipo"] = "VPN"
            info["virtual"] = True
        else:
            info["tipo"] = "Otro"

        color_tipo = Fore.MAGENTA if info["virtual"] else Fore.BLUE
        print(f"\n{Style.BRIGHT}{color_tipo}● {interfaz}")
        print(f"{Fore.YELLOW}  Tipo:          {color_tipo}{info['tipo']}")
        print(f"{Fore.YELLOW}  Estado:        {info['estado']}")
        print(f"{Fore.YELLOW}  IPv4:          {Fore.WHITE}{info['ipv4'] or 'No disponible'}")
        print(f"{Fore.YELLOW}  Máscara:       {Fore.WHITE}{info['mascara_subred'] or 'No disponible'}")
        print(f"{Fore.YELLOW}  IPv6:          {Fore.WHITE}{info['ipv6'] or 'No disponible'}")
        print(f"{Fore.YELLOW}  MAC:           {Fore.WHITE}{info['mac'] or 'No disponible'}")
        print(f"{Fore.YELLOW}  Velocidad:     {Fore.WHITE}{info['velocidad_mbps']}")
        print(f"{Fore.YELLOW}  MTU:           {Fore.WHITE}{info['mtu']}")

    # Gateway predeterminado
    try:
        default_ip = socket.gethostbyname(socket.getfqdn())
    except Exception:
        default_ip = "No disponible"

    print(f"\n{Style.BRIGHT}{Fore.CYAN}🌐 Gateway y DNS")

    print(f"{Fore.YELLOW}IP por defecto:  {Fore.WHITE}{default_ip}")

    dns_servers = []
    if platform.system().lower() in ['linux', 'darwin']:
        try:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_ip = line.split()[1].strip()
                        dns_servers.append(dns_ip)
        except Exception:
            dns_servers = ["No disponible"]
    else:
        dns_servers = ["No disponible en esta plataforma"]

    print(f"{Fore.YELLOW}DNS:             {Fore.WHITE}{', '.join(dns_servers)}")

# ⚫ Captura pasiva de paquetes (modo escucha)
def capturar_trafico(
    duracion=60,
    guardar_pcap=False,
    archivo_pcap="captura_avanzada.pcap",
    log_a_archivo=True,
    archivo_log="registro_avanzado.log",
    filtro_ip=None,
    filtro_puerto=None,
    filtro_protocolo=None,  # "TCP", "UDP", "ICMP"
    ver_payload=False,
    solo_headers=False,
    verbose=True
):
    """
    🔍 Captura avanzada de tráfico IP en tiempo real.
    - Analiza encabezados, protocolos y payloads.
    - Filtra por IP, puerto o protocolo.
    - Guarda estadísticas, logs y archivos PCAP opcionalmente.
    """

    flecha = "->" if platform.system() == "Windows" else "→"
    print(f"{Style.BRIGHT}{Fore.CYAN}\n🔎 Iniciando captura de red avanzada por {duracion} segundos...\n")

    capturados = []
    stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Otro": 0}
    inicio = datetime.now()

    if log_a_archivo:
        with open(archivo_log, "w") as f:
            f.write(f"[Inicio: {inicio}]\n\n")

    def protocolo_nombre(puerto):
        conocidos = {
            80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
            25: "SMTP", 110: "POP3", 143: "IMAP", 21: "FTP", 123: "NTP",
            3306: "MySQL", 8080: "HTTP-Alt", 444: "SNPP"
        }
        return conocidos.get(puerto, "Desconocido")

    def procesar(pkt):
        if not IP in pkt:
            return

        ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
        ttl = pkt[IP].ttl if IP in pkt else "-"
        proto = "Otro"
        puerto_src = puerto_dst = "-"
        nombre_proto = "-"
        flags_tcp = ""
        payload = ""

        if TCP in pkt:
            proto = "TCP"
            puerto_src = pkt[TCP].sport
            puerto_dst = pkt[TCP].dport
            nombre_proto = protocolo_nombre(puerto_dst)
            flags_tcp = pkt[TCP].flags
        elif UDP in pkt:
            proto = "UDP"
            puerto_src = pkt[UDP].sport
            puerto_dst = pkt[UDP].dport
            nombre_proto = protocolo_nombre(puerto_dst)
        elif ICMP in pkt:
            proto = "ICMP"

        if filtro_ip and not (filtro_ip == ip_src or filtro_ip == ip_dst):
            return
        if filtro_puerto and proto in ["TCP", "UDP"]:
            if not (puerto_src == filtro_puerto or puerto_dst == filtro_puerto):
                return
        if filtro_protocolo and filtro_protocolo.upper() != proto:
            return

        tiempo = datetime.now().strftime("%H:%M:%S")
        header = (
            f"{Fore.LIGHTBLACK_EX}[{tiempo}] {Fore.CYAN}{ip_src}:{puerto_src} "
            f"{Fore.YELLOW}{flecha} {Fore.CYAN}{ip_dst}:{puerto_dst} "
            f"{Fore.MAGENTA}[{proto}/{nombre_proto}] {Fore.BLUE}TTL={ttl}"
        )
        if flags_tcp:
            header += f" {Fore.GREEN}Flags={flags_tcp}"

        if verbose and not solo_headers:
            print(header)

        if ver_payload and Raw in pkt:
            try:
                data = pkt[Raw].load
                decoded = data.decode("utf-8", errors="replace")
                print(Fore.GREEN + f"   ↪ Payload ({len(data)} bytes): {decoded[:100]}")
            except Exception as e:
                print(Fore.RED + f"   ↪ Error decodificando payload: {e}")

        if solo_headers and verbose:
            print(header)

        if log_a_archivo:
            with open(archivo_log, "a", encoding="utf-8") as f:
                f.write(f"[{tiempo}] {ip_src}:{puerto_src} -> {ip_dst}:{puerto_dst} [{proto}/{nombre_proto}] TTL={ttl}\n")

        stats[proto] = stats.get(proto, 0) + 1
        if guardar_pcap:
            capturados.append(pkt)

    # Interrupción elegante en Linux
    if platform.system() != "Windows":
        import signal
        def detener(signum, frame):
            print(Fore.RED + "\n[🚨] Interrupción manual.")
            raise KeyboardInterrupt
        signal.signal(signal.SIGINT, detener)

    try:
        sniff(
            prn=procesar,
            filter="ip",
            store=False,
            timeout=duracion
        )
    except PermissionError:
        print(Fore.RED + "❌ Necesitas ejecutar el script como administrador o root.")
        return
    except KeyboardInterrupt:
        print(Fore.RED + "\n[⚠️] Captura detenida por el usuario.")
    except Exception as e:
        print(Fore.RED + f"❌ Error inesperado: {e}")

    # Guardar PCAP
    if guardar_pcap and capturados:
        wrpcap(archivo_pcap, capturados)

    fin = datetime.now()
    duracion_real = (fin - inicio).seconds

    print(Fore.GREEN + f"\n[✔] Captura finalizada tras {duracion_real}s.")
    if guardar_pcap:
        print(Fore.CYAN + f"[💾] Archivo PCAP guardado en: {archivo_pcap}")
    if log_a_archivo:
        print(Fore.YELLOW + f"[📝] Log detallado registrado en: {archivo_log}")

    # Estadísticas
    total = sum(stats.values())
    print(Fore.LIGHTBLUE_EX + "\n📊 Estadísticas por protocolo:")
    print(Fore.WHITE + f"  Total de paquetes: {total}")
    for k, v in stats.items():
        print(Fore.LIGHTMAGENTA_EX + f"  {k}: {v}")

# ⚫ Recopilación de entorno e IPs
def entorno_basico():
    return {
        "sentinela_id": generar_id_sentinela(),
        "sistema": plataforma_host(),
        "virtual": detectar_virtualizacion(),
        "ips_locales": fingerprint_red(),
        "ip_publica": obtener_ip_publica()
    }

# ⚫ IP pública desde nodo externo (evade DNS leaks)
def obtener_ip_publica(usar_geolocalizacion=True):
    print(f"{Fore.CYAN}{Style.BRIGHT}\n🌐 [SENTINELA] Explorando tu red pública y local...\n")

    servicios = [
        ("https://api.ipify.org?format=json", True),
        ("https://ifconfig.me/all.json", True),
        ("https://ipinfo.io/json", True),
        ("https://icanhazip.com", False),
        ("https://ident.me", False),
        ("https://checkip.amazonaws.com", False),
        ("https://ipwho.is/", True),
    ]

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/7.68.0",
        "Wget/1.20.3",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
    ]

    resultados = []

    for url, espera_json in random.sample(servicios, len(servicios)):
        try:
            headers = {
                "User-Agent": random.choice(user_agents),
                "Accept": "application/json" if espera_json else "*/*"
            }
            response = requests.get(url, headers=headers, timeout=6)

            if espera_json:
                data = response.json()
                ip = data.get("ip") or data.get("ip_address") or data.get("address")
            else:
                ip = response.text.strip()

            if ip and validar_ip(ip):
                resultados.append({
                    "origen": url,
                    "ip": ip,
                    "tipo": "IPv6" if ":" in ip else "IPv4",
                })
        except Exception:
            continue

    ips_unicas = list({r['ip']: r for r in resultados}.values())

    salida = {
        "ips_detectadas": ips_unicas,
        "ip_publica": ips_unicas[0]['ip'] if ips_unicas else "No disponible"
    }

    if salida["ip_publica"] != "No disponible":
        print(f"{Fore.GREEN}{Style.BRIGHT}🌍 IP Pública Principal: {Fore.WHITE}{salida['ip_publica']}")
        print(f"{Fore.LIGHTBLACK_EX}📡 Recolectada desde múltiples fuentes confiables...\n")

    # Geolocalización
    if usar_geolocalizacion and salida["ip_publica"] != "No disponible":
        try:
            geo = requests.get(f"https://ipinfo.io/{salida['ip_publica']}/json", timeout=5).json()
            salida["geolocalizacion"] = {
                "🌍 País": geo.get("country", "Desconocido"),
                "🏙️ Ciudad": geo.get("city", "N/A"),
                "🗺️ Región": geo.get("region", "N/A"),
                "🏢 ISP": geo.get("org", "N/A"),
                "📡 ASN": geo.get("asn", "N/A"),
                "🧭 Coordenadas": geo.get("loc", "N/A"),
                "⏰ Zona Horaria": geo.get("timezone", "N/A")
            }

            print(f"{Fore.MAGENTA}{Style.BRIGHT}\n🌐 Geolocalización estimada:")
            for clave, valor in salida["geolocalizacion"].items():
                print(f"{Fore.YELLOW}   {clave:<16}: {Fore.WHITE}{valor}")
        except Exception:
            salida["geolocalizacion"] = {"error": "❌ No se pudo obtener geolocalización"}

    # IPs locales
    salida["ips_locales"] = obtener_ips_locales()
    print(f"\n{Fore.CYAN}{Style.BRIGHT}🔌 Interfaces de red detectadas (locales):")

    for ip in salida["ips_locales"]:
        color = Fore.BLUE if ip["ambito"] == "Privada" else Fore.RED if ip["ambito"] == "Pública" else Fore.LIGHTBLACK_EX
        print(f"{Fore.GREEN}{ip['interfaz']:<12} ➤ {color}{ip['ip']:<40} {Fore.WHITE}({ip['tipo']} - {ip['ambito']})")

    print(f"\n{Fore.LIGHTBLUE_EX}{Style.BRIGHT}✅ Escaneo completo.\n")

    return salida

def validar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def obtener_ips_locales():
    locales = []
    interfaces = psutil.net_if_addrs()
    for iface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                ip = addr.address
                tipo = "IPv6" if ":" in ip else "IPv4"
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        ambito = "Privada"
                    elif ip_obj.is_loopback:
                        ambito = "Loopback"
                    elif ip_obj.is_link_local:
                        ambito = "Link-local"
                    else:
                        ambito = "Pública"
                    locales.append({
                        "interfaz": iface,
                        "ip": ip,
                        "tipo": tipo,
                        "ambito": ambito
                    })
                except ValueError:
                    continue
    return locales

# ⚫ Iniciar el Módulo
def iniciar_sentinela(interactivo=True, guardar_log=True, ruta_log="sentinela_log.json"):
    print(Fore.CYAN + Style.BRIGHT + "\n🔍 [SENTINELA] Iniciando módulo de vigilancia avanzada...\n")
    time.sleep(1)

    etapas = [
        ("Recolectando información del entorno", entorno_basico),
        ("Escuchando tráfico de red en modo sigiloso", lambda: capturar_trafico(duracion=30))
    ]

    resultados = {}
    for idx, (mensaje, funcion) in enumerate(etapas, 1):
        print(Fore.YELLOW + f"[{idx}] {mensaje}...\n")
        time.sleep(0.5)

        if mensaje.lower().startswith("recolectando"):
            info = funcion()
            resultados.update(info)

            for clave, valor in info.items():
                clave_color = Fore.GREEN + f"{clave.upper():<15}"
                valor_str = json.dumps(valor, indent=2, ensure_ascii=False) if isinstance(valor, dict) else str(valor)
                print(f"   {clave_color}: {Fore.WHITE}{valor_str}")
                time.sleep(0.1)

        elif mensaje.lower().startswith("escuchando"):
            print(Fore.MAGENTA + "[👁️] Modo pasivo activado. No se generará tráfico.\n")
            print(Fore.LIGHTBLACK_EX + "    (Esto puede tardar unos segundos...)\n")

            hilo_escucha = threading.Thread(target=funcion)
            hilo_escucha.start()

            spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            i = 0
            while hilo_escucha.is_alive():
                print(f"\r{Fore.CYAN} ⏳ Escuchando... {spinner[i % len(spinner)]}", end="")
                i += 1
                time.sleep(0.15)
            print("\r", end="")  # limpiar línea
            hilo_escucha.join()

            print(Fore.GREEN + "\n[✅] Captura finalizada. Nada sospechoso detectado.")

    if guardar_log:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_nombre = ruta_log.replace(".json", f"_{timestamp}.json")
            with open(log_nombre, "w", encoding="utf-8") as f:
                json.dump(resultados, f, indent=4, ensure_ascii=False)
            print(Fore.BLUE + f"\n[💾] Información guardada en: {log_nombre}")
        except Exception as e:
            print(Fore.RED + f"[⚠️] Error al guardar el log: {e}")

    print(Fore.BLUE + f"\n[🕒] Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    mostrar_info_autor()

    # Interacción opcional
    if interactivo:
        respuesta = input(Fore.YELLOW + "¿Deseas ejecutar nuevamente el análisis? (s/n): ").strip().lower()
        if respuesta == "s":
            iniciar_sentinela(interactivo=interactivo, guardar_log=guardar_log)

# Punto de inicio
if __name__ == "__main__":
    asyncio.run(ritual_codex())
    iniciar_sentinela()

