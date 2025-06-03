## 🌟 ¿Qué es Sentinela Alpha?

`sentinela_alpha.py` es una herramienta de análisis forense pasivo y monitoreo de red escrita en Python, diseñada para inspeccionar de manera *silenciosa* y *precisa* el entorno en el que se ejecuta.  
No se trata de un simple script: es un **agente sigiloso**, capaz de detectar máquinas virtuales, recopilar huellas digitales del sistema y capturar paquetes en tiempo real sin levantar sospechas.

Perfecto para:
- Analistas de ciberseguridad 🔒
- Pentesters éticos 🥷
- Entornos de sandboxing y malware analysis 🧬
- Auditores digitales y profesionales IT 🧠

---

## 🧩 ¿Qué hace exactamente?

| Módulo                      | Descripción                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| 🔬 `generar_id_sentinela()` | Crea un ID único ultraentropizado para identificar el host sin colisiones   |
| 🧠 `plataforma_host()`      | Detecta sistema operativo y arquitectura con nivel quirúrgico               |
| 🛰️ `fingerprint_red()`     | Inspecciona todas las interfaces de red: IPs, MACs, tipos, estado y más     |
| 👁️ `capturar_trafico()`    | Captura pasivamente el tráfico de red y detecta patrones en tiempo real     |
| 🧠 `detectar_virtualizacion()` | Determina si estás dentro de una VM, sandbox o entorno artificial       |
| 🌎 `obtener_ip_publica()`   | Descubre tu IP pública y geolocalización a través de múltiples nodos        |
| 🚀 `iniciar_sentinela()`    | Lo une todo y ejecuta el modo de vigilancia en silencio                     |

---

## 🔧 Requisitos del Sistema

📌 Python 3.6 o superior  
💻 Compatible con Windows, Linux y macOS  
🔐 Privilegios de administrador recomendados para capturar tráfico

### 📦 Dependencias

Instálalas fácilmente con:

pip install -r requirements.txt
Contenido de requirements.txt:

💻 ¿Cómo lo ejecuto?
Descarga o clona este repositorio:

git clone https://github.com/Makavellik/Sentinela-Alpha
cd sentinela-alpha
Instala las dependencias:

pip install -r requirements.txt
Ejecuta el script:

python sentinela_alpha.py
🌐 ¿Qué información me da?
✅ Identidad del sistema
Genera un hash identificador único por host.

Extrae información sobre el sistema operativo, arquitectura, y si se trata de una máquina virtual.

🧬 Análisis de red local
Examina cada interfaz: IPv4, IPv6, MAC, tipo de red (Wi-Fi, Ethernet, Virtual, VPN, etc.)

Detecta si la interfaz está activa o no, su velocidad y su MTU.

Usa colores y formato enriquecido para una lectura más visual.

🌍 IP Pública y Geolocalización
Consulta múltiples APIs para encontrar la IP pública más precisa posible.

Extrae país, región, ciudad, ISP, ASN y zona horaria.

👁️ Captura de tráfico
Monitorea tráfico IP saliente y entrante (puertos, tamaños, protocolos).

Opcionalmente guarda archivos .pcap para análisis posterior (Wireshark compatible).

Log de eventos en texto plano si lo deseas.

✨ Ejemplo de salida

🔍 [SENTINELA] Iniciando módulo de vigilancia avanzada...

[🧠] Recolectando información del entorno...

   SENTINELA_ID    : d4f7acb9b6a789ff0c2ab71c3b43ff28
   SISTEMA         : Ubuntu 22.04 (x86_64)
   VIRTUAL         : No se detectó virtualización
   IPS_LOCALES     : eth0: 192.168.0.15 | Wi-Fi: No disponible
   IP_PUBLICA      : 179.23.15.99 (Argentina) - Fibertel ISP

[👁️] Iniciando escucha de red en modo sigiloso...
⏳ Esperando captura de tráfico... /

[✅] Captura finalizada. Nada sospechoso detectado.
🧠 ¿Por qué usarlo?
✔️ Portátil: Sin instalación permanente. Sin modificar el sistema.

✔️ Silencioso: No genera tráfico adicional. No realiza escaneos activos.

✔️ Robusto: Funciona en una gran variedad de plataformas sin requerimientos exóticos.

✔️ Extensible: Código limpio y modular. Puedes integrarlo con tus propias herramientas.

⚠️ Ética y legalidad
Esta herramienta ha sido desarrollada con fines educativos y de auditoría controlada.
NO LA USES en redes de terceros sin autorización explícita.
Respeta la privacidad, las leyes de ciberseguridad y los principios éticos.

