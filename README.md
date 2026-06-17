# Analizador de Red Educativo (TUI)

Esta herramienta de ciberseguridad interactiva está desarrollada en Rust. Su objetivo es proporcionar un entorno pedagógico para estudiantes y entusiastas, permitiéndoles monitorizar el tráfico de red, identificar ciberataques en tiempo real y aprender cómo mitigarlos.

---

## 1. ¿Cómo funciona la aplicación?

El Analizador de Red Educativo no es un simple clon de Wireshark; su enfoque es **completamente educativo**. Funciona combinando captura de paquetes en crudo con motores heurísticos y de inspección de tráfico.

El flujo interno de funcionamiento es el siguiente:

1. **Captura Promiscua:** Se inicia un hilo en segundo plano que utiliza `libpcap` (la misma tecnología detrás de tcpdump/Wireshark) para escuchar absolutamente todos los paquetes de red de tu interfaz principal.
2. **Disección Rápida:** Cada paquete en crudo se envía al hilo principal, donde la librería `etherparse` "pela" el paquete capa por capa (Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP).
3. **Análisis Dual:**
   - **Módulo de Seguridad:** El paquete es evaluado por un enjambre de "Detectores". Estos detectores aplican heurística (contadores, ventanas de tiempo, reglas simples) para deducir si el paquete pertenece a un ataque.
   - **Módulo de Perfilado (DPI Ligero):** Si el paquete es seguro, pasa al Perfilador, que extrae datos clave (como nombres de dominio en respuestas DNS) para saber qué aplicación está generando ese tráfico.
4. **Interactividad (TUI):** Usando `ratatui`, el hilo principal pinta a 60 FPS una terminal interactiva. Si se dispara un detector, salta una alerta roja; si el usuario clica la alerta, se abre el "Motor Pedagógico" explicando el ataque de forma didáctica.

---

## 2. Arquitectura y Partes de la App

El código fuente está altamente modularizado dentro del directorio `src/`. Estas son las piezas clave del rompecabezas:

- 📡 `capture.rs` **(Capa de Captura)**: Contiene el bucle infinito que captura tráfico a bajo nivel y lo envía a través de un canal (`mpsc`) al cerebro de la aplicación.
- 🧩 `parse.rs` **(Capa de Extracción)**: Lógica rápida para extraer resúmenes visuales de un paquete (origen, destino, puertos) para mostrarlos en el log de la TUI.
- 🕵️ `profiler.rs` **(DPI y Clasificación)**: El corazón de la nueva "Pestaña 2". Intercepta pasivamente paquetes DNS (puerto 53 UDP) para crear un mapeo local de `IP Externa -> Nombre de Dominio` y clasifica el tráfico (Ej: *Streaming de Vídeo*, *Videojuego*).
- 🛡️ `detector/` **(Motor Heurístico)**: Un subdirectorio que agrupa los detectores de seguridad. Todos implementan un rasgo (*trait*) común llamado `AnomalyDetector`. Cada fichero es un mini-motor de detección independiente.
- 🎓 `pedagogy.rs` **(Base de Conocimientos)**: Un módulo puramente didáctico. Es un gran diccionario interno que asocia cada alerta de seguridad con un curso intensivo (Qué es, Cómo funciona, Nivel de peligro, y Mitigación).
- 🖥️ `ui.rs` **(Motor Gráfico)**: Se encarga enteramente de dibujar la interfaz de la terminal. Calcula los porcentajes de pantalla, diseña las tablas, las listas y los pop-ups usando bloques de texto.
- 🧠 `app.rs` **(El Estado)**: El cerebro del programa. Mantiene en memoria los últimos 1000 paquetes, las alertas generadas, qué pestaña tienes abierta y coordina el flujo entre todos los módulos anteriores.

---

## 3. Tipos de Anomalías que Detecta

Actualmente, el sistema incluye **5 firmas de detección (Detectores)** listas para identificar ciberataques clásicos en vivo:

### 🧨 1. Inundación SYN (SYN Flood)

* **Dónde está:** `detector/syn_flood.rs`
- **Cómo lo detecta:** Rastrea los paquetes TCP que tienen la bandera `SYN` activa pero no tienen `ACK`. Si una misma IP envía más de 50 de estos paquetes en un solo segundo sin terminar el saludo a tres vías, hace saltar la alarma.
- **Qué representa:** Un ataque de Denegación de Servicio (DoS) diseñado para agotar los recursos de conexión de un servidor web.

### 🔭 2. Escaneo de Puertos (Port Scan)

* **Dónde está:** `detector/port_scan.rs`
- **Cómo lo detecta:** Guarda un registro temporal de a qué puertos intenta conectarse una IP de origen. Si detecta intentos de conexión a más de 15 puertos diferentes en menos de 2 segundos, lo marca como escaneo.
- **Qué representa:** La fase inicial de un ciberataque (reconocimiento), típicamente realizado con herramientas automáticas como `Nmap` para buscar servicios vulnerables abiertos.

### 💥 3. Inundación ICMP (Ping Flood)

* **Dónde está:** `detector/icmp_flood.rs`
- **Cómo lo detecta:** Se centra en los paquetes de capa de red (ICMP Echo Request). Si recibe ráfagas anormales (más de 30 pings por segundo de una misma fuente), dispara la alerta.
- **Qué representa:** Otro tipo de ataque de Denegación de Servicio volumétrico, cuyo objetivo es saturar el ancho de banda de la red víctima (conocido popularmente como el PING de la Muerte).

### 🎭 4. Falsificación ARP (ARP Spoofing)

* **Dónde está:** `detector/arp_spoof.rs`
- **Cómo lo detecta:** En la capa de enlace de datos, vigila el volumen de paquetes ARP por segundo. Un exceso de paquetes ARP anunciando la misma ruta (Gratuitous ARP) es una firma altamente sospechosa. Umbral: >10 paquetes ARP en 2 segundos desde una misma MAC.
- **Qué representa:** El preámbulo perfecto para un ataque *Man-In-The-Middle* (Hombre en el Medio). El atacante intenta envenenar la caché ARP de los dispositivos locales para interceptar su tráfico haciéndose pasar por el router.

### 🔓 5. Credenciales en Texto Plano

* **Dónde está:** `detector/cleartext.rs`
- **Cómo lo detecta:** Realiza una Inspección Profunda de Paquetes (DPI) sobre el *payload* (carga útil) de conexiones a puertos históricamente inseguros (80 HTTP, 21 FTP, 23 Telnet). Si el paquete contiene strings en claro como `"USER "`, `"PASS "` o `"AUTHORIZATION: BASIC"`, genera un aviso crítico.
- **Qué representa:** Una vulnerabilidad gravísima de privacidad. Demuestra al estudiante que usar protocolos sin cifrado TLS permite a cualquier persona de la red (o sniffer) capturar sus contraseñas en el aire.
