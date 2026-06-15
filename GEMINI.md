# Proyecto: Herramienta de Aprendizaje de Ciberseguridad (Analizador de Red)

## Objetivos
Crear una herramienta interactiva en la terminal (TUI) desarrollada en Rust. Su objetivo es capturar tráfico de red en vivo, analizar paquetes en tiempo real para detectar patrones de ataque comunes y proporcionar a los estudiantes explicaciones detalladas y pedagógicas sobre las amenazas detectadas.

## Requisitos Definidos
1. **Modalidad de Análisis:** Captura de tráfico en vivo (requerirá permisos de superusuario `sudo` o `CAP_NET_RAW`).
2. **Ataques a Detectar (MVP):**
   - Escaneo de puertos (Nmap / SYN scan).
   - Inundación SYN (DoS).
   - ARP Spoofing.
   - Tráfico en texto plano con credenciales (HTTP, Telnet).
   - ICMP Flood (Ping Flood).
3. **Interfaz de Usuario:** TUI (Text User Interface) desarrollada con `ratatui` y `crossterm`.
4. **Enfoque Pedagógico:** Nivel máximo. Al detectar una anomalía, se mostrará una vista detallada explicando la naturaleza del ataque, cómo funciona a nivel técnico, por qué es peligroso y cómo mitigarlo.
5. **Tecnologías:** Rust (`pcap` para captura, `etherparse` para parseo, `ratatui` para UI).

## Arquitectura

### 1. Capa de Captura (Network Sniffer)
Hilo dedicado (worker thread) que utiliza la librería `pcap` para leer paquetes de la interfaz de red en modo promiscuo. Enviará los paquetes en crudo a la capa de análisis a través de canales de mensajes (`std::sync::mpsc`).

### 2. Capa de Análisis y Detección (Analyzer)
Módulo que deserializa los paquetes utilizando `etherparse` y evalúa el tráfico con "Detectores" heurísticos:
- Contadores de frecuencia para detectar inundaciones (SYN, ICMP).
- Registro de puertos visitados en ventanas de tiempo para detectar escaneos.
- Análisis de payload para detectar credenciales sin cifrar.

### 3. Motor Pedagógico (Knowledge Base)
Base de datos integrada en el código (diccionario estático) que asocia cada tipo de alerta generada por el analizador con un documento explicativo completo (Qué es, Cómo funciona, Peligrosidad, Mitigación).

### 4. Interfaz TUI (Frontend)
El hilo principal gestionará la interfaz gráfica en la terminal:
- **Dashboard Principal:** Estadísticas globales y registro de los últimos paquetes en tiempo real.
- **Panel de Alertas:** Lista de anomalías detectadas.
- **Vista Educativa:** Panel detallado que se despliega al inspeccionar una alerta, mostrando el contenido pedagógico.
