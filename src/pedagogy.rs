#[derive(Clone, Debug)]
pub enum AttackType {
    PortScan,
    SynFlood,
    ArpSpoof,
    CleartextCredentials,
    IcmpFlood,
}

pub struct PedagogyContent {
    pub title: String,
    pub what_is_it: String,
    pub how_it_works: String,
    pub danger_level: String,
    pub mitigation: String,
}

impl AttackType {
    pub fn get_content(&self) -> PedagogyContent {
        match self {
            AttackType::PortScan => PedagogyContent {
                title: "Escaneo de Puertos (Port Scan)".to_string(),
                what_is_it: "Un escaneo de puertos es una técnica de reconocimiento utilizada por atacantes para descubrir servicios activos en un host.".to_string(),
                how_it_works: "El atacante envía paquetes (ej. SYN) a múltiples puertos de un objetivo de forma secuencial o aleatoria. Dependiendo de la respuesta (SYN-ACK, RST, o ninguna), determina si el puerto está abierto, cerrado o filtrado.".to_string(),
                danger_level: "Media. No es un ataque destructivo por sí mismo, pero es el paso previo esencial para explotar vulnerabilidades en los servicios descubiertos.".to_string(),
                mitigation: "Configurar firewalls (iptables/nftables) para bloquear escaneos detectados (ej. límite de conexiones). Usar IDS/IPS como Snort o Suricata para detectar el comportamiento y bloquear la IP atacante.".to_string(),
            },
            AttackType::SynFlood => PedagogyContent {
                title: "Inundación SYN (SYN Flood / DoS)".to_string(),
                what_is_it: "Un ataque de denegación de servicio (DoS) que busca agotar los recursos del servidor destino, impidiendo que usuarios legítimos se conecten.".to_string(),
                how_it_works: "El atacante envía una cantidad masiva de paquetes TCP con el flag SYN activado. El servidor responde con SYN-ACK y deja una conexión 'abierta a medias' (half-open) en su tabla de estado, esperando el ACK final del atacante (que nunca llega). Eventualmente, la tabla se llena y el servidor rechaza nuevas conexiones.".to_string(),
                danger_level: "Alta. Puede tumbar servicios críticos en cuestión de segundos.".to_string(),
                mitigation: "Habilitar SYN Cookies a nivel de sistema operativo (`sysctl -w net.ipv4.tcp_syncookies=1`). Reducir los tiempos de espera (timeouts) para conexiones TCP semi-abiertas.".to_string(),
            },
            AttackType::ArpSpoof => PedagogyContent {
                title: "Falsificación ARP (ARP Spoofing)".to_string(),
                what_is_it: "Un ataque Man-in-the-Middle (MitM) en redes locales donde el atacante asocia su dirección MAC con la dirección IP de otro host (como el router/gateway).".to_string(),
                how_it_works: "El atacante envía mensajes ARP falsificados (gratuitous ARP) a la red LAN. Las víctimas actualizan su caché ARP engañadas, de modo que el tráfico destinado al router pasa primero por la máquina del atacante, permitiéndole interceptar o alterar paquetes.".to_string(),
                danger_level: "Crítica. Permite el robo de credenciales en texto plano, alteración de comunicaciones y denegación de servicio en la red local.".to_string(),
                mitigation: "Usar tablas ARP estáticas para hosts críticos. Implementar 'Dynamic ARP Inspection' (DAI) en los switches de red. Evitar protocolos sin cifrar.".to_string(),
            },
            AttackType::CleartextCredentials => PedagogyContent {
                title: "Credenciales en Texto Plano (HTTP/Telnet)".to_string(),
                what_is_it: "La transmisión de información sensible (usuarios, contraseñas, tokens) sin ningún tipo de cifrado a través de la red.".to_string(),
                how_it_works: "Protocolos antiguos o mal configurados como HTTP, Telnet o FTP envían la información tal cual se escribe. Cualquiera que intercepte el tráfico (mediante un sniffer o un MitM como ARP Spoofing) puede leer el payload y extraer las credenciales usando expresiones regulares o búsqueda de cadenas (ej. 'USER', 'PASS').".to_string(),
                danger_level: "Crítica. Compromete el acceso a sistemas inmediatamente sin necesidad de exploits técnicos complejos.".to_string(),
                mitigation: "Migrar a protocolos seguros cifrados por defecto: HTTPS en lugar de HTTP, SSH en lugar de Telnet, SFTP/FTPS en lugar de FTP. Deshabilitar los puertos no seguros en los firewalls.".to_string(),
            },
            AttackType::IcmpFlood => PedagogyContent {
                title: "Inundación ICMP (Ping Flood)".to_string(),
                what_is_it: "Un ataque de denegación de servicio (DoS) simple que inunda a la víctima con paquetes de solicitud de eco (ping) ICMP.".to_string(),
                how_it_works: "El atacante envía ráfagas masivas de paquetes 'ICMP Echo Request' lo más rápido posible. La máquina víctima debe gastar CPU y ancho de banda respondiendo a cada uno de ellos con 'ICMP Echo Reply', lo que puede ralentizar o colapsar el sistema si la capacidad del atacante es mayor.".to_string(),
                danger_level: "Media-Baja. Generalmente requiere más ancho de banda por parte del atacante que la víctima para ser efectivo hoy en día. Fácil de bloquear.".to_string(),
                mitigation: "Configurar el firewall para limitar la tasa de paquetes ICMP entrantes (`limit` en iptables) o ignorarlos completamente si el servicio no requiere responder a pings.".to_string(),
            },
        }
    }
}
