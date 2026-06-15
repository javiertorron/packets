use crate::app::Alert;
use crate::capture::PacketInfo;
use crate::detector::AnomalyDetector;
use crate::pedagogy::AttackType;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

pub struct CleartextDetector {}

impl CleartextDetector {
    pub fn new() -> Self {
        Self {}
    }
}

impl AnomalyDetector for CleartextDetector {
    fn process_packet(&mut self, packet: &PacketInfo) -> Option<Alert> {
        let sliced = match SlicedPacket::from_ethernet(&packet.raw_data) {
            Ok(s) => s,
            Err(_) => return None,
        };

        if let Some(transport) = sliced.transport {
            if let TransportSlice::Tcp(tcp) = transport {
                // Puertos comunes en texto plano: 80 (HTTP), 21 (FTP), 23 (Telnet)
                let dst_port = tcp.destination_port();
                if dst_port == 80 || dst_port == 21 || dst_port == 23 {
                    // Buscar patrones simples
                    let text = String::from_utf8_lossy(&packet.raw_data);
                    let text_upper = text.to_uppercase();
                    if text_upper.contains("USER ") || 
                       text_upper.contains("PASS ") || 
                       text_upper.contains("AUTHORIZATION: BASIC") {
                            
                        let src_ip = if let Some(net) = sliced.net {
                            match net {
                                InternetSlice::Ipv4(ipv4) => ipv4.header().source_addr().to_string(),
                                InternetSlice::Ipv6(ipv6) => ipv6.header().source_addr().to_string(),
                                _ => "Desconocida".to_string(),
                            }
                        } else {
                            "Desconocida".to_string()
                        };

                        return Some(Alert {
                            title: format!("Credenciales en texto plano (Puerto {})", dst_port),
                            description: format!("Se detectó el envío de credenciales sin cifrar desde la IP {}", src_ip),
                            attack_type: AttackType::CleartextCredentials,
                        });
                    }
                }
            }
        }

        None
    }
}
