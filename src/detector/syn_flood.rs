use crate::app::Alert;
use crate::capture::PacketInfo;
use crate::detector::AnomalyDetector;
use crate::pedagogy::AttackType;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use std::collections::HashMap;
use chrono::{DateTime, Local};

pub struct SynFloodDetector {
    syn_counts: HashMap<String, Vec<DateTime<Local>>>,
    threshold: usize,
    time_window_secs: i64,
}

impl SynFloodDetector {
    pub fn new() -> Self {
        Self {
            syn_counts: HashMap::new(),
            threshold: 50, // 50 SYNs por segundo es un buen umbral para pruebas
            time_window_secs: 1,
        }
    }
}

impl AnomalyDetector for SynFloodDetector {
    fn process_packet(&mut self, packet: &PacketInfo) -> Option<Alert> {
        let sliced = match SlicedPacket::from_ethernet(&packet.raw_data) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let src_ip = if let Some(net) = sliced.net {
            match net {
                InternetSlice::Ipv4(ipv4) => ipv4.header().source_addr().to_string(),
                InternetSlice::Ipv6(ipv6) => ipv6.header().source_addr().to_string(),
                _ => return None,
            }
        } else {
            return None;
        };

        if let Some(transport) = sliced.transport {
            if let TransportSlice::Tcp(tcp) = transport {
                if tcp.syn() && !tcp.ack() {
                    let now = packet.timestamp;
                    let timestamps = self.syn_counts.entry(src_ip.clone()).or_insert_with(Vec::new);
                    timestamps.push(now);

                    // Limpiar timestamps viejos
                    timestamps.retain(|&t| (now - t).num_seconds() <= self.time_window_secs);

                    if timestamps.len() > self.threshold {
                        timestamps.clear(); // Limpiar para no inundar de alertas
                        return Some(Alert {
                            title: format!("SYN Flood detectado desde {}", src_ip),
                            description: format!("Se detectaron más de {} paquetes SYN en {} segundo(s) sin su ACK.", self.threshold, self.time_window_secs),
                            attack_type: AttackType::SynFlood,
                        });
                    }
                }
            }
        }

        None
    }
}
