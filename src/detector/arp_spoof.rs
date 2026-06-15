use crate::app::Alert;
use crate::capture::PacketInfo;
use crate::detector::AnomalyDetector;
use crate::pedagogy::AttackType;
use etherparse::{InternetSlice, SlicedPacket};
use std::collections::HashMap;
use chrono::{DateTime, Local};

pub struct ArpSpoofDetector {
    arp_counts: HashMap<String, Vec<DateTime<Local>>>,
    threshold: usize,
    time_window_secs: i64,
}

impl ArpSpoofDetector {
    pub fn new() -> Self {
        Self {
            arp_counts: HashMap::new(),
            threshold: 10, // 10 paquetes ARP en 2 segundos desde la misma MAC es sospechoso
            time_window_secs: 2,
        }
    }
}

impl AnomalyDetector for ArpSpoofDetector {
    fn process_packet(&mut self, packet: &PacketInfo) -> Option<Alert> {
        let sliced = match SlicedPacket::from_ethernet(&packet.raw_data) {
            Ok(s) => s,
            Err(_) => return None,
        };

        if let Some(net) = sliced.net {
            if let InternetSlice::Arp(_) = net {
                // Extraer la MAC de origen desde la cabecera Ethernet (bytes 6 a 11)
                let sender_mac = if packet.raw_data.len() >= 12 {
                    format!("{:02X?}", &packet.raw_data[6..12])
                } else {
                    "Desconocida".to_string()
                };
                
                let now = packet.timestamp;
                let timestamps = self.arp_counts.entry(sender_mac.clone()).or_insert_with(Vec::new);
                timestamps.push(now);
                timestamps.retain(|&t| (now - t).num_seconds() <= self.time_window_secs);

                if timestamps.len() > self.threshold {
                    timestamps.clear();
                    return Some(Alert {
                        title: "Posible ARP Spoofing detectado".to_string(),
                        description: format!("La dirección MAC {} está enviando demasiados paquetes ARP (posible envenenamiento).", sender_mac),
                        attack_type: AttackType::ArpSpoof,
                    });
                }
            }
        }

        None
    }
}
