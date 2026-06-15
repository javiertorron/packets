use crate::app::Alert;
use crate::capture::PacketInfo;
use crate::detector::AnomalyDetector;
use crate::pedagogy::AttackType;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use std::collections::HashMap;
use chrono::{DateTime, Local};

pub struct PortScanDetector {
    scan_history: HashMap<String, HashMap<u16, DateTime<Local>>>,
    threshold: usize,
    time_window_secs: i64,
}

impl PortScanDetector {
    pub fn new() -> Self {
        Self {
            scan_history: HashMap::new(),
            threshold: 15, // 15 puertos distintos en 2 segundos
            time_window_secs: 2,
        }
    }
}

impl AnomalyDetector for PortScanDetector {
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

        let dst_port = if let Some(transport) = sliced.transport {
            match transport {
                TransportSlice::Tcp(tcp) => tcp.destination_port(),
                TransportSlice::Udp(udp) => udp.destination_port(),
                _ => return None,
            }
        } else {
            return None;
        };

        let now = packet.timestamp;
        let ports = self.scan_history.entry(src_ip.clone()).or_insert_with(HashMap::new);
        
        ports.insert(dst_port, now);
        ports.retain(|_, &mut t| (now - t).num_seconds() <= self.time_window_secs);

        if ports.len() > self.threshold {
            ports.clear();
            return Some(Alert {
                title: format!("Escaneo de Puertos detectado desde {}", src_ip),
                description: format!("Se intentó conectar a más de {} puertos diferentes en {} segundo(s).", self.threshold, self.time_window_secs),
                attack_type: AttackType::PortScan,
            });
        }

        None
    }
}
