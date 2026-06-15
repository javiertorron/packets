use crate::app::Alert;
use crate::capture::PacketInfo;
use crate::detector::AnomalyDetector;
use crate::pedagogy::AttackType;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use std::collections::HashMap;
use chrono::{DateTime, Local};

pub struct IcmpFloodDetector {
    icmp_counts: HashMap<String, Vec<DateTime<Local>>>,
    threshold: usize,
    time_window_secs: i64,
}

impl IcmpFloodDetector {
    pub fn new() -> Self {
        Self {
            icmp_counts: HashMap::new(),
            threshold: 30, // 30 pings por segundo
            time_window_secs: 1,
        }
    }
}

impl AnomalyDetector for IcmpFloodDetector {
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
            let is_echo_request = match transport {
                TransportSlice::Icmpv4(icmp) => matches!(icmp.icmp_type(), etherparse::Icmpv4Type::EchoRequest(_)),
                TransportSlice::Icmpv6(icmp) => matches!(icmp.icmp_type(), etherparse::Icmpv6Type::EchoRequest(_)),
                _ => false,
            };

            if is_echo_request {
                let now = packet.timestamp;
                let timestamps = self.icmp_counts.entry(src_ip.clone()).or_insert_with(Vec::new);
                timestamps.push(now);
                timestamps.retain(|&t| (now - t).num_seconds() <= self.time_window_secs);

                if timestamps.len() > self.threshold {
                    timestamps.clear();
                    return Some(Alert {
                        title: format!("ICMP Flood detectado desde {}", src_ip),
                        description: format!("Ráfaga masiva de pings ({} en {}s) detectada.", self.threshold, self.time_window_secs),
                        attack_type: AttackType::IcmpFlood,
                    });
                }
            }
        }

        None
    }
}
