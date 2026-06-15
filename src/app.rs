use crate::capture::PacketInfo;
use crate::detector::{
    arp_spoof::ArpSpoofDetector, cleartext::CleartextDetector, icmp_flood::IcmpFloodDetector,
    port_scan::PortScanDetector, syn_flood::SynFloodDetector, AnomalyDetector,
};
use crate::profiler::Profiler;

pub struct Alert {
    pub title: String,
    pub description: String,
    pub attack_type: crate::pedagogy::AttackType,
}

pub struct App {
    pub packets: Vec<PacketInfo>,
    pub alerts: Vec<Alert>,
    pub selected_alert: Option<usize>,
    pub show_pedagogy: bool,
    pub packet_count: usize,
    
    pub active_tab: usize,
    pub profiler: Profiler,

    detectors: Vec<Box<dyn AnomalyDetector>>,
}

impl App {
    pub fn new() -> App {
        App {
            packets: Vec::new(),
            alerts: Vec::new(),
            selected_alert: None,
            show_pedagogy: false,
            packet_count: 0,
            active_tab: 0,
            profiler: Profiler::new(),
            detectors: vec![
                Box::new(ArpSpoofDetector::new()),
                Box::new(CleartextDetector::new()),
                Box::new(IcmpFloodDetector::new()),
                Box::new(PortScanDetector::new()),
                Box::new(SynFloodDetector::new()),
            ],
        }
    }

    pub fn add_packet(&mut self, packet: PacketInfo) {
        self.packet_count += 1;
        
        // Pass packet to profiler
        self.profiler.process_packet(&packet);
        
        // Pass packet to detectors
        for detector in &mut self.detectors {
            if let Some(alert) = detector.process_packet(&packet) {
                self.alerts.push(alert);
                if self.selected_alert.is_none() {
                    self.selected_alert = Some(0);
                }
            }
        }
        
        // Keep only last 1000 packets in memory for display
        if self.packets.len() >= 1000 {
            self.packets.remove(0);
        }
        self.packets.push(packet);
    }

    pub fn next_alert(&mut self) {
        if self.alerts.is_empty() {
            return;
        }
        let i = match self.selected_alert {
            Some(i) => {
                if i >= self.alerts.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.selected_alert = Some(i);
    }

    pub fn previous_alert(&mut self) {
        if self.alerts.is_empty() {
            return;
        }
        let i = match self.selected_alert {
            Some(i) => {
                if i == 0 {
                    self.alerts.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.selected_alert = Some(i);
    }

    pub fn toggle_pedagogy(&mut self) {
        if self.selected_alert.is_some() {
            self.show_pedagogy = !self.show_pedagogy;
        }
    }

    pub fn next_tab(&mut self) {
        self.active_tab = (self.active_tab + 1) % 2;
    }
}
