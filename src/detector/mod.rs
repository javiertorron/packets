pub mod arp_spoof;
pub mod cleartext;
pub mod icmp_flood;
pub mod port_scan;
pub mod syn_flood;

use crate::app::Alert;
use crate::capture::PacketInfo;

pub trait AnomalyDetector {
    fn process_packet(&mut self, packet: &PacketInfo) -> Option<Alert>;
}
