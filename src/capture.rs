use chrono::{DateTime, Local};
use pcap::{Capture, Device};
use std::sync::mpsc::Sender;

#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub timestamp: DateTime<Local>,
    pub length: u32,
    pub summary: String,
    pub raw_data: Vec<u8>,
}

pub fn start_capture(tx: Sender<PacketInfo>) -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::lookup()?.ok_or("No interface found")?;
    
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()?;

    loop {
        if let Ok(packet) = cap.next_packet() {
            let summary = crate::parse::parse_packet(packet.data);
            
            let info = PacketInfo {
                timestamp: Local::now(),
                length: packet.header.len,
                summary,
                raw_data: packet.data.to_vec(),
            };
            
            if tx.send(info).is_err() {
                break; // Receiver disconnected
            }
        }
    }
    
    Ok(())
}
