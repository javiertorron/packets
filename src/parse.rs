use etherparse::{SlicedPacket, InternetSlice, TransportSlice};

pub fn parse_packet(raw_data: &[u8]) -> String {
    let mut summary = String::new();

    match SlicedPacket::from_ethernet(raw_data) {
        Err(_) => summary.push_str("Unparseable packet"),
        Ok(value) => {
            if let Some(net) = value.net {
                match net {
                    InternetSlice::Ipv4(ipv4) => {
                        summary.push_str(&format!("IPv4 {} -> {} ", ipv4.header().source_addr(), ipv4.header().destination_addr()));
                    }
                    InternetSlice::Ipv6(ipv6) => {
                        summary.push_str(&format!("IPv6 {} -> {} ", ipv6.header().source_addr(), ipv6.header().destination_addr()));
                    }
                    InternetSlice::Arp(_arp) => {
                        summary.push_str("ARP packet ");
                    }
                }
            } else {
                summary.push_str("Non-IP packet ");
            }

            if let Some(transport) = value.transport {
                match transport {
                    TransportSlice::Tcp(tcp) => {
                        summary.push_str(&format!("TCP {} -> {} ", tcp.source_port(), tcp.destination_port()));
                        if tcp.syn() { summary.push_str("[SYN] "); }
                        if tcp.ack() { summary.push_str("[ACK] "); }
                    }
                    TransportSlice::Udp(udp) => {
                        summary.push_str(&format!("UDP {} -> {} ", udp.source_port(), udp.destination_port()));
                    }
                    TransportSlice::Icmpv4(_) => {
                        summary.push_str("ICMPv4 ");
                    }
                    TransportSlice::Icmpv6(_) => {
                        summary.push_str("ICMPv6 ");
                    }
                }
            }
        }
    }

    if summary.is_empty() {
        summary.push_str("Unknown packet");
    }
    
    summary
}
