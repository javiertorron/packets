use std::collections::HashMap;
use chrono::{DateTime, Local};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use dns_parser::Packet as DnsPacket;

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub target_ip: String,
    pub target_domain: Option<String>,
    pub port: u16,
    pub protocol: &'static str,
    pub category: String,
    pub bytes_transferred: usize,
    pub last_seen: DateTime<Local>,
}

pub struct Profiler {
    // Map local IP -> (Target IP -> ConnectionInfo)
    pub hosts: HashMap<String, HashMap<String, ConnectionInfo>>,
    // Map IP -> Domain (from DNS snooping)
    pub dns_cache: HashMap<String, String>,
}

impl Profiler {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            dns_cache: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, packet: &crate::capture::PacketInfo) {
        let sliced = match SlicedPacket::from_ethernet(&packet.raw_data) {
            Ok(s) => s,
            Err(_) => return,
        };

        let (src_ip, dst_ip) = if let Some(net) = sliced.net {
            match net {
                InternetSlice::Ipv4(ipv4) => (ipv4.header().source_addr().to_string(), ipv4.header().destination_addr().to_string()),
                InternetSlice::Ipv6(ipv6) => (ipv6.header().source_addr().to_string(), ipv6.header().destination_addr().to_string()),
                _ => return,
            }
        } else {
            return;
        };

        let is_src_local = is_local_ip(&src_ip);
        let is_dst_local = is_local_ip(&dst_ip);

        let (local_ip, remote_ip, direction) = if is_src_local && !is_dst_local {
            (src_ip.clone(), dst_ip.clone(), "outbound")
        } else if !is_src_local && is_dst_local {
            (dst_ip.clone(), src_ip.clone(), "inbound")
        } else {
            // Traffic between two local IPs or two remote IPs
            (src_ip.clone(), dst_ip.clone(), "internal")
        };

        let mut port = 0;
        let mut protocol = "Unknown";
        
        if let Some(transport) = sliced.transport {
            match transport {
                TransportSlice::Tcp(tcp) => {
                    port = if direction == "inbound" { tcp.source_port() } else { tcp.destination_port() };
                    protocol = "TCP";
                }
                TransportSlice::Udp(udp) => {
                    port = if direction == "inbound" { udp.source_port() } else { udp.destination_port() };
                    protocol = "UDP";

                    // DNS Snooping (Intercept DNS responses)
                    if udp.source_port() == 53 {
                        if let Ok(dns_packet) = DnsPacket::parse(sliced.payload) {
                            for answer in dns_packet.answers {
                                match answer.data {
                                    dns_parser::rdata::RData::A(rdata) => {
                                        let ip = rdata.0.to_string();
                                        self.dns_cache.insert(ip, answer.name.to_string());
                                    }
                                    dns_parser::rdata::RData::AAAA(rdata) => {
                                        let ip = rdata.0.to_string();
                                        self.dns_cache.insert(ip, answer.name.to_string());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let domain = self.dns_cache.get(&remote_ip).cloned();
        let category = categorize_traffic(port, &domain);

        let connections = self.hosts.entry(local_ip).or_insert_with(HashMap::new);
        let conn = connections.entry(remote_ip.clone()).or_insert(ConnectionInfo {
            target_ip: remote_ip,
            target_domain: domain.clone(),
            port,
            protocol,
            category: category.clone(),
            bytes_transferred: 0,
            last_seen: packet.timestamp,
        });

        conn.bytes_transferred += packet.length as usize;
        conn.last_seen = packet.timestamp;
        
        // Update domain/category if we discovered it later
        if conn.target_domain.is_none() && domain.is_some() {
            conn.target_domain = domain;
            conn.category = category;
        }
    }
}

fn is_local_ip(ip: &str) -> bool {
    ip.starts_with("192.168.") || 
    ip.starts_with("10.") || 
    ip.starts_with("127.") || 
    ip.starts_with("172.16.") || ip.starts_with("172.17.") || ip.starts_with("172.18.") || ip.starts_with("172.19.") || 
    ip.starts_with("172.20.") || ip.starts_with("172.21.") || ip.starts_with("172.22.") || ip.starts_with("172.23.") || 
    ip.starts_with("172.24.") || ip.starts_with("172.25.") || ip.starts_with("172.26.") || ip.starts_with("172.27.") || 
    ip.starts_with("172.28.") || ip.starts_with("172.29.") || ip.starts_with("172.30.") || ip.starts_with("172.31.")
}

fn categorize_traffic(port: u16, domain: &Option<String>) -> String {
    if let Some(d) = domain {
        let d = d.to_lowercase();
        if d.contains("youtube.com") || d.contains("googlevideo.com") || d.contains("netflix.com") || d.contains("nflxvideo.net") || d.contains("twitch.tv") {
            return "🎥 Streaming Vídeo".to_string();
        }
        if d.contains("steampowered.com") || d.contains("valve.net") || d.contains("riotgames.com") || d.contains("epicgames.com") || d.contains("ea.com") || d.contains("blizzard.com") {
            return "🎮 Videojuego".to_string();
        }
        if d.contains("whatsapp.net") || d.contains("discord.gg") || d.contains("discordapp.com") || d.contains("telegram.org") || d.contains("slack.com") {
            return "💬 Mensajería".to_string();
        }
        if d.contains("zoom.us") || d.contains("meet.google.com") || d.contains("teams.microsoft.com") || d.contains("skype.com") {
            return "📹 Videollamada".to_string();
        }
        if d.contains("spotify.com") || d.contains("sndcdn.com") {
            return "🎵 Audio".to_string();
        }
        if d.contains("google.com") || d.contains("bing.com") || d.contains("duckduckgo.com") {
            return "🔍 Búsqueda".to_string();
        }
        if d.contains("github.com") || d.contains("gitlab.com") || d.contains("bitbucket.org") {
            return "💻 Desarrollo".to_string();
        }
    }
    
    match port {
        443 => "🔒 Web (HTTPS)".to_string(),
        80 => "🌐 Web (HTTP)".to_string(),
        53 => "📖 DNS".to_string(),
        22 => "🔑 SSH".to_string(),
        21 => "📁 FTP".to_string(),
        _ => "Desconocido".to_string(),
    }
}
