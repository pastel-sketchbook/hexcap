use std::collections::HashSet;
use std::fmt;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Arp,
    Dns,
    Other(u8),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Arp => write!(f, "ARP"),
            Self::Dns => write!(f, "DNS"),
            Self::Other(n) => write!(f, "0x{n:02X}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub id: u64,
    pub timestamp: SystemTime,
    pub protocol: Protocol,
    pub src: String,
    pub dst: String,
    pub length: usize,
    pub data: Vec<u8>,
}

impl CapturedPacket {
    /// Check if either the source or destination port matches one of the given ports.
    pub fn matches_ports(&self, ports: &HashSet<u16>) -> bool {
        if ports.is_empty() {
            return true;
        }
        extract_port_from_addr(&self.src).is_some_and(|p| ports.contains(&p))
            || extract_port_from_addr(&self.dst).is_some_and(|p| ports.contains(&p))
    }
}

/// Extract port from "ip:port" address string.
fn extract_port_from_addr(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}

/// Minimal packet parser — extracts Ethernet → IP → protocol / addresses.
pub fn parse_packet(id: u64, data: &[u8]) -> CapturedPacket {
    let timestamp = SystemTime::now();
    let length = data.len();

    // Need at least an Ethernet header (14 bytes)
    if data.len() < 14 {
        return CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other(0),
            src: "??".into(),
            dst: "??".into(),
            length,
            data: data.to_vec(),
        };
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0806 => {
            // ARP
            CapturedPacket {
                id,
                timestamp,
                protocol: Protocol::Arp,
                src: format_mac(&data[6..12]),
                dst: format_mac(&data[0..6]),
                length,
                data: data.to_vec(),
            }
        }
        0x0800 => {
            // IPv4
            parse_ipv4(id, timestamp, data, length)
        }
        _ => CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other((ethertype >> 8) as u8),
            src: format_mac(&data[6..12]),
            dst: format_mac(&data[0..6]),
            length,
            data: data.to_vec(),
        },
    }
}

fn parse_ipv4(id: u64, timestamp: SystemTime, data: &[u8], length: usize) -> CapturedPacket {
    if data.len() < 34 {
        return CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other(0),
            src: "??".into(),
            dst: "??".into(),
            length,
            data: data.to_vec(),
        };
    }

    let ip = &data[14..];
    let proto_byte = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let ihl = ((ip[0] & 0x0F) as usize) * 4;

    let (protocol, src, dst) = match proto_byte {
        1 => (Protocol::Icmp, src_ip, dst_ip),
        6 => {
            // TCP
            let (sp, dp) = parse_ports(ip, ihl);
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Tcp },
                format!("{src_ip}:{sp}"),
                format!("{dst_ip}:{dp}"),
            )
        }
        17 => {
            // UDP
            let (sp, dp) = parse_ports(ip, ihl);
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Udp },
                format!("{src_ip}:{sp}"),
                format!("{dst_ip}:{dp}"),
            )
        }
        other => (Protocol::Other(other), src_ip, dst_ip),
    };

    CapturedPacket {
        id,
        timestamp,
        protocol,
        src,
        dst,
        length,
        data: data.to_vec(),
    }
}

fn parse_ports(ip: &[u8], ihl: usize) -> (u16, u16) {
    if ip.len() < ihl + 4 {
        return (0, 0);
    }
    let sp = u16::from_be_bytes([ip[ihl], ip[ihl + 1]]);
    let dp = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
    (sp, dp)
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}
