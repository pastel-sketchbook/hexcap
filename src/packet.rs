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
    pub decoded: Vec<DecodedField>,
}

/// A decoded header field for display in the detail view.
#[derive(Debug, Clone)]
pub struct DecodedField {
    pub label: String,
    pub value: String,
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

/// Extract port from address string. Handles `ip:port` and `[ipv6]:port`.
fn extract_port_from_addr(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        // [ipv6]:port
        let after_bracket = rest.split(']').nth(1)?;
        after_bracket.strip_prefix(':')?.parse().ok()
    } else {
        addr.rsplit(':').next()?.parse().ok()
    }
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
            decoded: vec![],
        };
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0806 => {
            // ARP
            let decoded = decode_arp(data);
            CapturedPacket {
                id,
                timestamp,
                protocol: Protocol::Arp,
                src: format_mac(&data[6..12]),
                dst: format_mac(&data[0..6]),
                length,
                data: data.to_vec(),
                decoded,
            }
        }
        0x0800 => parse_ipv4(id, timestamp, data, length),
        0x86DD => parse_ipv6(id, timestamp, data, length),
        _ => CapturedPacket {
            id,
            timestamp,
            #[allow(clippy::cast_possible_truncation)]
            protocol: Protocol::Other((ethertype >> 8) as u8),
            src: format_mac(&data[6..12]),
            dst: format_mac(&data[0..6]),
            length,
            data: data.to_vec(),
            decoded: vec![field("EtherType", format!("0x{ethertype:04X}"))],
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
            decoded: vec![],
        };
    }

    let ip = &data[14..];
    let proto_byte = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let ttl = ip[8];
    let total_len = u16::from_be_bytes([ip[2], ip[3]]);
    let ip_id = u16::from_be_bytes([ip[4], ip[5]]);
    let flags_frag = u16::from_be_bytes([ip[6], ip[7]]);
    let ihl = ((ip[0] & 0x0F) as usize) * 4;

    let mut decoded = vec![
        field("Version", "IPv4".into()),
        field("TTL", ttl.to_string()),
        field("Total Length", total_len.to_string()),
        field("ID", format!("0x{ip_id:04X}")),
        field("Flags", format_ip_flags(flags_frag)),
    ];

    let (protocol, src, dst) = match proto_byte {
        1 => {
            decoded.extend(decode_icmp(ip, ihl));
            (Protocol::Icmp, src_ip, dst_ip)
        }
        6 => {
            let (sp, dp) = parse_ports(ip, ihl);
            decoded.extend(decode_tcp(ip, ihl));
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Tcp },
                format!("{src_ip}:{sp}"),
                format!("{dst_ip}:{dp}"),
            )
        }
        17 => {
            let (sp, dp) = parse_ports(ip, ihl);
            decoded.extend(decode_udp(ip, ihl));
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Udp },
                format!("{src_ip}:{sp}"),
                format!("{dst_ip}:{dp}"),
            )
        }
        other => {
            decoded.push(field("IP Protocol", format!("0x{other:02X}")));
            (Protocol::Other(other), src_ip, dst_ip)
        }
    };

    CapturedPacket {
        id,
        timestamp,
        protocol,
        src,
        dst,
        length,
        data: data.to_vec(),
        decoded,
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

fn parse_ipv6(id: u64, timestamp: SystemTime, data: &[u8], length: usize) -> CapturedPacket {
    if data.len() < 54 {
        return CapturedPacket {
            id,
            timestamp,
            protocol: Protocol::Other(0),
            src: "??".into(),
            dst: "??".into(),
            length,
            data: data.to_vec(),
            decoded: vec![],
        };
    }

    let ip6 = &data[14..];
    let next_header = ip6[6];
    let hop_limit = ip6[7];
    let payload_len = u16::from_be_bytes([ip6[4], ip6[5]]);
    let src_ip = format_ipv6(&ip6[8..24]);
    let dst_ip = format_ipv6(&ip6[24..40]);

    let transport_offset = 40;

    let mut decoded = vec![
        field("Version", "IPv6".into()),
        field("Hop Limit", hop_limit.to_string()),
        field("Payload Length", payload_len.to_string()),
    ];

    let (protocol, src, dst) = match next_header {
        58 => {
            decoded.extend(decode_icmp(ip6, transport_offset));
            (Protocol::Icmp, src_ip, dst_ip)
        }
        6 => {
            let (sp, dp) = parse_ports(ip6, transport_offset);
            decoded.extend(decode_tcp(ip6, transport_offset));
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Tcp },
                format!("[{src_ip}]:{sp}"),
                format!("[{dst_ip}]:{dp}"),
            )
        }
        17 => {
            let (sp, dp) = parse_ports(ip6, transport_offset);
            decoded.extend(decode_udp(ip6, transport_offset));
            let is_dns = sp == 53 || dp == 53;
            (
                if is_dns { Protocol::Dns } else { Protocol::Udp },
                format!("[{src_ip}]:{sp}"),
                format!("[{dst_ip}]:{dp}"),
            )
        }
        other => {
            decoded.push(field("Next Header", format!("0x{other:02X}")));
            (Protocol::Other(other), src_ip, dst_ip)
        }
    };

    CapturedPacket {
        id,
        timestamp,
        protocol,
        src,
        dst,
        length,
        data: data.to_vec(),
        decoded,
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    let groups: Vec<String> = (0..8)
        .map(|i| {
            let hi = bytes[i * 2];
            let lo = bytes[i * 2 + 1];
            format!("{:x}", u16::from_be_bytes([hi, lo]))
        })
        .collect();
    // Simple compression: join with colons (no :: shortening for clarity).
    groups.join(":")
}

fn field(label: &str, value: String) -> DecodedField {
    DecodedField {
        label: label.into(),
        value,
    }
}

fn format_ip_flags(flags_frag: u16) -> String {
    let df = flags_frag & 0x4000 != 0;
    let mf = flags_frag & 0x2000 != 0;
    let offset = flags_frag & 0x1FFF;
    let mut parts = Vec::new();
    if df {
        parts.push("DF");
    }
    if mf {
        parts.push("MF");
    }
    if offset > 0 {
        return format!("{} off={offset}", parts.join(","));
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(",")
    }
}

fn decode_tcp(ip: &[u8], offset: usize) -> Vec<DecodedField> {
    if ip.len() < offset + 20 {
        return vec![];
    }
    let t = &ip[offset..];
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
    let flags_byte = t[13];
    let window = u16::from_be_bytes([t[14], t[15]]);

    let mut flags = Vec::new();
    if flags_byte & 0x01 != 0 {
        flags.push("FIN");
    }
    if flags_byte & 0x02 != 0 {
        flags.push("SYN");
    }
    if flags_byte & 0x04 != 0 {
        flags.push("RST");
    }
    if flags_byte & 0x08 != 0 {
        flags.push("PSH");
    }
    if flags_byte & 0x10 != 0 {
        flags.push("ACK");
    }
    if flags_byte & 0x20 != 0 {
        flags.push("URG");
    }

    vec![
        field("Seq", seq.to_string()),
        field("Ack", ack.to_string()),
        field("Flags", flags.join(",")),
        field("Window", window.to_string()),
    ]
}

fn decode_udp(ip: &[u8], offset: usize) -> Vec<DecodedField> {
    if ip.len() < offset + 8 {
        return vec![];
    }
    let t = &ip[offset..];
    let udp_len = u16::from_be_bytes([t[4], t[5]]);
    let checksum = u16::from_be_bytes([t[6], t[7]]);
    vec![
        field("UDP Length", udp_len.to_string()),
        field("Checksum", format!("0x{checksum:04X}")),
    ]
}

fn decode_icmp(ip: &[u8], offset: usize) -> Vec<DecodedField> {
    if ip.len() < offset + 4 {
        return vec![];
    }
    let t = &ip[offset..];
    let icmp_type = t[0];
    let icmp_code = t[1];
    let type_name = match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        128 => "Echo Request (v6)",
        129 => "Echo Reply (v6)",
        _ => "Other",
    };
    vec![
        field("Type", format!("{icmp_type} ({type_name})")),
        field("Code", icmp_code.to_string()),
    ]
}

fn decode_arp(data: &[u8]) -> Vec<DecodedField> {
    if data.len() < 42 {
        return vec![field("ARP", "truncated".into())];
    }
    let arp = &data[14..];
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    let op_name = match op {
        1 => "Request",
        2 => "Reply",
        _ => "Other",
    };
    let sender_ip = format!("{}.{}.{}.{}", arp[14], arp[15], arp[16], arp[17]);
    let target_ip = format!("{}.{}.{}.{}", arp[24], arp[25], arp[26], arp[27]);
    let sender_mac = format_mac(&arp[8..14]);
    vec![
        field("Operation", format!("{op} ({op_name})")),
        field("Sender MAC", sender_mac),
        field("Sender IP", sender_ip),
        field("Target IP", target_ip),
    ]
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}
