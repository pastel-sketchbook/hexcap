use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::packet::CapturedPacket;

/// Pcap global header magic + version (little-endian, microsecond timestamps).
const PCAP_MAGIC: u32 = 0xA1B2_C3D4;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const SNAPLEN: u32 = 65535;
const LINKTYPE_ETHERNET: u32 = 1;

/// Write captured packets to a pcap file.
///
/// The file format follows the classic libpcap format:
/// global header (24 bytes) + per-packet (16-byte header + data).
pub fn write_pcap(path: &Path, packets: &[&CapturedPacket]) -> Result<usize> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;

    // Global header.
    file.write_all(&PCAP_MAGIC.to_le_bytes())?;
    file.write_all(&VERSION_MAJOR.to_le_bytes())?;
    file.write_all(&VERSION_MINOR.to_le_bytes())?;
    file.write_all(&0i32.to_le_bytes())?; // thiszone
    file.write_all(&0u32.to_le_bytes())?; // sigfigs
    file.write_all(&SNAPLEN.to_le_bytes())?;
    file.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;

    let mut count = 0usize;
    for pkt in packets {
        let (secs, usecs) = timestamp_to_epoch(pkt.timestamp);
        #[allow(clippy::cast_possible_truncation)]
        let caplen = pkt.data.len() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let origlen = pkt.length as u32;

        // Packet record header (16 bytes).
        file.write_all(&secs.to_le_bytes())?;
        file.write_all(&usecs.to_le_bytes())?;
        file.write_all(&caplen.to_le_bytes())?;
        file.write_all(&origlen.to_le_bytes())?;

        // Packet data.
        file.write_all(&pkt.data)?;
        count += 1;
    }

    file.flush()?;
    Ok(count)
}

/// Convert `SystemTime` to (seconds, microseconds) since Unix epoch.
fn timestamp_to_epoch(ts: SystemTime) -> (u32, u32) {
    match ts.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => {
            #[allow(clippy::cast_possible_truncation)]
            let secs = dur.as_secs() as u32;
            let usecs = dur.subsec_micros();
            (secs, usecs)
        }
        Err(_) => (0, 0),
    }
}

/// Read packets from a pcap file, returning raw packet data with timestamps.
///
/// Parses the global header and iterates packet records.
pub fn read_pcap(path: &Path) -> Result<Vec<(SystemTime, Vec<u8>)>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read {}", path.display()))?;

    if buf.len() < 24 {
        bail!("file too small for pcap global header");
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != PCAP_MAGIC {
        bail!("not a pcap file (bad magic: 0x{magic:08X})");
    }

    let mut packets = Vec::new();
    let mut pos = 24; // skip global header

    while pos + 16 <= buf.len() {
        let secs = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        let usecs = u32::from_le_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let caplen =
            u32::from_le_bytes([buf[pos + 8], buf[pos + 9], buf[pos + 10], buf[pos + 11]]) as usize;
        pos += 16;

        if pos + caplen > buf.len() {
            break; // truncated packet
        }

        let data = buf[pos..pos + caplen].to_vec();
        let timestamp = SystemTime::UNIX_EPOCH
            + Duration::from_secs(u64::from(secs))
            + Duration::from_micros(u64::from(usecs));

        packets.push((timestamp, data));
        pos += caplen;
    }

    Ok(packets)
}

/// Bookmark sidecar path: same as pcap path but with `.bookmarks` extension.
#[must_use]
pub fn bookmark_path(pcap_path: &Path) -> std::path::PathBuf {
    pcap_path.with_extension("pcap.bookmarks")
}

/// Save bookmark IDs to a sidecar file (one ID per line).
pub fn save_bookmarks(path: &Path, bookmarks: &std::collections::HashSet<u64>) -> Result<()> {
    if bookmarks.is_empty() {
        // Remove stale sidecar if no bookmarks.
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let mut ids: Vec<u64> = bookmarks.iter().copied().collect();
    ids.sort_unstable();
    let mut content = String::new();
    for id in &ids {
        let _ = writeln!(content, "{id}");
    }
    std::fs::write(path, content)
        .with_context(|| format!("failed to write bookmarks to {}", path.display()))?;
    Ok(())
}

/// Load bookmark IDs from a sidecar file.
pub fn load_bookmarks(path: &Path) -> Result<std::collections::HashSet<u64>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bookmarks from {}", path.display()))?;
    let mut set = std::collections::HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty()
            && let Ok(id) = trimmed.parse::<u64>()
        {
            set.insert(id);
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{CapturedPacket, Protocol};

    #[test]
    fn write_and_read_pcap_header() {
        let dir = std::env::temp_dir().join("hexcap_test_export.pcap");
        let pkt = CapturedPacket {
            id: 1,
            timestamp: SystemTime::now(),
            protocol: Protocol::Tcp,
            src: "1.2.3.4:80".into(),
            dst: "5.6.7.8:443".into(),
            length: 14,
            data: vec![0u8; 14],
            decoded: vec![],
            tcp_flags: 0,
        };
        let packets: Vec<&CapturedPacket> = vec![&pkt];
        let count = write_pcap(&dir, &packets).unwrap();
        assert_eq!(count, 1);

        // Verify global header magic.
        let bytes = std::fs::read(&dir).unwrap();
        assert!(bytes.len() >= 24 + 16 + 14);
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(magic, PCAP_MAGIC);

        std::fs::remove_file(&dir).ok();
    }
}
