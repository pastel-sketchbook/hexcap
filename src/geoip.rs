use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

/// `GeoIP` database wrapper using `MaxMind`'s `.mmdb` format.
pub struct GeoDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    /// Open a `MaxMind` database file (`.mmdb`).
    pub fn open(path: &Path) -> Result<Self> {
        let reader =
            maxminddb::Reader::open_readfile(path).context("failed to open GeoIP database")?;
        Ok(Self { reader })
    }

    /// Look up a country ISO code for an IP address.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        if !is_global(ip) {
            return None;
        }
        let result = self.reader.lookup(ip).ok()?;
        let country: maxminddb::geoip2::Country = result.decode().ok()??;
        country.country.iso_code.map(String::from)
    }
}

/// Batch-resolve IPs using a `GeoIP` database, updating a cache.
pub fn resolve_batch(db: &GeoDb, ips: &[IpAddr], cache: &mut HashMap<IpAddr, String>) {
    for &ip in ips {
        if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(ip)
            && let Some(code) = db.country(ip)
        {
            e.insert(code);
        }
    }
}

/// Format an address with `GeoIP` country code if available.
#[must_use]
pub fn geo_display(addr: &str, cache: &HashMap<IpAddr, String>) -> String {
    if let Some(ip) = extract_ip(addr)
        && let Some(code) = cache.get(&ip)
    {
        return format!("{addr} [{code}]");
    }
    addr.to_string()
}

/// Extract IP address from `ip:port` or `[ipv6]:port` format.
fn extract_ip(addr: &str) -> Option<IpAddr> {
    let ip_str = if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next()?
    } else if let Some(idx) = addr.rfind(':') {
        let after = &addr[idx + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            &addr[..idx]
        } else {
            addr
        }
    } else {
        addr
    };
    ip_str.parse().ok()
}

/// Check if an IP is globally routable (not private/reserved).
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.octets().starts_with(&[100]) // 100.64.0.0/10 CGNAT
                && !v4.octets().starts_with(&[169, 254]) // link-local
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}
