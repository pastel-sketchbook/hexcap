use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;

/// Resolve an IP address to a hostname using the system resolver.
///
/// This is a blocking call — always run from a background thread.
fn resolve_ip(ip: IpAddr) -> Option<String> {
    reverse_lookup(ip)
}

/// Reverse DNS lookup using libc `getnameinfo`.
#[allow(clippy::cast_possible_truncation)]
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem;

    let mut host_buf = [0u8; 256];

    // SAFETY: We zero-initialize the sockaddr structs and pass valid pointers.
    // The host buffer is stack-allocated with known size.
    unsafe {
        match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = mem::zeroed();
                sa.sin_family = libc::AF_INET.cast_unsigned() as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                let sa_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                let ret = libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast::<libc::sockaddr>(),
                    sa_len,
                    host_buf.as_mut_ptr().cast::<libc::c_char>(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                );
                if ret != 0 {
                    return None;
                }
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = mem::zeroed();
                sa.sin6_family = libc::AF_INET6.cast_unsigned() as libc::sa_family_t;
                sa.sin6_addr.s6_addr = v6.octets();
                let sa_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                let ret = libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast::<libc::sockaddr>(),
                    sa_len,
                    host_buf.as_mut_ptr().cast::<libc::c_char>(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                );
                if ret != 0 {
                    return None;
                }
            }
        }

        let hostname = CStr::from_ptr(host_buf.as_ptr().cast::<libc::c_char>())
            .to_str()
            .ok()?
            .to_string();

        // If the resolver just echoed back the IP, treat it as no result.
        if hostname == ip.to_string() {
            return None;
        }
        Some(hostname)
    }
}

/// Extract the IP portion from an address string like `1.2.3.4:80` or `[::1]:80`.
pub fn extract_ip(addr: &str) -> Option<IpAddr> {
    if let Some(rest) = addr.strip_prefix('[') {
        // [ipv6]:port
        let ip_str = rest.split(']').next()?;
        IpAddr::from_str(ip_str).ok()
    } else {
        // ipv4:port — take everything before the last colon
        let ip_str = addr.rsplit(':').next_back()?;
        IpAddr::from_str(ip_str).ok()
    }
}

/// Spawn a background thread to resolve IPs found in the current packet list.
/// Results are merged into `app.dns_cache`.
pub fn resolve_batch(
    addrs: Vec<String>,
    existing_keys: HashSet<IpAddr>,
    app: Arc<Mutex<crate::app::App>>,
) {
    thread::spawn(move || {
        let mut new_entries: HashMap<IpAddr, String> = HashMap::new();
        for addr in &addrs {
            if let Some(ip) = extract_ip(addr) {
                if existing_keys.contains(&ip) || new_entries.contains_key(&ip) {
                    continue;
                }
                if let Some(hostname) = resolve_ip(ip) {
                    new_entries.insert(ip, hostname);
                }
            }
        }
        if !new_entries.is_empty()
            && let Ok(mut a) = app.lock()
        {
            a.dns_cache.extend(new_entries);
        }
    });
}

/// Look up a resolved hostname for an address string, returning
/// `hostname (ip:port)` if found, or the original address if not.
#[must_use]
pub fn resolve_display(addr: &str, cache: &HashMap<IpAddr, String>) -> String {
    if let Some(ip) = extract_ip(addr)
        && let Some(hostname) = cache.get(&ip)
    {
        return format!("{hostname} ({addr})");
    }
    addr.to_string()
}
