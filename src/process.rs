//! Process-to-socket resolution via `lsof`.
//!
//! Resolves which ports a process is listening on / connected to,
//! so hexcap can filter captured packets to a specific process.

use std::collections::HashSet;
use std::process::Command;

use anyhow::{Context, Result};

/// A process with network sockets.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub ports: HashSet<u16>,
}

/// List all processes that have open IPv4/IPv6 network sockets.
/// Returns a de-duplicated list sorted by process name.
pub fn list_network_processes() -> Result<Vec<ProcessInfo>> {
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P", "-F", "pcn"])
        .output()
        .context("failed to run lsof")?;

    if !output.status.success() {
        anyhow::bail!("lsof failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_lsof_output(&text))
}

/// Resolve ports for a specific process by name or PID.
pub fn resolve_process(query: &str) -> Result<ProcessInfo> {
    let procs = list_network_processes()?;

    // Try PID match first.
    if let Ok(pid) = query.parse::<u32>()
        && let Some(p) = procs.iter().find(|p| p.pid == pid)
    {
        return Ok(p.clone());
    }

    // Fuzzy name match (case-insensitive contains).
    let lower = query.to_ascii_lowercase();
    let matches: Vec<&ProcessInfo> = procs
        .iter()
        .filter(|p| p.name.to_ascii_lowercase().contains(&lower))
        .collect();

    match matches.len() {
        0 => anyhow::bail!("no process found matching '{query}'"),
        1 => Ok(matches[0].clone()),
        _ => {
            // Merge all matching processes (same name, multiple PIDs).
            let mut merged = ProcessInfo {
                pid: matches[0].pid,
                name: matches[0].name.clone(),
                ports: HashSet::new(),
            };
            for m in &matches {
                merged.ports.extend(&m.ports);
            }
            Ok(merged)
        }
    }
}

/// Parse lsof -F pcn output into process list.
fn parse_lsof_output(text: &str) -> Vec<ProcessInfo> {
    use std::collections::HashMap;

    let mut by_pid: HashMap<u32, ProcessInfo> = HashMap::new();
    let mut current_pid: Option<u32> = None;
    let mut current_name: Option<String> = None;

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let tag = line.as_bytes()[0];
        let value = &line[1..];

        match tag {
            b'p' => {
                if let Ok(pid) = value.parse::<u32>() {
                    current_pid = Some(pid);
                }
            }
            b'c' => {
                current_name = Some(value.to_string());
            }
            b'n' => {
                if let (Some(pid), Some(name)) = (current_pid, &current_name)
                    && let Some(port) = extract_port(value)
                {
                    let entry = by_pid.entry(pid).or_insert_with(|| ProcessInfo {
                        pid,
                        name: name.clone(),
                        ports: HashSet::new(),
                    });
                    entry.ports.insert(port);
                }
            }
            _ => {}
        }
    }

    let mut procs: Vec<ProcessInfo> = by_pid.into_values().collect();
    procs.sort_by_key(|a| a.name.to_ascii_lowercase());
    procs
}

/// Extract port from lsof network name field.
/// Handles formats like `192.168.1.1:443`, `*:80`, `[::1]:8080`, `localhost:3000`.
fn extract_port(name: &str) -> Option<u16> {
    // Take local part (before "->") if this is an established connection.
    let local = name.split("->").next()?;
    // Port is after the last ':'.
    let port_str = local.rsplit(':').next()?;
    port_str.trim().parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_port_ipv4() {
        assert_eq!(extract_port("192.168.1.1:443"), Some(443));
    }

    #[test]
    fn extract_port_wildcard() {
        assert_eq!(extract_port("*:80"), Some(80));
    }

    #[test]
    fn extract_port_ipv6() {
        assert_eq!(extract_port("[::1]:8080"), Some(8080));
    }

    #[test]
    fn extract_port_with_arrow() {
        assert_eq!(extract_port("10.0.0.1:5000->10.0.0.2:443"), Some(5000));
    }

    #[test]
    fn extract_port_none() {
        assert_eq!(extract_port("pipe"), None);
    }

    #[test]
    fn parse_lsof_basic() {
        let input = "p1234\ncMyApp\nn192.168.1.1:8080\nn*:443\n";
        let procs = parse_lsof_output(input);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 1234);
        assert_eq!(procs[0].name, "MyApp");
        assert!(procs[0].ports.contains(&8080));
        assert!(procs[0].ports.contains(&443));
    }
}
