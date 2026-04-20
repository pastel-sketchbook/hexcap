use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use pcap::{Capture, Device};
use tracing::{error, info};

use crate::app::App;
use crate::packet;

pub struct CaptureHandle {
    _handle: thread::JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl CaptureHandle {
    pub fn start(
        interface: Option<&str>,
        filter: Option<&str>,
        app: Arc<Mutex<App>>,
    ) -> Result<Self> {
        let device = match interface {
            Some(name) => Device::list()
                .context("failed to list devices")?
                .into_iter()
                .find(|d| d.name == name)
                .with_context(|| format!("interface '{name}' not found"))?,
            None => Device::lookup()
                .context("failed to lookup default device")?
                .context("no default device found")?,
        };

        // Store the active interface name.
        if let Ok(mut a) = app.lock() {
            a.interface_name.clone_from(&device.name);
        }

        info!(interface = %device.name, "starting capture");

        let mut cap = Capture::from_device(device)
            .context("failed to open device")?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .context("failed to activate capture")?;

        if let Some(f) = filter {
            cap.filter(f, true)
                .with_context(|| format!("bad BPF filter: {f}"))?;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            let mut counter: u64 = 0;
            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                match cap.next_packet() {
                    Ok(pkt) => {
                        counter += 1;
                        let parsed = packet::parse_packet(counter, pkt.data);
                        if let Ok(mut app) = app.lock() {
                            app.push_packet(parsed);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        error!(%e, "capture error");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            _handle: handle,
            stop,
        })
    }

    /// Signal the capture thread to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// List available network interfaces.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let devices = Device::list().context("failed to list devices")?;
    Ok(devices
        .into_iter()
        .map(|d| {
            let addrs: Vec<String> = d.addresses.iter().map(|a| format!("{}", a.addr)).collect();
            InterfaceInfo {
                name: d.name,
                description: d.desc.unwrap_or_default(),
                addresses: addrs,
            }
        })
        .collect())
}

/// Info about a network interface for display in the picker.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
}
