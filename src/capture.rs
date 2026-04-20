use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use pcap::{Capture, Device};
use tracing::{error, info};

use crate::app::App;
use crate::packet;

pub struct CaptureHandle {
    _handle: thread::JoinHandle<()>,
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

        let handle = thread::spawn(move || {
            let mut counter: u64 = 0;
            loop {
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

        Ok(Self { _handle: handle })
    }
}
