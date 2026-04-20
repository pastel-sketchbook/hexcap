use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

use crate::config;
use crate::packet::{CapturedPacket, FlowKey, Protocol};
use crate::process::ProcessInfo;
use crate::theme::{self, Theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    List,
    Detail,
    Flows,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InputMode {
    #[default]
    Normal,
    Search,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtoFilter {
    #[default]
    All,
    Tcp,
    Udp,
    Icmp,
    Dns,
    Arp,
}

impl ProtoFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Tcp,
            Self::Tcp => Self::Udp,
            Self::Udp => Self::Icmp,
            Self::Icmp => Self::Dns,
            Self::Dns => Self::Arp,
            Self::Arp => Self::All,
        }
    }

    pub fn matches(self, proto: Protocol) -> bool {
        match self {
            Self::All => true,
            Self::Tcp => proto == Protocol::Tcp,
            Self::Udp => proto == Protocol::Udp,
            Self::Icmp => proto == Protocol::Icmp,
            Self::Dns => proto == Protocol::Dns,
            Self::Arp => proto == Protocol::Arp,
        }
    }
}

impl fmt::Display for ProtoFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "All"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Dns => write!(f, "DNS"),
            Self::Arp => write!(f, "ARP"),
        }
    }
}

pub struct App {
    pub packets: VecDeque<CapturedPacket>,
    pub max_packets: usize,
    pub selected: usize,
    pub view: View,
    pub paused: bool,
    pub hex_scroll: u16,
    pub theme_index: usize,

    // -- Filtering --
    pub input_mode: InputMode,
    pub search_query: String,
    pub proto_filter: ProtoFilter,
    pub follow: bool,

    // -- Stats --
    pub total_bytes: u64,
    /// Bytes received in the current 1-second window.
    pub current_window_bytes: u64,
    /// Bandwidth history (bytes per second), most recent last. Fixed length.
    pub bandwidth_history: VecDeque<u64>,
    /// When the current 1-second window started.
    pub window_start: Instant,

    // -- Process filter --
    pub process_filter: Option<ProcessFilter>,
    pub process_picker: Option<ProcessPicker>,

    // -- Export --
    pub export_path: Option<PathBuf>,

    // -- Status message (auto-clears after a few seconds) --
    pub status_message: Option<(String, Instant)>,

    // -- Flow tracking --
    pub flows: Vec<FlowInfo>,
    pub flow_map: HashMap<FlowKey, usize>,
    pub flow_selected: usize,
    pub flow_filter: Option<FlowKey>,

    // -- Interface --
    pub interface_name: String,
    pub interface_picker: Option<InterfacePicker>,
    /// Set to Some(name) when user picks a new interface; main loop consumes it.
    pub pending_interface: Option<String>,

    // -- Bookmarks --
    /// Set of bookmarked packet IDs.
    pub bookmarks: HashSet<u64>,
}

/// Aggregated info for a single bidirectional flow.
#[derive(Debug, Clone)]
pub struct FlowInfo {
    pub key: FlowKey,
    pub protocol: Protocol,
    pub src: String,
    pub dst: String,
    pub packet_count: u64,
    pub total_bytes: u64,
}

/// Active process filter state.
#[derive(Debug, Clone)]
pub struct ProcessFilter {
    pub name: String,
    pub pid: u32,
    pub ports: HashSet<u16>,
}

/// Interactive process picker overlay.
#[derive(Debug, Clone)]
pub struct ProcessPicker {
    pub processes: Vec<ProcessInfo>,
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub query: String,
}

/// Interactive interface picker overlay.
#[derive(Debug, Clone)]
pub struct InterfacePicker {
    pub interfaces: Vec<crate::capture::InterfaceInfo>,
    pub selected: usize,
}

impl App {
    pub fn new(
        max_packets: usize,
        process_filter: Option<ProcessFilter>,
        export_path: Option<PathBuf>,
    ) -> Self {
        // Load persisted theme preference first, then fall back to Ghostty detection.
        let prefs = config::load_preferences();
        let theme_index = if prefs.theme != theme::THEMES[0].name || config::has_preferences_file()
        {
            theme::theme_index_by_name(&prefs.theme)
        } else {
            theme::detect_ghostty_theme().unwrap_or(0)
        };

        Self {
            packets: VecDeque::new(),
            max_packets,
            selected: 0,
            view: View::List,
            paused: false,
            hex_scroll: 0,
            theme_index,
            input_mode: InputMode::Normal,
            search_query: String::new(),
            proto_filter: ProtoFilter::All,
            follow: true,
            total_bytes: 0,
            current_window_bytes: 0,
            bandwidth_history: VecDeque::new(),
            window_start: Instant::now(),
            process_filter,
            process_picker: None,
            export_path,
            status_message: None,
            flows: Vec::new(),
            flow_map: HashMap::new(),
            flow_selected: 0,
            flow_filter: None,
            interface_name: String::new(),
            interface_picker: None,
            pending_interface: None,
            bookmarks: HashSet::new(),
        }
    }

    // -- Theme ---------------------------------------------------------------

    #[must_use]
    pub fn theme(&self) -> &'static Theme {
        &theme::THEMES[self.theme_index]
    }

    pub fn next_theme(&mut self) {
        self.theme_index = (self.theme_index + 1) % theme::THEMES.len();
        self.persist_preferences();
    }

    fn persist_preferences(&self) {
        let prefs = config::Preferences {
            theme: self.theme().name.to_string(),
        };
        let _ = config::save_preferences(&prefs);
    }

    // -- Filtering -----------------------------------------------------------

    /// Get the filtered view indices into `self.packets`.
    pub fn filtered_indices(&self) -> Vec<usize> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, p)| self.matches_filters(p))
            .map(|(i, _)| i)
            .collect()
    }

    fn matches_filters(&self, pkt: &CapturedPacket) -> bool {
        // Process port filter.
        if let Some(ref pf) = self.process_filter
            && !pf.ports.is_empty()
            && !pkt.matches_ports(&pf.ports)
        {
            return false;
        }
        if !self.proto_filter.matches(pkt.protocol) {
            return false;
        }
        if !self.search_query.is_empty() {
            let q = self.search_query.to_ascii_lowercase();
            let haystack = format!("{} {} {} {}", pkt.protocol, pkt.src, pkt.dst, pkt.length)
                .to_ascii_lowercase();
            if !haystack.contains(&q) {
                return false;
            }
        }
        // Flow filter.
        if let Some(ref fk) = self.flow_filter {
            let pkt_flow = FlowKey::new(&pkt.src, &pkt.dst);
            if &pkt_flow != fk {
                return false;
            }
        }
        true
    }

    pub fn next_proto_filter(&mut self) {
        self.proto_filter = self.proto_filter.next();
        self.clamp_selected();
    }

    pub fn start_search(&mut self) {
        self.input_mode = InputMode::Search;
    }

    pub fn cancel_search(&mut self) {
        self.input_mode = InputMode::Normal;
        self.search_query.clear();
    }

    pub fn confirm_search(&mut self) {
        self.input_mode = InputMode::Normal;
        self.clamp_selected();
    }

    pub fn search_push(&mut self, ch: char) {
        self.search_query.push(ch);
        self.clamp_selected();
    }

    pub fn search_pop(&mut self) {
        self.search_query.pop();
        self.clamp_selected();
    }

    fn clamp_selected(&mut self) {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            self.selected = 0;
        } else if !filtered.contains(&self.selected) {
            self.selected = *filtered.last().unwrap_or(&0);
        }
    }

    // -- Follow mode ---------------------------------------------------------

    pub fn toggle_follow(&mut self) {
        self.follow = !self.follow;
    }

    // -- Bandwidth tracking ---------------------------------------------------

    /// Maximum number of 1-second samples to keep for the sparkline.
    const BANDWIDTH_HISTORY_LEN: usize = 30;

    /// Call periodically (~every tick) to rotate bandwidth windows.
    pub fn tick_bandwidth(&mut self) {
        if self.window_start.elapsed().as_secs() >= 1 {
            self.bandwidth_history.push_back(self.current_window_bytes);
            while self.bandwidth_history.len() > Self::BANDWIDTH_HISTORY_LEN {
                self.bandwidth_history.pop_front();
            }
            self.current_window_bytes = 0;
            self.window_start = Instant::now();
        }
    }

    // -- Packets -------------------------------------------------------------

    pub fn push_packet(&mut self, pkt: CapturedPacket) {
        if self.paused {
            return;
        }
        self.total_bytes += pkt.length as u64;
        self.current_window_bytes += pkt.length as u64;

        // Update flow tracking.
        let flow = FlowKey::new(&pkt.src, &pkt.dst);
        let flow_idx = if let Some(&idx) = self.flow_map.get(&flow) {
            idx
        } else {
            let idx = self.flows.len();
            self.flows.push(FlowInfo {
                key: flow.clone(),
                protocol: pkt.protocol,
                src: pkt.src.clone(),
                dst: pkt.dst.clone(),
                packet_count: 0,
                total_bytes: 0,
            });
            self.flow_map.insert(flow, idx);
            idx
        };
        self.flows[flow_idx].packet_count += 1;
        self.flows[flow_idx].total_bytes += pkt.length as u64;

        self.packets.push_back(pkt);
        while self.packets.len() > self.max_packets {
            self.packets.pop_front();
            if self.selected > 0 {
                self.selected -= 1;
            }
        }
        if self.follow {
            let filtered = self.filtered_indices();
            if let Some(&last) = filtered.last() {
                self.selected = last;
            }
        }
    }

    // -- Navigation ----------------------------------------------------------

    pub fn next(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            if pos + 1 < filtered.len() {
                self.selected = filtered[pos + 1];
            }
        } else if let Some(&first) = filtered.first() {
            self.selected = first;
        }
    }

    pub fn previous(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            if pos > 0 {
                self.selected = filtered[pos - 1];
            }
        } else if let Some(&first) = filtered.first() {
            self.selected = first;
        }
    }

    pub fn first(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(&f) = filtered.first() {
            self.selected = f;
        }
    }

    pub fn last(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(&l) = filtered.last() {
            self.selected = l;
        }
    }

    pub fn open_detail(&mut self) {
        if self.selected_packet().is_some() {
            self.view = View::Detail;
            self.hex_scroll = 0;
        }
    }

    pub fn close_detail(&mut self) {
        self.view = View::List;
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.selected = 0;
        self.total_bytes = 0;
        self.flows.clear();
        self.flow_map.clear();
        self.flow_selected = 0;
        self.flow_filter = None;
    }

    // -- Flow view -----------------------------------------------------------

    pub fn open_flows(&mut self) {
        self.view = View::Flows;
        self.flow_selected = 0;
    }

    pub fn close_flows(&mut self) {
        self.view = View::List;
    }

    pub fn flow_next(&mut self) {
        if !self.flows.is_empty() && self.flow_selected + 1 < self.flows.len() {
            self.flow_selected += 1;
        }
    }

    pub fn flow_prev(&mut self) {
        if self.flow_selected > 0 {
            self.flow_selected -= 1;
        }
    }

    /// Apply a flow filter and return to the packet list.
    pub fn flow_select(&mut self) {
        if let Some(flow) = self.flows.get(self.flow_selected) {
            self.flow_filter = Some(flow.key.clone());
            self.view = View::List;
            self.clamp_selected();
        }
    }

    pub fn clear_flow_filter(&mut self) {
        self.flow_filter = None;
        self.clamp_selected();
    }

    // -- Interface picker ----------------------------------------------------

    pub fn open_interface_picker(&mut self, interfaces: Vec<crate::capture::InterfaceInfo>) {
        self.interface_picker = Some(InterfacePicker {
            interfaces,
            selected: 0,
        });
    }

    pub fn close_interface_picker(&mut self) {
        self.interface_picker = None;
    }

    pub fn iface_picker_next(&mut self) {
        if let Some(ref mut picker) = self.interface_picker
            && picker.selected + 1 < picker.interfaces.len()
        {
            picker.selected += 1;
        }
    }

    pub fn iface_picker_prev(&mut self) {
        if let Some(ref mut picker) = self.interface_picker
            && picker.selected > 0
        {
            picker.selected -= 1;
        }
    }

    pub fn iface_picker_select(&mut self) {
        let name = {
            let Some(picker) = &self.interface_picker else {
                return;
            };
            let Some(iface) = picker.interfaces.get(picker.selected) else {
                return;
            };
            iface.name.clone()
        };
        self.pending_interface = Some(name);
        self.interface_picker = None;
    }

    // -- Bookmarks -----------------------------------------------------------

    /// Toggle bookmark on the currently selected packet.
    pub fn toggle_bookmark(&mut self) {
        if let Some(pkt) = self.selected_packet() {
            let id = pkt.id;
            if !self.bookmarks.remove(&id) {
                self.bookmarks.insert(id);
            }
        }
    }

    /// Jump to the next bookmarked packet (forward from current selection).
    pub fn jump_next_bookmark(&mut self) {
        let filtered = self.filtered_indices();
        if let Some(cur_pos) = filtered.iter().position(|&i| i == self.selected) {
            // Search forward from current position.
            for &idx in &filtered[cur_pos + 1..] {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
            // Wrap around from the start.
            for &idx in &filtered[..cur_pos] {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
        }
    }

    /// Jump to the previous bookmarked packet.
    pub fn jump_prev_bookmark(&mut self) {
        let filtered = self.filtered_indices();
        if let Some(cur_pos) = filtered.iter().position(|&i| i == self.selected) {
            // Search backward.
            for &idx in filtered[..cur_pos].iter().rev() {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
            // Wrap around from the end.
            for &idx in filtered[cur_pos + 1..].iter().rev() {
                if let Some(pkt) = self.packets.get(idx)
                    && self.bookmarks.contains(&pkt.id)
                {
                    self.selected = idx;
                    self.follow = false;
                    return;
                }
            }
        }
    }

    pub fn scroll_down(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_add(1);
    }

    pub fn scroll_up(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_sub(1);
    }

    pub fn selected_packet(&self) -> Option<&CapturedPacket> {
        self.packets.get(self.selected)
    }

    // -- Process picker ------------------------------------------------------

    pub fn open_process_picker(&mut self, processes: Vec<ProcessInfo>) {
        let filtered: Vec<usize> = (0..processes.len()).collect();
        self.process_picker = Some(ProcessPicker {
            processes,
            filtered,
            selected: 0,
            query: String::new(),
        });
    }

    pub fn close_process_picker(&mut self) {
        self.process_picker = None;
    }

    pub fn picker_select(&mut self) {
        let info = {
            let Some(picker) = &self.process_picker else {
                return;
            };
            let Some(&idx) = picker.filtered.get(picker.selected) else {
                return;
            };
            picker.processes[idx].clone()
        };
        self.process_filter = Some(ProcessFilter {
            name: info.name,
            pid: info.pid,
            ports: info.ports,
        });
        self.process_picker = None;
        self.clamp_selected();
    }

    pub fn clear_process_filter(&mut self) {
        self.process_filter = None;
        self.clamp_selected();
    }

    pub fn picker_next(&mut self) {
        if let Some(ref mut picker) = self.process_picker
            && picker.selected + 1 < picker.filtered.len()
        {
            picker.selected += 1;
        }
    }

    pub fn picker_prev(&mut self) {
        if let Some(ref mut picker) = self.process_picker
            && picker.selected > 0
        {
            picker.selected -= 1;
        }
    }

    pub fn picker_push(&mut self, ch: char) {
        if let Some(ref mut picker) = self.process_picker {
            picker.query.push(ch);
            Self::refilter_picker(picker);
        }
    }

    pub fn picker_pop(&mut self) {
        if let Some(ref mut picker) = self.process_picker {
            picker.query.pop();
            Self::refilter_picker(picker);
        }
    }

    fn refilter_picker(picker: &mut ProcessPicker) {
        let q = picker.query.to_ascii_lowercase();
        picker.filtered = picker
            .processes
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                q.is_empty()
                    || p.name.to_ascii_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        if picker.selected >= picker.filtered.len() {
            picker.selected = picker.filtered.len().saturating_sub(1);
        }
    }

    /// Refresh process ports for the active filter (call periodically).
    pub fn refresh_process_ports(&mut self) {
        if let Some(ref mut pf) = self.process_filter
            && let Ok(info) = crate::process::resolve_process(&pf.name)
        {
            pf.ports = info.ports;
            pf.pid = info.pid;
        }
    }

    // -- Stats ---------------------------------------------------------------

    /// Set a temporary status message (displayed for ~3 seconds).
    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, Instant::now()));
    }

    /// Clear expired status messages (older than 3 seconds).
    pub fn tick_status(&mut self) {
        if let Some((_, at)) = &self.status_message
            && at.elapsed().as_secs() >= 3
        {
            self.status_message = None;
        }
    }

    /// Export visible (filtered) packets to the configured pcap path.
    /// Returns a status message describing the result.
    pub fn export_packets(&self) -> String {
        let Some(ref path) = self.export_path else {
            return "No export path set (use --write <file>)".into();
        };
        let filtered = self.filtered_indices();
        let packets: Vec<&crate::packet::CapturedPacket> = filtered
            .iter()
            .filter_map(|&i| self.packets.get(i))
            .collect();
        match crate::export::write_pcap(path.as_path(), &packets) {
            Ok(n) => format!("Exported {n} packets to {}", path.display()),
            Err(e) => format!("Export failed: {e}"),
        }
    }

    pub fn proto_counts(&self) -> ProtoCounts {
        let mut counts = ProtoCounts::default();
        for p in &self.packets {
            match p.protocol {
                Protocol::Tcp => counts.tcp += 1,
                Protocol::Udp => counts.udp += 1,
                Protocol::Icmp => counts.icmp += 1,
                Protocol::Dns => counts.dns += 1,
                Protocol::Arp => counts.arp += 1,
                Protocol::Other(_) => counts.other += 1,
            }
        }
        counts
    }
}

#[derive(Debug, Default)]
pub struct ProtoCounts {
    pub tcp: usize,
    pub udp: usize,
    pub icmp: usize,
    pub dns: usize,
    pub arp: usize,
    pub other: usize,
}
