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
    Stream,
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

#[allow(clippy::struct_excessive_bools)]
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
    /// Display filter expression (e.g., "tcp port:443 !dns").
    pub display_filter: String,
    /// Whether the display filter input bar is active.
    pub display_filter_editing: bool,
    /// Buffer for editing the display filter.
    pub display_filter_buf: String,
    pub follow: bool,
    /// Follow mode scroll interval: 1 = every packet, 5 = every 5th, etc.
    pub follow_interval: u64,
    /// Counter for follow interval throttling.
    pub follow_counter: u64,

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

    // -- Annotations --
    /// User notes per packet ID.
    pub annotations: HashMap<u64, String>,
    /// When set, we're editing an annotation for this packet ID.
    pub annotating: Option<u64>,
    /// Text buffer for annotation input.
    pub annotation_buf: String,

    // -- Capture timing --
    /// When capture started (or packets were loaded).
    pub capture_start: Instant,
    /// Rolling packet count for packets-per-second calculation.
    pub pps_counter: u64,
    /// Last computed packets-per-second value.
    pub pps: u64,

    // -- DNS resolution cache --
    pub dns_cache: HashMap<std::net::IpAddr, String>,
    pub dns_enabled: bool,

    // -- GeoIP cache --
    pub geoip_cache: HashMap<std::net::IpAddr, String>,
    pub geoip_enabled: bool,

    // -- TCP stream follow --
    /// Reassembled TCP stream payload for the current flow.
    pub stream_data: Vec<u8>,
    pub stream_scroll: u16,

    // -- Column widths --
    /// Index of the column currently being resized (0-5).
    pub resize_column: usize,
    /// Extra width adjustments per column.
    pub column_widths: [i16; 6],

    // -- Help overlay --
    pub show_help: bool,

    // -- Stats summary overlay --
    pub show_stats_summary: bool,

    // -- Packet diff --
    /// First packet ID marked for diff comparison.
    pub diff_mark: Option<u64>,
    /// When set, show diff overlay comparing these two packet indices.
    pub diff_pair: Option<(usize, usize)>,
}

/// Aggregated info for a single bidirectional flow.
#[derive(Debug, Clone, serde::Serialize)]
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
            display_filter: String::new(),
            display_filter_editing: false,
            display_filter_buf: String::new(),
            follow: true,
            follow_interval: 1,
            follow_counter: 0,
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
            annotations: HashMap::new(),
            annotating: None,
            annotation_buf: String::new(),
            capture_start: Instant::now(),
            pps_counter: 0,
            pps: 0,
            dns_cache: HashMap::new(),
            dns_enabled: false,
            geoip_cache: HashMap::new(),
            geoip_enabled: false,
            stream_data: Vec::new(),
            stream_scroll: 0,
            resize_column: 0,
            column_widths: [0; 6],
            show_help: false,
            show_stats_summary: false,
            diff_mark: None,
            diff_pair: None,
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
            // First try matching against metadata (protocol, addresses, length).
            let haystack = format!("{} {} {} {}", pkt.protocol, pkt.src, pkt.dst, pkt.length)
                .to_ascii_lowercase();
            if !haystack.contains(&q) {
                // Fall back to payload search: try ASCII substring in raw bytes,
                // then hex pattern (e.g. "ff d8" or "ffd8").
                if !payload_contains_ascii(&pkt.data, &q) && !payload_contains_hex(&pkt.data, &q) {
                    return false;
                }
            }
        }
        // Flow filter.
        if let Some(ref fk) = self.flow_filter {
            let pkt_flow = FlowKey::new(&pkt.src, &pkt.dst);
            if &pkt_flow != fk {
                return false;
            }
        }
        // Display filter.
        if !self.display_filter.is_empty() && !matches_display_filter(pkt, &self.display_filter) {
            return false;
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

    /// Cycle follow speed: off → 1x → 5x → 10x → 25x → off.
    pub fn cycle_follow_speed(&mut self) {
        if self.follow {
            self.follow_interval = match self.follow_interval {
                1 => 5,
                5 => 10,
                10 => 25,
                _ => {
                    self.follow = false;
                    self.set_status("Follow: off".into());
                    return;
                }
            };
        } else {
            self.follow = true;
            self.follow_interval = 1;
        }
        self.follow_counter = 0;
        let label = if self.follow_interval == 1 {
            "Follow: every packet".into()
        } else {
            format!("Follow: every {}th packet", self.follow_interval)
        };
        self.set_status(label);
    }

    // -- Bandwidth tracking ---------------------------------------------------

    /// Maximum number of 1-second samples to keep for the sparkline.
    const BANDWIDTH_HISTORY_LEN: usize = 30;

    /// Call periodically (~every tick) to rotate bandwidth windows and compute PPS.
    pub fn tick_bandwidth(&mut self) {
        if self.window_start.elapsed().as_secs() >= 1 {
            self.bandwidth_history.push_back(self.current_window_bytes);
            while self.bandwidth_history.len() > Self::BANDWIDTH_HISTORY_LEN {
                self.bandwidth_history.pop_front();
            }
            self.current_window_bytes = 0;
            self.pps = self.pps_counter;
            self.pps_counter = 0;
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
        self.pps_counter += 1;

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
            self.follow_counter += 1;
            if self.follow_counter >= self.follow_interval {
                self.follow_counter = 0;
                let filtered = self.filtered_indices();
                if let Some(&last) = filtered.last() {
                    self.selected = last;
                }
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

    const PAGE_SIZE: usize = 20;

    pub fn page_down(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            let target = (pos + Self::PAGE_SIZE).min(filtered.len().saturating_sub(1));
            self.selected = filtered[target];
        }
    }

    pub fn page_up(&mut self) {
        self.follow = false;
        let filtered = self.filtered_indices();
        if let Some(pos) = filtered.iter().position(|&i| i == self.selected) {
            let target = pos.saturating_sub(Self::PAGE_SIZE);
            self.selected = filtered[target];
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

    // -- TCP stream follow ---------------------------------------------------

    /// Open the TCP stream view for the currently selected packet's flow.
    pub fn open_stream(&mut self) {
        let Some(pkt) = self.selected_packet() else {
            return;
        };
        if pkt.protocol != Protocol::Tcp {
            self.set_status("Follow stream only works for TCP packets".into());
            return;
        }
        let flow = FlowKey::new(&pkt.src, &pkt.dst);

        // Reassemble: collect TCP payload bytes from all packets in this flow,
        // in capture order. This is a simple concatenation (not sequence-number ordered).
        let mut payload = Vec::new();
        for p in &self.packets {
            if p.protocol != Protocol::Tcp {
                continue;
            }
            let pkt_flow = FlowKey::new(&p.src, &p.dst);
            if pkt_flow != flow {
                continue;
            }
            // Extract TCP payload: skip Ethernet(14) + IP header + TCP header.
            if let Some(tcp_payload) = extract_tcp_payload(&p.data) {
                payload.extend_from_slice(tcp_payload);
            }
        }

        self.stream_data = payload;
        self.stream_scroll = 0;
        self.view = View::Stream;
    }

    pub fn close_stream(&mut self) {
        self.view = View::Detail;
    }

    pub fn stream_scroll_down(&mut self) {
        self.stream_scroll = self.stream_scroll.saturating_add(1);
    }

    pub fn stream_scroll_up(&mut self) {
        self.stream_scroll = self.stream_scroll.saturating_sub(1);
    }

    // -- Column resizing -----------------------------------------------------

    pub fn next_resize_column(&mut self) {
        self.resize_column = (self.resize_column + 1) % 6;
    }

    pub fn widen_column(&mut self) {
        self.column_widths[self.resize_column] =
            self.column_widths[self.resize_column].saturating_add(2);
    }

    pub fn narrow_column(&mut self) {
        self.column_widths[self.resize_column] =
            self.column_widths[self.resize_column].saturating_sub(2);
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

    /// Mark current packet for diff, or open diff if a mark already exists.
    pub fn mark_or_diff(&mut self) {
        let Some(pkt) = self.selected_packet() else {
            return;
        };
        let current_id = pkt.id;
        let current_idx = self.selected;

        if let Some(mark_id) = self.diff_mark {
            if mark_id == current_id {
                self.diff_mark = None;
                self.set_status("Diff mark cleared".into());
                return;
            }
            if let Some(mark_idx) = self.packets.iter().position(|p| p.id == mark_id) {
                self.diff_pair = Some((mark_idx, current_idx));
                self.diff_mark = None;
            } else {
                self.set_status("Marked packet no longer in buffer".into());
                self.diff_mark = None;
            }
        } else {
            self.diff_mark = Some(current_id);
            self.set_status(format!(
                "Marked #{current_id} for diff — select another and press x"
            ));
        }
    }

    pub fn scroll_down(&mut self) {
        self.hex_scroll = self.hex_scroll.saturating_add(1);
    }

    // -- Annotations ---------------------------------------------------------

    /// Start editing an annotation for the selected packet.
    pub fn start_annotate(&mut self) {
        if let Some(pkt) = self.selected_packet() {
            let id = pkt.id;
            self.annotation_buf = self.annotations.get(&id).cloned().unwrap_or_default();
            self.annotating = Some(id);
        }
    }

    /// Confirm the annotation input.
    pub fn confirm_annotate(&mut self) {
        if let Some(id) = self.annotating.take() {
            let text = self.annotation_buf.trim().to_string();
            if text.is_empty() {
                self.annotations.remove(&id);
                self.set_status(format!("Annotation removed from #{id}"));
            } else {
                self.annotations.insert(id, text);
                self.set_status(format!("Annotated #{id}"));
            }
            self.annotation_buf.clear();
        }
    }

    /// Cancel annotation input.
    pub fn cancel_annotate(&mut self) {
        self.annotating = None;
        self.annotation_buf.clear();
    }

    /// Push a char into annotation buffer.
    pub fn annotate_push(&mut self, ch: char) {
        self.annotation_buf.push(ch);
    }

    /// Pop a char from annotation buffer.
    pub fn annotate_pop(&mut self) {
        self.annotation_buf.pop();
    }

    // -- Display filter --------------------------------------------------------

    pub fn start_display_filter(&mut self) {
        self.display_filter_editing = true;
        self.display_filter_buf = self.display_filter.clone();
    }

    pub fn confirm_display_filter(&mut self) {
        self.display_filter = self.display_filter_buf.clone();
        self.display_filter_editing = false;
        self.clamp_selected();
    }

    pub fn cancel_display_filter(&mut self) {
        self.display_filter_editing = false;
        self.display_filter_buf.clear();
    }

    pub fn display_filter_push(&mut self, ch: char) {
        self.display_filter_buf.push(ch);
    }

    pub fn display_filter_pop(&mut self) {
        self.display_filter_buf.pop();
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

    /// Export visible (filtered) packets to a pcap file.
    /// If `--write` was given, uses that path. Otherwise auto-generates a timestamped name.
    /// Returns a status message describing the result.
    pub fn export_packets(&self) -> String {
        let path = if let Some(ref p) = self.export_path {
            p.clone()
        } else {
            // Auto-generate filename: hexcap_YYYYMMDD_HHMMSS.pcap
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Simple timestamp without chrono: use seconds since epoch.
            PathBuf::from(format!("hexcap_{now}.pcap"))
        };
        let filtered = self.filtered_indices();
        let packets: Vec<&crate::packet::CapturedPacket> = filtered
            .iter()
            .filter_map(|&i| self.packets.get(i))
            .collect();
        match crate::export::write_pcap(path.as_path(), &packets) {
            Ok(n) => {
                // Save bookmarks sidecar if any bookmarks exist.
                let bm_path = crate::export::bookmark_path(&path);
                if let Err(e) = crate::export::save_bookmarks(&bm_path, &self.bookmarks) {
                    return format!("Exported {n} packets but bookmark save failed: {e}");
                }
                // Save annotations sidecar.
                let ann_path = crate::export::annotation_path(&path);
                if let Err(e) = crate::export::save_annotations(&ann_path, &self.annotations) {
                    return format!("Exported {n} packets but annotation save failed: {e}");
                }
                let mut extras = Vec::new();
                if !self.bookmarks.is_empty() {
                    extras.push(format!("{} bookmarks", self.bookmarks.len()));
                }
                if !self.annotations.is_empty() {
                    extras.push(format!("{} annotations", self.annotations.len()));
                }
                let note = if extras.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", extras.join(", "))
                };
                format!("Exported {n} packets{note} to {}", path.display())
            }
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

/// Check if packet data contains the query as an ASCII substring (case-insensitive).
fn payload_contains_ascii(data: &[u8], query: &str) -> bool {
    let query_bytes = query.as_bytes();
    if query_bytes.is_empty() || query_bytes.len() > data.len() {
        return false;
    }
    data.windows(query_bytes.len()).any(|window| {
        window
            .iter()
            .zip(query_bytes.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

/// Check if the query looks like a hex pattern and search for it in the data.
///
/// Accepts patterns like "ff d8 ff" or "ffd8ff" (spaces optional).
fn payload_contains_hex(data: &[u8], query: &str) -> bool {
    let hex_chars: String = query.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if hex_chars.len() < 2 || !hex_chars.len().is_multiple_of(2) {
        return false;
    }
    // All chars must be valid hex.
    if !hex_chars.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let pattern: Vec<u8> = (0..hex_chars.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_chars[i..i + 2], 16).ok())
        .collect();
    if pattern.len() != hex_chars.len() / 2 || pattern.is_empty() {
        return false;
    }
    data.windows(pattern.len())
        .any(|window| window == pattern.as_slice())
}

/// Check whether a packet matches a Wireshark-style display filter expression.
///
/// Supported tokens (space-separated, all must match = AND):
/// - Protocol: `tcp`, `udp`, `icmp`, `dns`, `arp`
/// - Port:    `port:443`
/// - IP:      `ip:10.0.0.1`
/// - Flags:   `syn`, `rst`, `fin`
/// - Negation: prefix any token with `!` (e.g. `!arp`, `!port:22`)
fn matches_display_filter(pkt: &CapturedPacket, filter: &str) -> bool {
    for token in filter.split_whitespace() {
        let (negated, tok) = if let Some(rest) = token.strip_prefix('!') {
            (true, rest)
        } else {
            (false, token)
        };
        let matched = match tok.to_ascii_lowercase().as_str() {
            "tcp" => pkt.protocol == Protocol::Tcp,
            "udp" => pkt.protocol == Protocol::Udp,
            "icmp" => pkt.protocol == Protocol::Icmp,
            "dns" => pkt.protocol == Protocol::Dns,
            "arp" => pkt.protocol == Protocol::Arp,
            "syn" => pkt.tcp_flags & 0x02 != 0,
            "rst" => pkt.tcp_flags & 0x04 != 0,
            "fin" => pkt.tcp_flags & 0x01 != 0,
            other => {
                if let Some(port_str) = other.strip_prefix("port:") {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let src_port = extract_port(&pkt.src);
                        let dst_port = extract_port(&pkt.dst);
                        src_port == Some(port) || dst_port == Some(port)
                    } else {
                        false
                    }
                } else if let Some(ip_str) = other.strip_prefix("ip:") {
                    pkt.src.starts_with(ip_str) || pkt.dst.starts_with(ip_str)
                } else {
                    // Unknown token — treat as no-match to surface typos.
                    false
                }
            }
        };
        if negated == matched {
            return false;
        }
    }
    true
}

/// Extract the port number from an address string like `192.168.1.1:443` or `[::1]:80`.
fn extract_port(addr: &str) -> Option<u16> {
    let colon_pos = addr.rfind(':')?;
    addr[colon_pos + 1..].parse().ok()
}

/// Extract TCP payload from a raw Ethernet frame.
///
/// Skips Ethernet header (14 bytes), IP header (variable), and TCP header (variable).
fn extract_tcp_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip = &data[14..];
    let ip_hdr_len = match ethertype {
        0x0800 => {
            // IPv4
            if ip.is_empty() {
                return None;
            }
            ((ip[0] & 0x0F) as usize) * 4
        }
        0x86DD => 40, // IPv6 fixed header
        _ => return None,
    };
    if ip.len() < ip_hdr_len + 20 {
        return None;
    }
    let tcp = &ip[ip_hdr_len..];
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() <= tcp_hdr_len {
        return None; // No payload
    }
    Some(&tcp[tcp_hdr_len..])
}
