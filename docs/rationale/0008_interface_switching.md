# 0008 — Live Interface Switching

## Context

Users often need to switch between network interfaces (e.g., Wi-Fi vs
Ethernet, loopback for local debugging) without restarting hexcap.

## Decision

**Interface picker overlay with capture thread restart.**

- Pressing `i` opens a picker listing all available interfaces (via
  `pcap::Device::list()`), showing name and description.
- Selecting an interface stops the current capture thread via an
  `AtomicBool` stop signal, then starts a new capture thread on the
  chosen interface.

### Deadlock fix

The initial implementation held the `Arc<Mutex<App>>` guard while calling
`CaptureHandle::start`, which internally locks the same mutex to set
`interface_name`. This caused a deadlock. The fix: drop the guard before
starting the new capture.

## Why AtomicBool instead of dropping the thread?

`pcap::Capture::next_packet()` blocks for up to the read timeout. An
`AtomicBool` checked between packets allows graceful shutdown within one
timeout interval (~100ms). Dropping the thread handle would require
platform-specific cancellation or unsafe tricks.

## Why not support multiple simultaneous interfaces?

The single-mutex `App` model assumes one packet stream. Supporting
multiple interfaces would require per-interface capture threads feeding
into a merge queue, plus UI for distinguishing which interface each
packet came from. This is significant complexity for a niche use case.
