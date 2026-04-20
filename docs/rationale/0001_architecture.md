# 0001 — Architecture: Thread Model and State Sharing

## Context

hexcap needs to simultaneously capture live network packets from libpcap and
render a responsive terminal UI. These are fundamentally different workloads:
capture is blocking I/O on a raw socket, while the TUI needs 20 fps rendering
and instant key response.

## Decision

**Two threads with `Arc<Mutex<App>>`.**

- The **main thread** owns the terminal, runs the ratatui render loop, and
  handles keyboard input at 50 ms poll intervals.
- A **background `std::thread`** runs the libpcap capture loop, parsing each
  packet and pushing it into the shared `App` state.

The shared state is `Arc<Mutex<App>>` — a single mutex protecting the entire
application model.

## Why not async (tokio)?

libpcap's `next_packet()` is a blocking FFI call. Wrapping it in
`spawn_blocking` adds complexity without benefit — the capture thread is
inherently synchronous and long-lived. A dedicated `std::thread` is simpler,
has zero runtime overhead, and avoids pulling in an async executor for what
is essentially a producer-consumer pattern.

## Why a single Mutex instead of channels?

The TUI needs random access to all packets (scrolling, filtering, detail view).
A channel-based design would require the consumer to buffer packets anyway,
duplicating the storage. A single `Mutex<App>` keeps the model in one place
and makes the TUI rendering path straightforward: lock, read, draw, unlock.

The lock contention is minimal — the capture thread holds it only for the
duration of a `push_back` call (~nanoseconds), and the UI thread holds it
for rendering (~microseconds at 50 ms intervals).

## Trade-offs

- Mutex poisoning on capture thread panic is handled with `.expect()` and a
  clear error message. This is acceptable because a panicked capture thread
  means the application is in an unrecoverable state.
- The single-mutex design does not scale to multi-interface capture, but that
  is not a current goal.
