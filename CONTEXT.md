# zPulsar

A lightweight Windows process network monitor: it shows every process's live network activity — destinations, hostnames, speeds, totals — with near-instant attribution. Written in Zig; user-mode only.

## Language

**Engine**:
The UI-independent core of zPulsar: capture, attribution, aggregation, and name/service resolution. It exposes its state only as Snapshots and knows nothing about windows, rendering, or the tray.
_Avoid_: Backend, service, daemon

**Snapshot**:
An immutable, self-contained view of the Engine's current state — Process Rows, Flows, rates, In-session Totals — published as a whole; a reader's view never changes underneath it.
_Avoid_: Frame, state dump

**Flow**:
A single network conversation attributed to one process, identified by protocol, owning process, and local/remote endpoint (for ICMP, by protocol, owning process, and remote endpoint). Endpoint reuse after closure starts a new Flow — see Generation.
_Avoid_: Connection (implies TCP only), socket, session

**Generation**:
What distinguishes successive Flows that reuse the same endpoints: a connect, or first activity after closure, starts a new Generation — never resuming the old Flow or its totals.
_Avoid_: Resurrection, reuse (ambiguous with port reuse)

**Linger**:
The fixed window after a Flow closes during which it stays visible, dimmed, in the flow list before being removed. Its bytes remain in its Process Row's totals.
_Avoid_: Grace period, TIME_WAIT (that's TCP's, not ours)

**Eviction**:
Dropping per-item visibility under a memory cap by rolling an item's totals upward into its parent. Eviction may coarsen attribution; it never loses bytes.
_Avoid_: Dropping, discarding (both imply lost bytes)

**Process Row**:
The top-level unit of display and aggregation — a monitored process, or a single service inside a shared service-host process.
_Avoid_: App, program

**Attribution**:
Binding a flow to the process (or service) that owns it.

**Attribution Latency**:
The time from a flow's first observable activity to it appearing correctly attributed in the UI. zPulsar's core differentiator: bounded by budget, not by a polling interval.

**Service Attribution**:
Attributing a flow to the individual Windows service inside a shared host process (e.g. svchost.exe), rather than to the host process as a whole.
_Avoid_: svchost splitting

**Hostname Attribution**:
Labeling a flow's remote endpoint with the name the process actually resolved, observed at lookup time — falling back to reverse lookup only when no lookup was seen.
_Avoid_: Reverse DNS (that's the fallback, not the mechanism)

**Tray-idle**:
The state where the main window is closed and only the tray icon remains: monitoring continues in full, footprint drops to the minimum.
_Avoid_: Background mode, minimized

**In-session Totals**:
Per-flow and per-process-row byte totals accumulated since zPulsar started; they do not survive restart (v1).
_Avoid_: History, stats DB

**Performance Budget**:
The numeric targets the v1 spec commits to: attribution latency < 200 ms, idle CPU < 1%, tray-idle RAM < 30 MB, window-open RAM < 80 MB, executable < 5 MB.
