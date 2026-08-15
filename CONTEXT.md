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
A single network conversation attributed to one process, identified by protocol, owning process, and local/remote endpoint (for ICMP, by protocol, address family, and owning process — the send path names no peer, see ADR-0003; a recognized Group Address is vacated from the local endpoint, see ADR-0004). Endpoint reuse after closure starts a new Flow — see Generation.
_Avoid_: Connection (implies TCP only), socket, session

**ICMP Message Count**:
What an ICMP Flow accumulates in place of bytes: how many messages it sent and received, displayed "N msgs". No user-mode source reports ICMP message sizes, so ICMP contributes zero to every byte total — Flow, Process Row, and session alike.
_Avoid_: ICMP bytes, estimated bytes (there is no size to estimate from)

**Group Address**:
A destination address that names a set of receivers rather than one host: a multicast group, the limited broadcast address, or a subnet-directed broadcast. Where one is recognized it is vacated from a Flow's local endpoint, which no group could honestly occupy — see ADR-0004.
_Avoid_: Multicast, broadcast (each names one kind, not the category)

**Generation**:
What distinguishes successive Flows that reuse the same endpoints: a connect, or first activity after closure, starts a new Generation — never resuming the old Flow or its totals.
_Avoid_: Resurrection, reuse (ambiguous with port reuse)

**Linger**:
The fixed window after a Flow closes during which it stays visible, dimmed, in the flow list before being removed. Its bytes remain in its Process Row's totals.
_Avoid_: Grace period, TIME_WAIT (that's TCP's, not ours)

**Eviction**:
Dropping per-item visibility under a memory cap by rolling an item's totals upward — a Flow's into its Process Row, an exited Process Row's into the Evicted-processes Row. Eviction may coarsen attribution; it never loses bytes.
_Avoid_: Dropping, discarding (both imply lost bytes)

**Evicted-processes Row**:
The single row that evicted exited Process Rows roll their totals into, labelled "(evicted processes)". It owns no PID and no Flows: it is where attribution stops, and the only row that is never itself a candidate for Eviction.
_Avoid_: Other, misc (both read as a category rather than as a memory bound)

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
Labeling a flow's remote endpoint with the name the process actually resolved, observed at lookup time — falling back to a Hint only when no lookup was seen.
_Avoid_: Reverse DNS (that's a fallback, not the mechanism)

**Hint**:
A remote name nobody was observed resolving: read from the machine's resolver cache at startup, for names resolved before zPulsar existed, or from a reverse lookup after that. A Hint says an address *was* resolved under a name, never by whom — so it renders dimmed behind its source's marker, and never displaces an observation.
_Avoid_: Guess (a Hint is evidence, just not attributable), fallback name

**Posture**:
How hard the Engine is being read, and the only thing it knows about the world outside itself: window-open pays for the Attribution Latency budget, Tray-idle drops to the ETW session's own 1 s flush and ~1 s Snapshots. Named for the reader's state, never for the reader — the Engine has no idea a window exists.
_Avoid_: Mode, state (both already mean too many things here)

**Ledger**:
zPulsar's main window: one dense, sortable table of Process Rows over a status bar. Its row order is *frozen* between periodic re-sorts, so rows sit still while the numbers inside them move.
_Avoid_: Grid, list (both name the widget rather than what it shows)

**Tray-idle**:
The state where the main window is closed and only the tray icon remains: monitoring continues in full, footprint drops to the minimum.
_Avoid_: Background mode, minimized

**In-session Totals**:
Per-flow and per-process-row byte totals accumulated since zPulsar started; they do not survive restart (v1).
_Avoid_: History, stats DB

**Performance Budget**:
The numeric targets the v1 spec commits to: attribution latency < 200 ms, idle CPU < 1%, tray-idle RAM < 30 MB, window-open RAM < 80 MB, executable < 5 MB.
