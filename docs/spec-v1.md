# zPulsar v1 Specification

Assembled 2026-08-14 from the [wayfinder map](https://github.com/cyljacky02/zpulsar/issues/1) (issue [#11](https://github.com/cyljacky02/zpulsar/issues/11)). Every decision below was resolved and confirmed on a map ticket; this document consolidates them into the single spec a build effort starts from. Vocabulary follows the glossary in `CONTEXT.md`; standing constraints are recorded in ADR-0001 (user-mode only) and ADR-0002 (engine architecture).

## Problem Statement

Windows gives its users no good answer to "what is my machine talking to right now, and which program is doing it." The in-box tools are either polling-based and slow to attribute (Resource Monitor), connection-list-only with no rates or names (netstat), or system-wide counters with no per-process breakdown. Third-party monitors that do the job properly (NetLimiter class) ship a kernel driver — installer, signing chain, crash blast radius — and even they stop at the process boundary, attributing everything inside a shared `svchost.exe` to "svchost.exe". Users who want to know which process opened a connection, to what hostname, at what speed, and — when the process is a shared service host — *which service specifically*, have nowhere lightweight to turn.

## Solution

zPulsar: a single portable, admin-elevated executable for Windows 10 x64 1809+ that monitors every TCP, UDP, and ICMP flow on the machine from user mode only and attributes each one to its owning process — and to the individual Windows service inside shared host processes — within 200 ms of first activity. It runs as an always-present tray icon with a GPU-rendered immediate-mode main window: one dense, sortable process table with live down/up speeds and in-session totals, flows expanding inline beneath their process, remote endpoints labeled with the hostname the process actually resolved, and a selection-driven Info View. Closing the window drops zPulsar to Tray-idle — monitoring continues in full at minimal footprint, live speeds stay visible in the tray tooltip. No kernel driver, no installer, no persisted history; MIT licensed.

## User Stories

1. As a user, I want to see every process that is using the network in one live table, so that I know at a glance what my machine is doing.
2. As a user, I want each process row to show its current download and upload speed, so that I can spot who is consuming my bandwidth right now.
3. As a user, I want per-process in-session byte totals alongside live speeds, so that I can see who consumed data over time, not just this second.
4. As a user, I want a new flow to appear correctly attributed within 200 ms of its first activity, so that short-lived connections don't escape unseen or land on the wrong process.
5. As a user, I want to expand a process row to see its individual flows, so that I can inspect exactly which connections a process holds.
6. As a user, I want each flow's remote endpoint labeled with the hostname the process actually resolved, so that I see "api.example.com" instead of a bare IP.
7. As a user, I want hostnames obtained only by reverse lookup shown dimmed, so that I can tell an observed name from an unreliable hint.
8. As a user, I want flows whose hostname is unknown to show their bare endpoint, so that nothing is hidden just because a name is missing.
9. As a power user, I want traffic inside a shared svchost.exe attributed to the individual service, so that "svchost.exe" stops being a black hole.
10. As a power user, I want zPulsar to say "svchost.exe (N services)" with the service list when per-service attribution genuinely fails, so that I get an honest answer instead of a guess.
11. As a user, I want ICMP conversations my processes initiate (e.g. pings) to appear as flows with message counts, so that ping traffic is visible even though no byte counts exist for it.
12. As a user, I want connections that existed before zPulsar started to appear in the table, so that starting the monitor late doesn't hide established activity.
13. As a user, I want a process that exits to stay in the table, dimmed "(exited)" with its totals intact, so that a burst of traffic from a short-lived process remains explained.
14. As a user, I want a flow that closes to linger dimmed for a few seconds before disappearing, so that I can see what just ended.
15. As a user, I want closed-flow bytes to remain in the owning process's totals, so that totals never shrink when flows disappear.
16. As a user, I want to sort the table by any activity column, so that the busiest processes are one click away.
17. As a user, I want row order to update periodically rather than jitter every frame, so that I can actually click the row I aimed at.
18. As a user, I want per-cell activity coloring scaled across traffic magnitudes, so that I can see hot spots without reading numbers.
19. As a user, I want to select a process and see its properties (name, path, PID, service) and activity in an Info View, so that inspection doesn't require another tool.
20. As a user, I want to select a flow and see its protocol, local and remote endpoints, remote name, and activity in the Info View, so that a single connection can be examined in place.
21. As a user, I want a status bar with the active flow count, global down/up speed, and session totals, so that machine-wide activity is always in view.
22. As a user, I want to close the window and have zPulsar keep monitoring from the tray, so that watching my network doesn't cost me a taskbar slot.
23. As a user, I want the tray tooltip to show global down/up speed and the current top talker, so that I can check on things without opening the window.
24. As a user, I want clicking the tray icon to bring the full window back with all session state intact, so that Tray-idle costs me nothing.
25. As a laptop user, I want zPulsar to use under 1% CPU when idle, so that monitoring doesn't drain my battery.
26. As a user, I want zPulsar under 30 MB of RAM while Tray-idle and under 80 MB with the window open, so that an always-on monitor stays cheap.
27. As a user, I want zPulsar as one portable exe under 5 MB with no installer, so that I can carry it, run it, and delete it cleanly.
28. As a user, I want zPulsar to request elevation itself via its manifest, so that setup is a UAC prompt and nothing more.
29. As a user, I want a clear error and exit if monitoring cannot start, so that I never watch a silently empty window.
30. As a user, I want a second launch of zPulsar to hand off to the running instance and show its window, so that I never end up with two monitors fighting.
31. As a user, I want zPulsar to recover its ETW session after a crash without my help, so that one bad exit doesn't require manual cleanup.
32. As a user, I want zPulsar to stop its trace session reliably on every exit path, so that it never leaks a system-wide session that keeps logging after it's gone.
33. As a user, I want totals that are either exact or explicitly flagged as re-baselined after event loss, so that the numbers are never silently wrong.
34. As a user, I want memory-pressure eviction to roll totals upward rather than drop them, so that attribution may coarsen but bytes are never lost.
35. As a user, I want processes that start after zPulsar to appear with their real image name immediately, so that attribution never shows a raw PID placeholder.
36. As a user, I want traffic arriving just after a process exits still attributed to that exited process — and a reused PID to get a fresh row — so that totals never bleed between unrelated processes.
37. As a security-conscious user, I want zPulsar to install no kernel driver and mutate no global firewall or audit state, so that running a monitor doesn't change my system's behavior.
38. As a developer, I want the monitoring engine buildable headless without the UI, so that its behavior can be tested and profiled in isolation.
39. As a future contributor, I want the UI reachable only through published Snapshots, so that a different front-end can be built without touching engine internals.
40. As a user, I want zPulsar under the MIT license, so that I can use, audit, and redistribute it freely.

## Implementation Decisions

### Platform and constraints

- **User-mode only** (ADR-0001, hard constraint): no kernel-mode components, ever, for as long as the ADR stands. All capture uses ETW real-time providers, IP Helper, and documented user-mode APIs.
- **Target: Windows 10 x64, version 1809 and later.** Client SKUs only; Windows Server behavior (svchost grouping) is out of scope.
- **Elevation is mandatory and manifest-declared** (`requireAdministrator`). No unelevated shim, no degraded mode in v1: UAC decline means the process never starts; engine start failure shows a message box and exits (fail-fast).
- **Distribution: one portable exe.** No installer, no auto-start, no bundled assets. MIT license.
- **Language/toolchain: Zig 0.16.0**, `ReleaseSmall` for distribution builds.

### Capture: TCP/UDP byte accounting

- One ETW real-time session named **`zPulsarNet`** (QPC clock, `EVENT_TRACE_REAL_TIME_MODE`, 16 KB buffers, min/max buffers 2×/4× logical CPUs, 1 s FlushTimer) hosts **all four providers** below. A two-session hot/cold split is the documented fallback only if `EventsLost` ever demands it.
- TCP/UDP bytes come from the **`Microsoft-Windows-Kernel-Network`** manifest provider, keywords `0x10 | 0x20` (IPv4 | IPv6): send/recv events 10/11 (TCPv4), 26/27 (TCPv6), 42/43 (UDPv4), 58/59 (UDPv6); connect/accept/disconnect 12/15/13 (v4) and 28/31/29 (v6) drive TCP flow lifecycle. Retransmit (14/30) and protocol-copy (18/34) events are **excluded from totals**.
- **Attribution key is the payload PID, never the event-header PID** (receive path runs at DPC in arbitrary context). Payloads are fixed-width; parse with hardcoded offsets after asserting `EventDescriptor.Version == 0`, with TDH-derived offsets (computed once per event id) as the fallback for unknown versions. Ports and addresses are network byte order in both events and IP Helper tables — one shared normalization.
- **Delivery latency is buffer-flush-bound** (1 s FlushTimer floor), so the Engine issues `ControlTrace(EVENT_TRACE_CONTROL_FLUSH)` every **100–150 ms while the window is open**; Tray-idle suspends the tick and rides the 1 s floor. This is what makes the < 200 ms Attribution Latency budget hold for trickle traffic.
- **Cold start**: start the session and providers first, then snapshot `GetExtendedTcpTable` / `GetExtendedUdpTable` (both address families), then drain buffered events reconciling by normalized 5-tuple. Attribution never depends on the snapshot — every data event carries its own PID; the snapshot exists to show pre-existing idle connections, give close events a row to close, and re-baseline after loss.

### Capture: ICMP

- ICMP visibility comes from the **`Microsoft-Windows-TCPIP`** provider, keyword `ut:Global`, **event 1422** (`IcmpSendRecv`): one event per ICMP message, both directions, carrying type/code/addresses/direction.
- **Outbound attribution is the event-header PID** — verified to be the real calling process, including the `IcmpSendEcho` path. This is undocumented behavior verified on Windows 11; **re-verify on Windows 10 1809 during the build** (see Testing Decisions).
- **Inbound replies log as System** and are attributed by correlation: match to the live ICMP Flow with the same remote address and paired type (8→0, 13→14), most recent request wins (documented heuristic — 1422 carries no echo Identifier). **Unmatched inbound ICMP is dropped** — no phantom System-row activity; unsolicited inbound ICMP is a documented blind spot.
- **No user-mode ICMP byte source exists.** ICMP Flows carry sent/recv **message counts**, displayed as "N msgs"; ICMP contributes zero to byte totals. WFP net events and raw sockets were evaluated and rejected (app-path-only attribution / global engine-option mutation / no attribution respectively).

### Capture: hostname observation (DNS)

- **`Microsoft-Windows-DNS-Client` event 3008 only** (query completed): fires in the calling process for every completed resolution — **including cache hits** — with query name, full results (CNAME chain + addresses), and status; PID from the event header. Ignore 3008s with nonzero status or empty results; normalize IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`) to IPv4.
- **Three-tier lookup at flow creation**: (PID, IP) exact → (any-PID, IP) global last-writer-wins → startup cache/reverse-lookup results; miss shows the bare endpoint. The name resolves once at flow creation and is stored on the Flow; a later observation upgrades it in place (and un-dims it); the first *observed* name wins permanently. Observation cache is LRU-capped (~8 k entries), idle-evicted; refresh `lastSeen` on upsert and on attributed-flow activity.
- **Pre-start names** come from a one-shot `MSFT_DnsClientCache` CIM snapshot at startup (no PID attribution — marked cache-derived).
- **Reverse-lookup fallback**: `GetNameInfoW` (`NI_NAMEREQD | NI_NUMERICSERV`) on its own resolver lane, triggered ~2 s after a flow misses all tiers; results display **dimmed** (reverse names are hints, not observations); negative results cached ~10 min so PTR-less ranges don't loop. Private resolvers (in-app DoH, nslookup) bypass the provider by design — that gap is exactly what the fallback covers.

### Attribution: services inside shared hosts (Service Attribution)

- Three tiers, all documented APIs; nothing undocumented is load-bearing:
  1. **PID hosts exactly one service** (per an `EnumServicesStatusEx(SC_ENUM_PROCESS_INFO)` map, refreshed on service state change): attribute by the map alone — the common case on 1703+ split machines.
  2. **PID hosts N services**: match the flow to its `MIB_TCPROW_OWNER_MODULE` / UDP row and resolve via `GetOwnerModuleFromTcpEntry` / `GetOwnerModuleFromUdpEntry` (returns the service name per-socket; requires elevation, which zPulsar always has).
  3. **Both fail** (no table row, tag 0, non-service module name): the honest fallback label **"svchost.exe (N services)"** with the hosted-service list — never a guessed single service.
- Resolution is **eager at flow creation** (the table row must still exist for short-lived flows): the flow appears immediately under the fallback label and **upgrades in place** when resolution lands. The service map is keyed by (PID, process start time) against PID reuse.
- The raw service-tag fast path (`I_QueryTagInformation`) is undocumented and **optional** — a profiling-driven escape hatch only, flagged as such.

### Attribution: process identity and lifetime

- **`Microsoft-Windows-Kernel-Process`** enabled into the same session, level 4, keyword `0x10`: ProcessStart (1), ProcessStop (2), ProcessRundown (15). Dispatch on provider GUID first, then (event id, version).
- **Process Rows are keyed by (PID, payload CreateTime)** — verified bit-identical across start/stop/rundown events and `GetProcessTimes`. PID reuse yields a fresh row; events arriving after exit (inside the flush window) attribute to the exited row.
- **Cold start via `EnableTraceEx2(EVENT_CONTROL_CODE_CAPTURE_STATE)`** issued after the consumer is live: one rundown event per existing process. Re-issue after `EventsLost` as part of loss recovery. Dedupe start-vs-rundown on the row key.
- **Image names come from the start/rundown payload** (full NT device path; kernel-written, so protected processes need no access checks). Convert `\Device\HarddiskVolumeN\` to drive letters via a `QueryDosDeviceW` map for display; kernel/minimal processes (System, Registry, MemCompression…) show their bare payload name. The stop-event name is ANSI and truncated — never display it. `OpenProcess` + `QueryFullProcessImageNameW` is the rare fallback only.
- **Payloads are version-dispatched**: 1809 emits 1v2/2v1/15v0 (no sequence numbers or SID; start ImageName at fixed offset 24); 1903+ emits 1v3+/2v2/15v1+ (SID skip before ImageName). Fields were inserted, not appended — never parse an unknown version with old offsets; fall back to TDH. Implement pairs {1v2, 1v3, 1v4, 2v1, 2v2, 15v0, 15v1, 15v2}; ignore unknown ids (e.g. 27).

### Data model (inside the Engine)

- **Flow key: (protocol, local endpoint, remote endpoint, owning PID)**; ICMP: (protocol, remote address, PID). A Flow never migrates between Process Rows; duplicated/inherited sockets appear as sibling Flows per PID.
- **Generation**: endpoint reuse after closure starts a new Flow; totals never resurrect.
- **Closure**: TCP is event-driven (connect/accept/disconnect) plus a **10 s reconciliation sweep** against the IP Helper tables as safety net (the sweep also checks `EventsLost` and triggers re-baseline). UDP Flows age out after **60 s** inactivity, ICMP after **30 s**. Closed Flows **Linger 10 s** dimmed, then leave the list; their bytes remain in row totals. Process exit closes its live Flows immediately into normal Linger; exited rows persist all session, dimmed "(exited)".
- **Rates**: bytes bucket by **event QPC timestamp** (never arrival time — delivery is flush-bursty) into **100 ms slots, ring of 16** (1.6 s, absorbs late arrivals). Displayed speed = **1 s sliding window** (last 10 buckets). Flows *and* rows own rings (double-bucketed at event time), so row speed survives flow eviction. No EMA, no units toggle in v1 (the ring supports adding EMA later).
- **Totals**: independent u64 sent/recv accumulators per Flow and per Row (row totals include bytes of evicted/vanished flows — never "sum of visible flows"). Decimal units, auto-scaled (B/KB/MB/GB, /s). ICMP shows message counts and contributes 0 bytes.
- **Memory bounds**: Flow cap ~16 k — evict closed/lingering oldest-first; if live flows alone exceed the cap, roll the longest-idle live Flows' totals into their row (they return as a fresh Generation on next activity). Exited-row cap ~512 — evict oldest-and-smallest into one aggregate "(evicted processes)" row. **Invariant: Eviction may coarsen attribution, never lose bytes.**

### Architecture and threading (ADR-0002)

- **Two modules behind a build-enforced boundary**: the Engine (capture → attribution → aggregation → resolution) may import only the standard library and the repo's win32 facade; the app layer (tray + window) imports the Engine; only the facade imports the binding library. Violations are compile errors; a debug-only **headless build target** proves the boundary and doubles as the test/perf rig.
- **Pull-based API**: lifecycle calls + refcounted, arena-backed **immutable Snapshots** published by pointer swap + one "data changed" wake event. No callbacks into the UI, no delta streams; Snapshots carry precomputed rates and health flags (e.g. "counts re-baselined"). Multiple simultaneous readers by construction.
- **Five fixed threads**: (1) main — message loop, tray, window/device/UI context; (2) ETW consumer — blocked in `ProcessTrace`, parse-only, pushes fixed-size records onto a bounded SPSC ring (power-of-two 16 Ki × ~64 B, drop-newest on full with a loss counter, wake on empty→non-empty); (3) Engine — single owner of all state, drains ring + completion queues, runs the tick (flush, sweeps, eviction, Snapshot publish); (4) metadata resolver — owner-module calls, service map, table snapshots, DoS-device map, one-shot DNS-cache read; (5) reverse-lookup lane — `GetNameInfoW` only, bounded queue, so a hung PTR lookup can never starve Service Attribution. No locks on the hot path.
- **Loss recovery is unified**: ring overflow and ETW `EventsLost` both re-baseline from fresh IP Helper tables (plus re-CAPTURE_STATE) and flag the Snapshot — totals are honest or marked, never silently low.
- **Tray-idle**: a **permanent hidden tray window** (ordinary invisible top-level, not message-only, so `TaskbarCreated` arrives) owns the tray icon and the single-instance "show yourself" message for the process lifetime. Close destroys the main window, swapchain, D3D11 device, and UI context **wholesale**; reopen runs the first-open code path. Engine posture in Tray-idle: accounting stays exact, flush tick suspends, Snapshots/rates at ~1 s for the tooltip. **The < 200 ms Attribution Latency budget is a window-open budget.**
- **Startup**: manifest elevation → single-instance mutex (second instance signals the first and exits) → start session (on `ERROR_ALREADY_EXISTS`, stop the orphan by name and retry — safe because the mutex rules out a live twin) → enable providers → table snapshots → CAPTURE_STATE → window shown on launch, rows fill as data lands; DNS-cache snapshot and service map build async.
- **Shutdown**: tray icon off → window/device teardown → `CloseTrace` → **`ControlTrace(STOP)` — never skipped** (ETW sessions outlive their process) → join consumer + Engine; resolver threads joined with a 2 s timeout, then exit regardless. Console-ctrl handler and `WM_ENDSESSION` cover non-menu exits; crash orphans self-heal on the next launch.

### UI (locked by prototype)

- **Layout: "Ledger + Info View"** — one dense sortable process table, flows expanding inline beneath their Process Row, plus a right-docked ~300 px selection-driven Info View, always visible in v1.
- **Table columns**: Process (badge + name + Service Attribution + flow count) | PID | Down | Up | Down total | Up total; all sortable except PID. Flow rows: protocol badge (TCP/UDP/ICMP), hostname (observed normal, reverse-lookup dimmed, unresolved shows bare endpoint), dim endpoint. ICMP rows show message counts.
- **Per-cell activity coloring**: down green, up amber; fill intensity log-scaled ~1 KB/s → 50 MB/s; idle cells unfilled; zero values render dim "—".
- **Re-sort is periodic (1–2 s), never per frame** — per-frame reorder is jumpy *and* breaks click accuracy (clicks resolve against the previous frame's layout; mis-selection reproduced in the prototype).
- **Click model**: process row click selects and toggles expansion; flow row click selects for inspection. Selected row accent blue, hover gray. No app-global arrow-key shortcuts (grid navigation consumes them).
- **Info View sections**: Process → properties (name, PID, service, path) + activity; Flow → connection properties (protocol, local, remote, remote name, country) + activity; **Tools** section at the bottom is reserved extension points only (Traceroute / MTR / WHOIS / Copy remote address; Open file location / Copy path) — **not implemented in v1**. **Country shows "—" in v1** (no GeoIP source ships; the field and space are reserved).
- **Status bar**: active flow count · global ↓/↑ · session totals. **Tray tooltip** (1 s cadence): global ↓/↑ + top talker by combined current rate. Window numbers repaint at 500 ms.
- **Process icons**: colored-initial badges in v1; real exe icons are a build-phase upgrade.
- **Chrome**: close-to-tray with the wholesale teardown/recreate cycle (exercised end-to-end in the prototype); window shown on launch.

### Toolchain bindings

- **GUI: dvui, Direct3D 11 backend, attach mode** (caller-owned HWND and window procedure), pinned to a known-good commit (≥ `7c597c5`); no Dear ImGui fallback needed (zgui remains the proven fallback if dvui regresses). Lean build flags are mandatory for the exe budget: freetype, tree-sitter, and file-dialogs off. Verified: sortable/virtualized/per-cell-colored grid, in-process device teardown/recreate, 1.92 MB exe / 51.5 MB working set for a representative 500-row app.
- **Win32: zigwin32, pinned to an exact commit** via `zig fetch`, routed through a thin repo-owned facade module that is the only importer of the binding — with **comptime `@sizeOf`/`@offsetOf` asserts** on every ABI-crossing struct. Hand-rolled externs are the narrow escape hatch (one known case: the ETW buffer-callback type is stubbed upstream — declare the true signature locally and cast). translate-c rejected. Verified by compiling and running live table-fetch + ETW session start/stop on Zig 0.16.0.
- Zig's bundled mingw-w64 headers/import libs cover everything (no Windows SDK dependency); a few newer ETW filter constants are absent and must be defined locally if ever used.

### Performance Budget (commitments, and what serves them)

| Budget | Mechanism |
|---|---|
| Attribution Latency < 200 ms (window open) | 100–150 ms ETW flush tick; eager service resolution; parse-only consumer; payload-PID attribution |
| Idle CPU < 1% | event-driven capture (no polling loops); flush tick suspended in Tray-idle; render-on-demand UI |
| Tray-idle RAM < 30 MB | wholesale window/device/UI-context teardown; capped flow/row stores |
| Window-open RAM < 80 MB | measured 51.5 MB for a representative grid app; arena-backed Snapshots; bounded caches |
| Exe < 5 MB | single static exe, ReleaseSmall, lean dvui flags (1.92 MB measured floor) |

## Testing Decisions

- **The seam is the Engine boundary — one seam, already build-enforced.** The debug-only headless target runs the full Engine without any UI; tests drive it by feeding parsed event records into the ring (bypassing the live ETW session) and asserting on published Snapshots. This tests external behavior only — what a Snapshot reader sees — never internal maps, rings, or thread states.
- **Behavioral coverage through that seam**: flow identity and Generation, closure/aging/Linger timing, rate-window math against QPC-stamped synthetic streams, totals invariants under eviction ("never lose bytes"), re-baseline flagging after simulated loss, ICMP correlation and drop rules, hostname tier precedence and upgrade-in-place, service-attribution tiers and upgrade-in-place, exited-row and PID-reuse semantics.
- **Parser tests are table-driven against captured payload bytes.** The research docs contain verified raw payloads and offsets (Kernel-Network event layouts; Kernel-Process v2/v3/v4 hex dumps; DNS 3008 QueryResults formats) — these become fixtures. Every (event id, version) pair the engine claims to parse gets a fixture; unknown versions must route to the TDH fallback.
- **Live-session integration checks run elevated on a real machine** (not in unit CI): session start/orphan-adoption/stop, cold-start reconciliation, CAPTURE_STATE rundown, a known-size transfer totals check (validates `size` semantics), and the flush-tick latency bound.
- **The 1809 floor has two mandatory verification items** before release, on a real 1809 image: (a) TCPIP event 1422 exists and outbound header-PID attribution holds; (b) Kernel-Process emits 1v2/2v1/15v0 and CAPTURE_STATE rundown works. Both are flagged as engineering assumptions verified only on Win11 so far.
- **Budget verification is a headless-rig measurement**, not a guess: idle CPU, attribution latency under trickle traffic, and RAM in both postures measured against the Performance Budget table.
- Prior art: none — this is a greenfield repo; the fixtures above are the starting corpus.

## Out of Scope

- **Traffic limiting/shaping** and **any kernel-mode component** (ADR-0001; ruled out at charting).
- **Persisted history** — v1 is live view + In-session Totals only; nothing survives restart.
- **Per-app row grouping** (aggregating multiple PIDs of one executable), **EMA-smoothed speeds**, **units toggles** (bits/s, binary units).
- **Non-admin degraded mode** (own-process-only visibility).
- **Installer, start-with-Windows, live speed rendered in the tray icon itself** (tooltip only in v1).
- **ARM64.**
- **Per-address tools** (traceroute, MTR, WHOIS, …) — the Info View's Tools section reserves the space; implementations are v2+.
- **GeoIP country attribution** — the Info View's country field shows "—" in v1; the source decision (offline GeoLite2 vs online lookup) is deferred with the feature.
- **Windows Server** support.

## Further Notes

- **Build-phase caveats recorded by the prototype**: dvui GridWidget handles sortable columns, per-cell fills, and inline expansion cleanly; don't bind app-global shortcuts to arrow keys; dvui's dx11 backend panics on synthetic zero-repeat-count key messages (upstream bug; real keyboards unaffected); the default UI font lacks ↓/↑ glyphs — use icon glyphs.
- **Verification items deferred to the build** (tracked in Testing Decisions): the two 1809 re-verifications; `size`-semantics totals check; loopback-traffic visibility (expected present — decide whether to tag it); flush-tick CPU cost at 10 Hz.
- **Pinning discipline**: dvui and zigwin32 are pre-1.0/tagless — both are pinned to exact commits and upgraded deliberately; the win32 facade is the single file that absorbs upstream reorganizations.
- **Source documents**: research findings live in `docs/research/` (ETW TCP/UDP pipeline, ICMP visibility, DNS-Client ETW, svchost service attribution, GUI library viability, Win32 interop, Kernel-Process ETW); architecture in `docs/adr/0002`; constraint in `docs/adr/0001`; UI prototype with screenshots on the `cyljacky02/prototype-the-main-window-ui` branch; full decision detail on map tickets [#2](https://github.com/cyljacky02/zpulsar/issues/2)–[#10](https://github.com/cyljacky02/zpulsar/issues/10) and [#13](https://github.com/cyljacky02/zpulsar/issues/13).
