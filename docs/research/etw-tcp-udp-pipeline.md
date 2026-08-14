# ETW pipeline for real-time per-process TCP/UDP byte accounting

Research ticket: [#2](https://github.com/cyljacky02/zpulsar/issues/2) · Date: 2026-08-14
Scope: Windows 10 x64 1809+, user-mode only, admin-elevated. Budgets: attribution latency < 200 ms, idle CPU < 1%.

Evidence classes used: Microsoft Learn API docs, the OS's own registered provider manifest
(dumped with `wevtutil gp Microsoft-Windows-Kernel-Network /ge:true /gm:true` and
`Get-WinEvent -ListProvider`, Windows 11 machine — events are all version 0 and match the
Vista-era MOF docs, see §2), the mingw-w64 SDK headers bundled with Zig 0.16
(`lib/libc/include/any-windows-any/evntrace.h`, `evntcons.h`), and reference consumers'
source (microsoft/krabsetw, winsiderss/systeminformer, microsoft/perfview).

---

## Verdict

**Use the `Microsoft-Windows-Kernel-Network` manifest provider
(GUID `{7DD42A49-5329-4832-8DFD-43D979153A88}`) in zPulsar's own real-time session,
consumed on a dedicated `ProcessTrace` thread with fixed-offset payload parsing, seeded at
startup from `GetExtendedTcpTable`/`GetExtendedUdpTable`.**

Per-process byte accounting at < 200 ms / < 1% idle CPU is achievable, with one nuance: ETW
delivers events to real-time consumers when a buffer is flushed, and the timer floor is
1 second — so the engine must either rely on buffers filling (fine under load with small
buffers) or issue an explicit `ControlTrace(EVENT_TRACE_CONTROL_FLUSH)` tick (~100–150 ms)
to bound trickle-traffic latency below 200 ms. Details in §4.

### Recommended session config

| Setting | Value | Why / source |
|---|---|---|
| Session | Own named session, e.g. `zPulsarNet` (clean up orphan on `ERROR_ALREADY_EXISTS`) | Not the NT Kernel Logger — no global-singleton conflict ([session name rules][props]) |
| `Wnode.ClientContext` | `1` (QPC) | Stable timestamps; required for ordered delivery ([ProcessTrace remarks][processtrace]) |
| `LogFileMode` | `EVENT_TRACE_REAL_TIME_MODE` (0x00000100) | Real-time delivery ([logging-mode constants][modes]) |
| `BufferSize` | 16 (KB) | "Small events, moderate rate → 16–32 KB"; small buffers fill fast → low latency under load ([EVENT_TRACE_PROPERTIES][props]) |
| `MinimumBuffers` / `MaximumBuffers` | `2 × nLogicalCPU` / `4 × nLogicalCPU` | ETW enforces ≥ 2/CPU anyway; start Min≈Max and raise Max if `EventsLost` > 0 ([EVENT_TRACE_PROPERTIES][props]) |
| `FlushTimer` | `1` (seconds — the documented minimum) | Baseline worst-case delivery 1 s ([EVENT_TRACE_PROPERTIES][props]) |
| Latency tick | `ControlTrace(…, EVENT_TRACE_CONTROL_FLUSH)` every 100–150 ms while flows are active | Forces delivery of partially filled buffers; sub-200 ms worst case ([ControlTrace][controltrace]) |
| Enable call | `EnableTraceEx2(h, &KernelNetworkGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x10 \| 0x20, 0, 0, NULL)` | `0x10` = `KERNEL_NETWORK_KEYWORD_IPV4`, `0x20` = IPV6 (provider manifest; [EnableTraceEx2][enable]) |
| Consumer | `OpenTrace` with `LoggerName`, `ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME \| PROCESS_TRACE_MODE_EVENT_RECORD` (0x100 \| 0x10000000), `EventRecordCallback`; `ProcessTrace` blocks a dedicated thread; `CloseTrace` to stop | [EVENT_TRACE_LOGFILE][logfile], [ProcessTrace][processtrace]; constants verified in Zig-bundled `evntcons.h` lines 49–51 |
| Parsing | Fixed offsets per (event ID, version 0); assert `EventDescriptor.Version == 0` and fall back to TDH-derived offsets (computed once per event ID at startup, never per event) if a future build bumps versions | Templates are all fixed-width scalars (§2); TDH per event is the expensive path |
| Cold start | `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` + `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` for AF_INET and AF_INET6, then live events take over | §5 |

### Event schema the engine parses (verified against the OS manifest)

All events: channel `Microsoft-Windows-Kernel-Network/Analytic`, level 4 (Informational),
version 0. **The PID is in the payload, not the header** (§2.3). Ports and IP addresses in
payloads are in network byte order (§2.4).

| ID | Meaning | Keyword | Payload (in order, fixed width) |
|---|---|---|---|
| 10 | TCPv4 data sent | 0x10 | `PID:u32, size:u32, daddr:u32, saddr:u32, dport:u16, sport:u16, startime:u32, endtime:u32, seqnum:u32, connid:u32` |
| 11 | TCPv4 data received | 0x10 | `PID:u32, size:u32, daddr:u32, saddr:u32, dport:u16, sport:u16, seqnum:u32, connid:u32` |
| 12 / 15 | TCPv4 connect attempted / accepted | 0x10 | `PID, size, daddr, saddr, dport, sport, mss:u16, sackopt:u16, tsopt:u16, wsopt:u16, rcvwin:u32, rcvwinscale:u16, sndwinscale:u16, seqnum:u32, connid:u32` |
| 13 | TCPv4 disconnect | 0x10 | same layout as 11 |
| 14 | TCPv4 retransmit | 0x10 | same layout as 11 — **do not add to totals** (bytes already counted at send) |
| 16 | TCPv4 reconnect attempt | 0x10 | same layout as 11 |
| 17 | TCP connect failed | 0x30 | (error code in `size` slot per message template) |
| 18 | TCPv4 protocol copy | 0x10 | same layout as 11 — exclude from totals (kernel copy on behalf of user, would double count) |
| 26 | TCPv6 data sent | 0x20 | as 10, but `daddr`/`saddr` are 16-byte binary (in6_addr) |
| 27 | TCPv6 data received | 0x20 | as 11, 16-byte addresses |
| 28 / 31 | TCPv6 connect / accept | 0x20 | as 12, 16-byte addresses |
| 29 / 30 / 32 / 34 | TCPv6 disconnect / retransmit / reconnect / copy | 0x20 | as their v4 counterparts, 16-byte addresses |
| 42 | UDPv4 datagram sent | 0x10 | `PID:u32, size:u32, daddr:u32, saddr:u32, dport:u16, sport:u16, seqnum:u32, connid:u32` |
| 43 | UDPv4 datagram received | 0x10 | same as 42 |
| 49 | UDP send failed | 0x30 | (error code) |
| 58 / 59 | UDPv6 sent / received | 0x20 | as 42/43, 16-byte addresses |

Byte offsets follow directly from the fixed-width field order, e.g. event 11 (TCPv4 recv):
`PID@0, size@4, daddr@8, saddr@12, dport@16, sport@18, seqnum@20, connid@24` (28 bytes);
event 27 (TCPv6 recv): `PID@0, size@4, daddr@8, saddr@24, dport@40, sport@42, seqnum@44,
connid@48` (52 bytes).

Accounting rule: `sent[PID] += size` on 10/26/42/58; `recv[PID] += size` on 11/27/43/59;
ignore 14/30 (retransmit) and 18/34 (protocol copy) for totals; use 12/15/13 (and v6
28/31/29) plus the cold-start snapshot to maintain the connection list.

Orientation rule (**not** uniform — see §2.5): `saddr`/`sport` are the local endpoint for
every event **except UDP receive (43/59)**, where the payload describes the arriving
datagram and the local endpoint is `daddr`/`dport`.

---

## 1. Provider comparison

### 1.1 `Microsoft-Windows-Kernel-Network` (manifest provider) — RECOMMENDED

- Registered OS provider, GUID `{7DD42A49-5329-4832-8DFD-43D979153A88}`, keywords
  `KERNEL_NETWORK_KEYWORD_IPV4 = 0x10`, `KERNEL_NETWORK_KEYWORD_IPV6 = 0x20`
  (verified via `logman query providers Microsoft-Windows-Kernel-Network` and the manifest dump).
- It is a "modern" (manifest) provider, so it is enabled into any ordinary trace session with
  `EnableTraceEx2`, and **up to eight sessions can enable it simultaneously** — no global
  singleton, no fight with WPR/xperf/other monitors ([EnableTraceEx2 remarks][enable]).
- Carries exactly the same instrumentation and field set as the classic kernel-logger
  TcpIp/UdpIp events (§1.2) — same `PID/size/5-tuple` payloads — but with unique event IDs
  per protocol/direction/IP version, so dispatch is a switch on `EventDescriptor.Id` instead
  of (provider GUID, opcode) pairs. Microsoft's TraceEvent library decodes this provider's
  IDs with the same mapping as the table above
  ([KernelTraceEventParser.cs][traceevent]).
- Event richness: send/recv/connect/accept/disconnect/retransmit/reconnect/copy/fail for
  TCP (v4+v6), send/recv/fail for UDP (v4+v6). That is everything the engine needs and
  nothing more.
- Overhead: events fire per transport-level send/receive operation (not per packet); this
  is the same event volume the NT Kernel Logger's `EVENT_TRACE_FLAG_NETWORK_TCPIP` produces,
  the lowest-volume source that still carries byte counts + PID + 5-tuple.

### 1.2 NT Kernel Logger (`EVENT_TRACE_FLAG_NETWORK_TCPIP`) — same data, worse ergonomics

- Enables the MOF classes `TcpIp` (GUID `9a280ac0-c8e0-11d1-84e2-00c04fb998a2`) and `UdpIp`
  (GUID `bf3a50c5-a9c9-4988-a005-2df0b7c80f80`); event *types* 10/11/26/27 etc. with the
  identical `PID, size, daddr, saddr, dport, sport, seqnum, connid` payloads
  ([TcpIp class][tcpip], [UdpIp class][udpip], [TcpIp_TypeGroup1][tg1], [UdpIp_TypeGroup1][utg1]).
- Hard limitation: "There is only one NT Kernel Logger session. If the session is already in
  use, StartTrace returns ERROR_ALREADY_EXISTS" ([NT Kernel Logger session][ntkl]). A
  monitor that hijacks it breaks WPR/xperf and vice versa.
- The Win8+ escape hatch is `EVENT_TRACE_SYSTEM_LOGGER_MODE` (0x02000000): a private session
  that "will receive events from SystemTraceProvider" with `EnableFlags` ([logging-mode
  constants][modes], [EVENT_TRACE_PROPERTIES][props]). This is exactly what System Informer's
  ExtendedTools does for its per-process network columns: private session
  `SiKernelTraceSession`, `EVENT_TRACE_FLAG_NETWORK_TCPIP`, dispatch on TcpIpGuid/UdpIpGuid
  opcodes 10/11/26/27, PID and TransferSize read from the payload structs
  ([etwmon.c][etwmon]). Fully viable **fallback** route on 1809+, but it buys nothing over
  the manifest provider for this use case and costs MOF-style opcode dispatch.

### 1.3 `Microsoft-Windows-TCPIP` — rejected

- tcpip.sys's internal diagnostic provider: 753 distinct events on the reference machine
  (`Get-WinEvent -ListProvider Microsoft-Windows-TCPIP`), 38 keywords including per-path and
  per-packet categories (`ut:SendPath`, `ut:ReceivePath`, `ut:Packet`, `ut:TcpipDiagnosis`).
- Not documented on Microsoft Learn; the event surface is a private implementation detail of
  tcpip.sys and shifts between Windows builds — hardcoded parsing would be build-fragile.
- Event volume is one-to-two orders of magnitude above Kernel-Network at the keywords that
  carry byte counts (per-packet/per-path granularity), directly hostile to the < 1% CPU
  budget, with no additional information needed for byte accounting.

## 2. Event schema notes (what the payload actually means)

### 2.1 Source of truth

The schema table in the Verdict is the OS's registered manifest (wevtutil/Get-WinEvent
template dump). It agrees field-for-field with the documented MOF classes for the kernel
logger flavor ([TcpIp_TypeGroup1][tg1]: `PID(WmiDataId 1), size(2), daddr(3), saddr(4),
dport(5), sport(6), seqnum(7), connid(8)`; [UdpIp_TypeGroup1][utg1] identical), and with the
event-ID mapping in Microsoft's TraceEvent parser ([KernelTraceEventParser.cs][traceevent]).
All events are version 0 — this schema has been stable since Vista; the engine should still
assert version and fail over to TDH-computed offsets (§3.2). The manifest is authoritative
for field *names, widths and order* only: it does not say which of `daddr`/`saddr` is the
local endpoint, and its message text is actively misleading there (§2.5).

### 2.2 `size` semantics

Learn documents `size` as "Size of the packet" and the event message renders it as
"%2 bytes transmitted/received from a:p to b:p" — it is the byte count of the transport
operation (application payload), not wire bytes; header/retransmit overhead is not
included (retransmits are separate events, ID 14/30). This matches Resource-Monitor-style
per-process totals. Flag for the prototype: confirm empirically that large `send()` calls
appear as one event with the full size (they do for TCP; UDP is one event per datagram).

### 2.3 PID: payload field, never the header

Learn, on both TcpIp and UdpIp classes: "Because some network events are logged by separate
threads, you may not be able to use the ProcessId and ThreadId members of
EVENT_TRACE_HEADER to identify the process … that originated the network activities" — the
payload `PID` ("Identifier of the process associated with the request") is the
authoritative attribution key ([TcpIp][tcpip], [UdpIp][udpip]). The receive path in
particular executes at DPC in an arbitrary process context, so `EVENT_RECORD.EventHeader.ProcessId`
is garbage for exactly the events zPulsar cares most about. System Informer likewise reads
the payload `ProcessId`, not the header ([etwmon.c][etwmon]).

### 2.4 Byte order

`dport`/`sport` use the manifest out-type `win:Port` (MOF `Extension("Port")`) and are
big-endian in the raw payload — `ntohs` before display/compare. `daddr`/`saddr` are
`in_addr` / 16-byte `in6_addr` network-order values. The same convention holds for the
iphlpapi snapshot rows ("The dwLocalPort … in network byte order" — [MIB_TCPROW_OWNER_PID][tcprow],
[MIB_UDPROW_OWNER_PID][udprow]), so the flow-table key normalization is shared.

### 2.5 Orientation: which of `daddr`/`saddr` is the local endpoint

Added 2026-08-15 for [#36](https://github.com/cyljacky02/zpulsar/issues/36); the original
ticket assumed a single global orientation, which is wrong for UDP receive.

**The manifest cannot answer this.** Every data event's message template is
`"%2 bytes transmitted/received from %4:%6 to %3:%5"` — that is `saddr:sport` → `daddr:dport`
— for *all* of 10/11/26/27/42/43/58/59. The same packet-oriented phrasing is used for send
and receive alike, so it neither distinguishes the two nor survives checking: it is
demonstrably wrong for TCP receive (below). Only a controlled live trace settles it.

**Method.** Elevated `logman` file session on the provider (keywords `0x30`, level 4),
traffic generated from a known PID with known local ports, then the ETL's event records
decoded directly against the §Verdict layout — `tracerpt` and `Get-WinEvent` both decline to
decode this provider's templates and silently emit only the session header, so neither can
be used to check payloads. Three runs: real-internet IPv4 (UDP to `8.8.8.8:53`, TCP to
`1.1.1.1:80`), and IPv4 + IPv6 loopback socket pairs where each datagram's sending and
receiving socket are both known.

**Result.**

| ids | orientation | local endpoint is |
|---|---|---|
| 10, 11, 12, 13, 15, 26, 27, 28, 29, 31 (all TCP) | endpoint-oriented | `saddr`/`sport` |
| 42, 58 (UDP send) | endpoint-oriented | `saddr`/`sport` |
| **43, 59 (UDP receive)** | **packet-oriented** | **`daddr`/`dport`** |

The discriminator is what a single datagram/segment looks like from both ends:

- **UDP.** The send event and the receive event for the *same* datagram carry byte-identical
  `saddr`/`daddr`. That is only possible if both describe the datagram rather than either
  socket — so on the receiving side `saddr` is the sender, i.e. the remote. Loopback pair
  `::1:60110 → ::1:60109`: id 58 and id 59 both report `saddr=:60110, daddr=:60109`, and the
  receiving socket is `:60109`.
- **TCP.** The send and the matching receive on one socket carry the *same* `saddr` = that
  socket's own local address, and the two ends of the connection report mirrored tuples.
  tcpip.sys logs against the TCB, which knows local and remote regardless of direction.
  Loopback pair: client `:53791` reports `saddr=:53791` on both its send (26) and its
  receive (27); server `:53790` reports `saddr=:53790` on both of its own.

So the #20 verification was correct for TCP and not an artefact of a symmetric echo pair —
but it was TCP-only, and generalizing it to UDP split every UDP conversation into two
Flows with mirrored endpoints (#36).

Consequence for parsing: orientation is a property of the (event id, direction) pair, not of
the provider. `parser.zig` encodes it once in `Class.orientation` and applies it through
`assignEndpoints`, which the TDH fallback shares so the two paths cannot disagree.

**Nuance — broadcast and multicast receives.** Because a UDP receive reports the datagram's
own destination, a datagram addressed to a broadcast or multicast group yields that group as
the Flow's local endpoint (e.g. `192.168.88.255:57621`, `224.0.0.252:5355`) rather than a
unicast address the socket could have bound. There is no better answer available: the
payload carries no field for the receiving interface's unicast address, so anything else
would be invented. The remote side — the only side Hostname Attribution keys on — is the
actual sender, which is what matters. A consequence is that a process broadcasting and
hearing its own datagram shows two Flows (`us → group` for the send, `group → us` for the
receive); those are genuinely different endpoint pairs, not the #36 mirroring, which
affected ordinary unicast conversations.

## 3. Real-time consumer mechanics

### 3.1 Pipeline

1. `StartTraceW` with the properties in the Verdict table. If `ERROR_ALREADY_EXISTS`, stop
   the orphan by name and retry (Learn explicitly tells components to clean up their own
   orphaned session rather than start a second one — [EVENT_TRACE_PROPERTIES,
   LoggerNameOffset][props]).
2. `EnableTraceEx2(session, &{7DD42A49-…}, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
   TRACE_LEVEL_INFORMATION, 0x30, 0, 0, NULL)` ([EnableTraceEx2][enable]). MatchAnyKeyword
   `0x10|0x20`; any-bit match is sufficient, and 0 would also work (treated as
   all-keywords for manifest providers).
3. `OpenTraceW` with `LoggerName = session name`,
   `ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD`,
   `EventRecordCallback` + `Context` ([EVENT_TRACE_LOGFILE][logfile]).
4. `ProcessTrace(&handle, 1, NULL, NULL)` on a dedicated thread — it blocks until
   `CloseTrace`/`BufferCallback FALSE`/session stop; a real-time `ProcessTrace` call takes
   exactly one real-time handle ([ProcessTrace][processtrace]).
5. Shutdown: `CloseTrace`, then `ControlTrace(…, EVENT_TRACE_CONTROL_STOP)`. Also register a
   console/ctrl handler: an abandoned session keeps logging (ETW sessions outlive their
   creating process).

Privileges: controlling a session, enabling a provider into a cross-process session, and
consuming real-time events all require admin / Performance Log Users / LocalSystem
([ControlTrace ERROR_ACCESS_DENIED][controltrace], [EVENT_TRACE_LOGFILE, LoggerName][logfile]).
zPulsar's existing admin-elevation requirement covers this.

### 3.2 Parsing: fixed offsets, TDH as validator only

Every data-carrying template in this provider is a flat sequence of fixed-width scalars (no
strings, no varlength fields), so payload offsets are compile-time constants per event ID
(§Verdict). The hot path should be a switch on `EventDescriptor.Id` + bounds-check
(`UserDataLength >= expected`) + direct loads. TDH (`TdhGetEventInformation`) is the
documented general decoder but costs a schema lookup per call; use it once at startup (or
in debug builds) to verify the hardcoded offsets against the live OS manifest, and as the
fallback if `Version != 0` ever appears. This is the same tradeoff production consumers
make — System Informer casts `UserData` straight to fixed structs ([etwmon.c][etwmon]).

### 3.3 Latency: the one real constraint

Documented delivery rule: "Delivers the events to consumers in real-time. **Events are
delivered when the buffers are flushed, not at the time the provider writes the event**"
([logging-mode constants][modes]). A buffer is flushed when it fills, when `FlushTimer`
expires, or on explicit flush ([EVENT_TRACE_PROPERTIES][props], [ControlTrace][controltrace]).
`FlushTimer` is in **seconds** with a documented minimum of 1; for real-time sessions a
value of 0 means the default 1 s ([EVENT_TRACE_PROPERTIES][props]).

Consequences for the 200 ms budget:

- Under active traffic, 16 KB buffers fill in well under 200 ms (each event is ~28–90 bytes
  + header; a few thousand events/s per CPU fills a buffer in tens of ms), so delivery is
  buffer-fill-driven and fast.
- For trickle flows (one event sitting in a per-CPU buffer), the timer floor means up to
  1 s latency. To guarantee < 200 ms, the controller thread calls
  `ControlTrace(EVENT_TRACE_CONTROL_FLUSH)` every 100–150 ms; flush delivers the session's
  active (non-empty) buffers ([ControlTrace][controltrace]). Learn notes explicit flushes
  are "not normally needed" and that higher flush periods reduce CPU — i.e. the tick has a
  real but small cost; make it adaptive (suspend when no flows active / UI hidden) to hold
  idle CPU at ~0.
- `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` (krabsetw's default alongside real-time mode,
  [krabs trace defaults][krabs]) would improve trickle latency and ordering, but Learn
  explicitly warns against it above ~1,000 events/s ([logging-mode constants][modes]) — a
  saturated link exceeds that. Byte accounting is order-insensitive (counters are
  additive), so keep default per-CPU buffering.

### 3.4 CPU

Idle: zero events → the ProcessTrace thread sleeps in the kernel; only the (adaptive) flush
tick runs. Well under 1%. Under load: event cost is dominated by ETW's own per-event
logging (sub-microsecond) plus a ~10–30 ns fixed-offset parse; at a heavy 20k events/s
that is single-digit-% of one core, and the session can shed load safely — overflow drops
events and counts them in `EventsLost` (query via `EVENT_TRACE_CONTROL_QUERY`,
[EVENT_TRACE_PROPERTIES][props]); on `EventsLost > 0` the engine re-snapshots (§5) rather
than carrying silent undercounts.

## 4. Cold start: snapshot + reconciliation

ETW only reports *activity*; connections that exist before the session starts and stay
idle would be invisible. Seed the flow table at startup:

- TCP: `GetExtendedTcpTable(pTable, &size, FALSE, AF_INET|AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)`
  → `MIB_TCPTABLE_OWNER_PID` / `MIB_TCP6TABLE_OWNER_PID`; each row: local/remote
  address+port, TCP state, `dwOwningPid` ([GetExtendedTcpTable][gettcp],
  [MIB_TCPROW_OWNER_PID][tcprow]).
- UDP: `GetExtendedUdpTable(…, UDP_TABLE_OWNER_PID, …)` for both families →
  `MIB_UDPROW_OWNER_PID` / v6: local address+port + `dwOwningPid` (UDP has no remote
  endpoint at the table level) ([GetExtendedUdpTable][getudp], [MIB_UDPROW_OWNER_PID][udprow]).

Reconciliation model:

- **Attribution never depends on the snapshot.** Every data event carries its own payload
  PID, so bytes are attributed correctly from the first event even for flows the snapshot
  missed. The snapshot exists to (a) list pre-existing idle connections in the UI, (b) give
  close events a row to close, and (c) re-baseline after `EventsLost > 0`.
- Order of operations: start the ETW session first, then snapshot, then process the
  (buffered) event stream — events that raced the snapshot just update rows that already
  exist (match on normalized 5-tuple; both sources are network-byte-order, §2.4). A
  connection seen in an event but absent from the snapshot is inserted from the event.
- Lifecycle after start: TCP rows open/close via events 12/15/13 (v6: 28/31/29). UDP has no
  lifecycle events — age UDP flow entries out on inactivity (e.g. 60 s) and re-poll the UDP
  table at low frequency (5–10 s) for listener display.
- PID → image name: resolve lazily on first sight (`OpenProcess` +
  `QueryFullProcessImageNameW`), cache; PID-reuse hazard is bounded by the same-session
  option of also enabling `Microsoft-Windows-Kernel-Process` for process start/stop events
  later (out of scope for this ticket, fits the same session for free).

## 5. Constants (verified in the Zig 0.16 toolchain's bundled headers)

From `lib/libc/include/any-windows-any/evntrace.h` (mingw-w64, ships with Zig — no Windows
SDK install needed): `EVENT_TRACE_REAL_TIME_MODE 0x00000100`,
`EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING 0x10000000`, `EVENT_TRACE_SYSTEM_LOGGER_MODE
0x02000000`, `EVENT_TRACE_INDEPENDENT_SESSION_MODE 0x08000000`,
`EVENT_TRACE_FLAG_NETWORK_TCPIP 0x00010000`, `EVENT_TRACE_CONTROL_FLUSH 3`,
`KERNEL_LOGGER_NAME "NT Kernel Logger"`. From `evntcons.h`: `PROCESS_TRACE_MODE_REAL_TIME
0x00000100`, `PROCESS_TRACE_MODE_RAW_TIMESTAMP 0x00001000`,
`PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000`. All APIs are in `advapi32`/`sechost`
(evntrace) and `iphlpapi`; nothing requires the full Windows SDK.

## 6. Risks / open items for the prototype

1. **Trickle-flow latency** rests on the explicit-flush tick; measure its actual CPU cost
   at 10 Hz (expected negligible — it only delivers non-empty buffers).
2. **`size` semantics** (§2.2): validate against a known transfer (e.g. 100 MB loopback +
   NIC transfer) that totals match, and decide whether to surface retransmit bytes as a
   separate stat.
3. **Loopback traffic** is expected to appear (transport-level instrumentation); confirm
   and decide whether to tag it.
4. Event 17/49 (fail) payloads differ from the message placeholders; don't parse them
   beyond the event ID until needed.

## Sources

- Provider manifest dump (primary): `wevtutil gp Microsoft-Windows-Kernel-Network /ge:true /gm:true`,
  `Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Network` — event IDs, keywords,
  channel, and full payload templates as registered in the OS.
- [TcpIp class (kernel-logger MOF; event types, header-PID caveat)][tcpip]
- [UdpIp class][udpip] · [TcpIp_TypeGroup1 (field list)][tg1] · [UdpIp_TypeGroup1][utg1]
- [EVENT_TRACE_PROPERTIES (BufferSize/FlushTimer/buffer-flush delivery model)][props]
- [Logging Mode Constants (REAL_TIME, NO_PER_PROCESSOR_BUFFERING, SYSTEM_LOGGER_MODE)][modes]
- [EnableTraceEx2 (keywords, 8-session limit for manifest providers, privileges)][enable]
- [ProcessTrace (blocking, one real-time handle, ordering)][processtrace]
- [EVENT_TRACE_LOGFILE (ProcessTraceMode flags, real-time consumer privileges)][logfile]
- [ControlTrace (EVENT_TRACE_CONTROL_FLUSH / QUERY, privileges)][controltrace]
- [Configuring and Starting the NT Kernel Logger Session (single instance)][ntkl]
- [GetExtendedTcpTable][gettcp] · [GetExtendedUdpTable][getudp] ·
  [MIB_TCPROW_OWNER_PID][tcprow] · [MIB_UDPROW_OWNER_PID][udprow]
- [System Informer ExtendedTools `etwmon.c` (production reference consumer)][etwmon]
- [microsoft/krabsetw (real-time session defaults)][krabs]
- [microsoft/perfview TraceEvent `KernelTraceEventParser.cs` (event-ID mapping for GUID 7dd42a49)][traceevent]
- mingw-w64 headers bundled with Zig 0.16: `lib/libc/include/any-windows-any/evntrace.h`, `evntcons.h`.

[tcpip]: https://learn.microsoft.com/en-us/windows/win32/etw/tcpip
[udpip]: https://learn.microsoft.com/en-us/windows/win32/etw/udpip
[tg1]: https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-typegroup1
[utg1]: https://learn.microsoft.com/en-us/windows/win32/etw/udpip-typegroup1
[props]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
[modes]: https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
[enable]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
[processtrace]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
[logfile]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
[controltrace]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
[ntkl]: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session
[gettcp]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
[getudp]: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
[tcprow]: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
[udprow]: https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_pid
[etwmon]: https://github.com/winsiderss/systeminformer/blob/master/plugins/ExtendedTools/etwmon.c
[krabs]: https://github.com/microsoft/krabsetw
[traceevent]: https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs
