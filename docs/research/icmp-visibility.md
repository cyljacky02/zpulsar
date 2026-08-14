# ICMP flow visibility from user mode (research ticket #3)

Question: how can zPulsar see per-process ICMP traffic from user mode only
(ADR-0001 forbids kernel components)?

Method: Microsoft Learn API docs, ETW provider manifests dumped from a live
Windows machine (`wevtutil gp`), source of real consumers (simplewall,
windows-rs metadata), plus two small local experiments (elevated, Windows 11
build 26200). Claims verified only empirically are flagged as such.

## Verdict

**Primary technique: the `Microsoft-Windows-TCPIP` ETW provider, keyword
`ut:Global` (0x8000008000000000 with the channel bit), event 1422 (task
`IcmpSendRecv`).** It emits one event per ICMP message in both directions with
`IcmpType`, `IcmpCode`, source/destination address, and direction. Attribution
comes from the ETW record header's ProcessId, not the payload:

- **Outbound ICMP: strong, real PID attribution.** Verified empirically: echo
  requests sent via `ping.exe` (the `IcmpSendEcho` path) are logged with the
  pinging process's PID in the event header.
- **Inbound ICMP: no attribution** (header PID is 4/System). zPulsar must
  correlate replies to the process that sent the matching request (remote
  address + request/reply type pairing, e.g. type 8 -> type 0, within a time
  window).

**Secondary/optional layer: WFP net events (`FwpmNetEventSubscribe`)** for the
drop side and cross-checking. `CLASSIFY_DROP` events surface blocked ICMP with
the application *path* (`appId`) — useful signal the ETW drop event (1423)
lacks. `CLASSIFY_ALLOW` events exist but require flipping a persistent,
machine-global engine option, and even then carry an app path, never a PID,
and no byte counts — so net events cannot be the primary source for a
per-process monitor.

**Attribution quality:** outbound per-message PID attribution is excellent but
rests on undocumented behavior (ETW header PID = caller context on the send
path); it must be re-verified on Windows 10 1809, and treated as an
engineering assumption, not a contract. Inbound attribution is heuristic and
ambiguous when several processes talk ICMP to the same remote host
concurrently (event 1422 does not carry the ICMP echo Identifier, so flows
cannot be disambiguated by ID).

**Hard limit: no user-mode source provides per-process ICMP byte counts.**
Event 1422 has no size field; WFP net events have no volume fields; the only
byte-accurate source (raw capture) has no process information. zPulsar should
report ICMP flows as message counts (bytes column "n/a" or estimated), and
explicitly not promise ICMP byte accounting.

**Raw sockets (`SIO_RCVALL`) remain a last resort** — packet bytes without any
attribution, per-interface socket management, and admin-only — justified only
if byte-accurate ICMP accounting ever becomes a requirement.

## Findings

### 1. WFP net events (`FwpmNetEventSubscribe` / `FwpmNetEventEnum`)

**What they carry.** Every net event shares a header
(`FWPM_NET_EVENT_HEADER0..5`) with: timestamp, `ipProtocol`, local/remote
address, local/remote port, `appId` ("The application ID of the local
application associated with the event" — a device-path of the executable),
`userId` (SID), `packageSid`. **There is no process ID field and no byte-count
field.**
Source: <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header2>

**Do they surface ICMP?** Yes — ICMP is classified by ALE, which is what
generates classify events: "A filter at the FWPM_LAYER_ALE_AUTH_CONNECT_V{4|6}
layer is matched ... for first outbound non-error ICMP messages with a unique
ICMP type, code, and ID", and AUTH_RECV_ACCEPT likewise "for first inbound
non-error ICMP messages (unicast) with a unique ICMP type, code, and ID". Note
the granularity: per unique type/code/ID ("flow"), not per packet.
Source: <https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers>

**Special conditions.** Event collection (`FWPM_ENGINE_COLLECT_NET_EVENTS`) is
on by default ("Collect network events. This is the default setting.") and the
setting "persist[s] across reboots". No Security auditing policy is involved —
net events are a BFE feature, independent of the `Audit Filtering Platform
Connection` audit subcategory.
Source: <https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmenginesetoption0>

However, the default collects **drop** events only. `CLASSIFY_ALLOW` events
(Windows 8+ per
<https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ne-fwpmtypes-fwpm_net_event_type>)
additionally require `FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS` to include
`FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW` = 0x10. The Learn page for
`FwpmEngineSetOption0` documents only the MCAST/BCAST keywords; the
CLASSIFY_ALLOW keyword value comes from Microsoft's Win32 metadata (windows-rs
bindings: `FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW: u32 = 16`,
`crates/libs/windows/src/Windows/Win32/NetworkManagement/WindowsFilteringPlatform/mod.rs`).
Source: <https://github.com/microsoft/windows-rs/blob/master/crates/libs/windows/src/Windows/Win32/NetworkManagement/WindowsFilteringPlatform/mod.rs>

*Empirical (Win11 26200):* with the defaults (`netsh wfp show options
optionsfor=netevents` -> `netevents = on`; `optionsfor=keywords` -> `keywords =
none`), running pings and then `netsh wfp show netevents` produced an **empty**
event list — permitted ICMP generates no net events until the CLASSIFY_ALLOW
keyword is set. Because keyword/collection settings persist machine-wide,
zPulsar would have to mutate global firewall-engine state and restore it —
a meaningful operational cost.

**Real consumer.** simplewall's network log is built on exactly this stack:
`FwpmNetEventSubscribe0..4` chosen by OS version, enables
`FWPM_ENGINE_COLLECT_NET_EVENTS` and sets `FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS`
including `FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW`; it resolves events to an
**application path** from `appId` — it never obtains a PID. ICMP shows up in
its log via `ipProtocol`.
Source: <https://github.com/henrypp/simplewall/blob/master/src/log.c>
(analysis via <https://deepwiki.com/search/how-does-simplewall-implement_64793b68-729e-44b7-8fd1-ec89ee43462d>)

**Latency.** Subscription (`FwpmNetEventSubscribe`) is callback-push;
enumeration (`FwpmNetEventEnum`) is a poll over BFE's recent-event buffer. No
latency or buffering guarantees are documented anywhere — if zPulsar uses net
events, delivery latency must be measured empirically.
Source: <https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe0>

**Assessment:** app-path (not PID) attribution, flow-granularity, no bytes,
requires persistent global option for allow events. Good as a *drop* log and
as a cross-check; insufficient as the primary per-process ICMP source.

### 2. `Microsoft-Windows-TCPIP` ETW provider

Provider manifest dumped locally (`wevtutil gp Microsoft-Windows-TCPIP
/ge:true /gm:true`, Windows 11 build 26200 — presence of these events on
Windows 10 1809 must be confirmed on a 1809 image; they are not documented on
Learn, so the manifest of the target OS is the authority).

**ICMP events:**

| Event | Task | Keyword(s) | Payload fields |
|---|---|---|---|
| 1422 | `IcmpSendRecv` | `ut:Global` (0x8000000000) | IPTransportProtocol, PathDirection, IcmpType, IcmpCode, CompartmentId, SourceAddress, DestAddress |
| 1423 | `IcmpPacketDrops` | `ut:Dropped` (0x10000000000) + `ut:TcpipDiagnosis` (0x80) | + DropReason, Status (v1 adds IfIndex) |
| 1424 | `IcmpEchoTimeout` | `ut:Global` | same shape as 1423 |

**No PID and no byte count in any payload.** Attribution is only available via
the ETW `EVENT_HEADER.ProcessId` of the logging thread.

*Empirical (Win11 26200):* a trace session on keyword 0x8000000000 during
`ping -n 3 1.1.1.1` (ping PID 47336) captured exactly 6 x event 1422:

```
hdrPID=47336 dir=0(out) icmpType=8   x3   <- echo requests, attributed to ping.exe
hdrPID=4     dir=1(in)  icmpType=0   x3   <- echo replies, attributed to System
```

So: **send-path ICMP events are logged in the calling process's context —
including `IcmpSendEcho` traffic — giving true per-message PID attribution for
outbound ICMP.** Receive-path events are logged at PID 4 (arbitrary/DPC
context) and carry no usable attribution. This is undocumented behavior;
re-verify per Windows build (especially 1809) before relying on it.

**Event-volume cost.** `ut:Global` is a state-change/diagnostic keyword, not a
per-packet data path (per-packet keywords like `ut:SendPath`/`ut:ReceivePath`
are separate bits). 198 of the provider's 753 events carry `ut:Global`, mostly
interface/address/route lifecycle tasks. *Empirical:* a ~5 s session captured
1127 events, of which 1052 were event 1542 ("IP: neighbor rundown") plus route
rundowns — a one-time state dump at session start; steady state was near zero
plus 2 events per ping. Cost: an initial rundown burst, then negligible.

**Latency:** standard ETW real-time delivery (buffer-flush bound, typically
sub-second with small buffers/flush timer) — acceptable for a monitor; exact
figures are configuration-dependent and should be measured.

### 3. Raw socket capture (`SIO_RCVALL`) — why last resort

- Requires a `SOCK_RAW` socket ("only members of the Administrators group can
  create sockets of type SOCK_RAW") bound to an **explicit** local interface
  ("you cannot bind to INADDR_ANY"), one socket per interface, with re-plumbing
  on interface changes.
  Sources: <https://learn.microsoft.com/en-us/windows/win32/winsock/sio-rcvall>,
  <https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2>
- Delivers **all** IPv4/IPv6 packets on the interface (RCVALL_IPLEVEL avoids
  NIC promiscuous mode but still delivers everything at IP level) — zPulsar
  would pay full-traffic-capture CPU to see a trickle of ICMP.
- **Zero attribution data.** Packets arrive as raw bytes; Windows exposes no
  ICMP endpoint-to-process table (IP Helper has `GetExtendedTcpTable`/
  `GetExtendedUdpTable`, but nothing for ICMP; `GetIcmpStatisticsEx` is
  system-wide MIB counters only). The raw-sockets doc itself notes a ping
  program must invent its own demultiplexing, "the application's process ID,
  for example" stuffed in the ICMP Identifier — a convention, not a rule, and
  `IcmpSendEcho`'s kernel-chosen Identifier is not queryable from user mode.
- The one thing it uniquely offers is **accurate byte counts** (full IP
  datagrams). Only worth the cost if ICMP byte accounting becomes a hard
  requirement, and then only as a size-annotation layer correlated against
  ETW-attributed flows.

### 4. The `IcmpSendEcho` path — who gets the blame?

`ping.exe` and most apps use `IcmpCreateFile` + `IcmpSendEcho[2/2Ex]`
(iphlpapi): a handle-based request serviced in kernel (no user socket; docs
describe it only as a handle from `IcmpCreateFile`; the legacy `icmp.sys`
implementation is not part of the documented contract).
Source: <https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho>

Attribution per technique:

- **TCPIP ETW 1422:** the requesting process (verified: ping.exe's PID on the
  send path). This is the decisive advantage of the ETW route.
- **WFP/ALE:** ALE classifies the "first outbound non-error ICMP message" with
  app identity; expected `appId` = the requesting exe (consistent with
  simplewall's log showing per-app ICMP), but **not verified here** because it
  requires enabling the persistent CLASSIFY_ALLOW keyword; verify during
  implementation.
- **Raw capture:** nothing — the packets carry no process information, and the
  kernel-chosen echo Identifier cannot be mapped back to the caller.
- **Security audit event 5156** (for completeness): the WFP audit pipeline
  *does* emit a real **ProcessID** + application path per permitted
  connection, and ICMP (protocol 1) is in scope — but it requires enabling
  the machine-wide "Audit Filtering Platform Connection" success auditing,
  floods the Security log for *all* protocols, and reading it needs Security
  log access. Rejected as too invasive for a monitor.
  Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156>

### 5. Negative result worth recording

`Microsoft-Windows-Kernel-Network` — the classic per-process PID+bytes
provider for TCP/UDP (tasks `KERNEL_NETWORK_TASK_TCPIP`/`UDPIP`) — has **no
ICMP events at all** (manifest dump: only TCP events 10-18/26-34 and UDP
42/43/49/58/59). Whatever zPulsar uses for TCP/UDP accounting, ICMP needs the
separate path described above.

## Open items for implementation (empirical verification required)

1. Confirm events 1422/1423/1424 exist in the Windows 10 1809 TCPIP manifest
   and that send-path header-PID attribution holds there.
2. Measure ETW delivery latency with zPulsar's chosen buffer configuration.
3. If the WFP drop/allow layer is adopted: verify `appId` for `IcmpSendEcho`
   callers, measure net-event callback latency, and implement save/restore of
   the persistent `NET_EVENT_MATCH_ANY_KEYWORDS` engine option.
4. Decide the UI contract for ICMP: message counts (recommended) vs estimated
   bytes.
