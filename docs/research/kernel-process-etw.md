# Kernel-Process ETW events for process start/exit tracking

Research ticket: [#13](https://github.com/cyljacky02/zpulsar/issues/13) · Date: 2026-08-14
Scope: Windows 10 x64 1809+, user-mode only, admin-elevated. Companion to the flow data
model (#8): event-driven process-exit marking and PID-reuse-safe Process Row keying
(PID + start time), riding the same real-time session as `Microsoft-Windows-Kernel-Network`.

Evidence classes used: the OS's own registered provider manifest (`wevtutil gp
Microsoft-Windows-Kernel-Process /ge:true /gm:true` and `Get-WinEvent -ListProvider`
template dump), a **local empirical trace** (elevated, Windows 11 25H2 build 26200: file-mode
session via `StartTrace`/`EnableTraceEx2` P/Invoke, raw `EVENT_RECORD.UserData` hex dumps to
verify byte offsets, `EVENT_CONTROL_CODE_CAPTURE_STATE` rundown test, a 60 s event-volume
measurement, and a bit-exact `GetProcessTimes` comparison), per-Windows-build manifest
archives (jdu2600/Windows10EtwEvents, 1511 → 25H2), Microsoft Learn API docs, reference
consumers (microsoft/krabsetw, microsoft/perfview), and the mingw-w64 headers bundled with
Zig 0.16. Anything verified only on the local 25H2 machine is flagged
**re-verify on Win10 1809**.

---

## Verdict

**Enable `Microsoft-Windows-Kernel-Process` (GUID `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)
into the existing `zPulsarNet` session with a second `EnableTraceEx2` call — level 4,
`MatchAnyKeyword = 0x10` (`WINEVENT_KEYWORD_PROCESS`). Key Process Rows by
(PID, payload `CreateTime`), which is bit-identical across the start event, the stop event,
the rundown event, and `GetProcessTimes` (verified empirically). Cold-start comes from the
provider itself: one `EnableTraceEx2(EVENT_CONTROL_CODE_CAPTURE_STATE)` call makes the
kernel emit one ProcessRundown (ID 15) event per existing process, with the same payload
layout as ProcessStart — no snapshot API needed. The start/rundown payloads carry the full
NT-device-path image name, making the lazy `OpenProcess`/`QueryFullProcessImageNameW`
resolution from #2 unnecessary for the common path. Payloads are NOT fully fixed-width
(trailing strings; a variable-length SID on v3+), but every field zPulsar needs sits in a
fixed-offset prefix except the start-event image name, which needs at most one SID skip.
Volume is negligible: 1,649 events/60 s measured on a heavily-loaded dev machine.**

### Session / enable config (delta on top of #2's `zPulsarNet` config)

| Setting | Value | Why / source |
|---|---|---|
| Enable call | `EnableTraceEx2(h, &{22FB2CD6-…}, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION (4), 0x10, 0, 0, NULL)` | `0x10` = `WINEVENT_KEYWORD_PROCESS` (manifest); same mask PerfView uses ([CommandProcessor.cs][perfview-cp]); verified live |
| Rundown request | `EnableTraceEx2(h, &{22FB2CD6-…}, EVENT_CONTROL_CODE_CAPTURE_STATE, 4, 0x10, 0, 0, NULL)` after the consumer thread is running | "Requests that the provider log its state information" ([EnableTraceEx2][enable]); emits one ID-15 event per existing process (verified: 500 processes → 500 events); krabsetw's `EnableRundownEvents()` does exactly this ([UserTrace006_Rundown.cs][krabs-rundown]) |
| What arrives under 0x10 | IDs **1** (ProcessStart), **2** (ProcessStop), **15** (ProcessRundown), and nominally 27 (ProcessInPrivateSet, never observed) | Manifest keyword table; 60 s empirical trace saw only 1/2/15. Ignore unknown IDs in the dispatch switch |
| Optional narrowing | `ENABLE_TRACE_PARAMETERS` + `EVENT_FILTER_DESCRIPTOR{Type = EVENT_FILTER_TYPE_EVENT_ID}` restricting to 1, 2, 15 | Attribute filtering, ≤ 64 IDs ([EnableTraceEx2][enable]). Not needed at this volume. NOTE: Zig's bundled mingw headers lack `EVENT_FILTER_TYPE_EVENT_ID` (= 0x80000200) and the newer `EVENT_ENABLE_PROPERTY_*` values — define locally if used (§1.3) |
| Dispatch | Switch on `EventHeader.ProviderId` first (Kernel-Network vs Kernel-Process share the session), then on `(EventDescriptor.Id, Version)` | [EVENT_HEADER][hdr] |
| Buffers / flush | Unchanged from #2 (16 KB buffers, 100–150 ms flush tick) | Process events add ≤ ~10 KB/s even under heavy churn (§6); exit-marking latency is bounded by the same flush tick |
| Session count | Kernel-Process is a manifest provider — up to 8 sessions may enable it; no conflict with other monitors | [EnableTraceEx2][enable] |

### Event schema the engine parses

Versions differ by Windows build (next table). All integers little-endian, **payload is
tightly packed — no alignment padding** (verified against raw `UserData` hex; a u64 at
offset 4 is a legitimate unaligned read). `CreateTime`/`ExitTime` are FILETIME (u64,
100 ns since 1601, wall clock).

**Event 1 ProcessStart / Event 15 ProcessRundown** (identical layouts per version pair
1v2≡15v0, 1v3≡15v1, 1v4≡15v2):

| Field | v2 / 15v0 (1703–1809) | v3 / 15v1 (1903–Win11 23H2) | v4 / 15v2 (Win11 24H2+) |
|---|---|---|---|
| ProcessID u32 | @0 | @0 | @0 |
| ProcessSequenceNumber u64 | — | @4 | @4 |
| CreateTime u64 FILETIME | @4 | @12 | @12 |
| ParentProcessID u32 | @12 | @20 | @20 |
| ParentProcessSequenceNumber u64 | — | @24 | @24 |
| SessionID u32 | @16 | @32 | @32 |
| Flags u32 | @20 | @36 | @36 |
| ProcessTokenElevationType u32 | — | @40 | @40 |
| ProcessTokenIsElevated u32 | — | @44 | @44 |
| MandatoryLabel SID (variable, `8 + 4×byte[ofs+1]` bytes) | — | @48 | @48 |
| ImageName UTF-16LE NUL-terminated | @24 | after SID | after SID |
| ImageChecksum u32, TimeDateStamp u32, PackageFullName wsz, PackageRelativeAppId wsz | after ImageName | after ImageName | after ImageName |
| SecurityMitigations u32 | — | — | last 4 bytes |

**Event 2 ProcessStop**:

| Field | v1 (1703–1809) | v2 (1903+) |
|---|---|---|
| ProcessID u32 | @0 | @0 |
| ProcessSequenceNumber u64 | — | @4 |
| CreateTime u64 FILETIME | @4 | @12 |
| ExitTime u64 FILETIME | @12 | @20 |
| ExitCode u32 | @20 | @28 |
| TokenElevationType u32 @24 / HandleCount u32 @28 / CommitCharge u64 @32 / CommitPeak u64 @40 / CPUCycleCount u64 @48 / ReadOps u32 @56 / WriteOps u32 @60 / ReadKB u32 @64 / WriteKB u32 @68 / HardFaultCount u32 @72 | as listed | +8 to every offset (@32…@80) |
| ImageName **ANSI** NUL-terminated (truncated, §2.4) | @76 | @84 |

(Stop v0, pre-1703 only: PID@0, CreateTime@4, ExitTime@12, ExitCode@20, TokenElevationType@24,
HandleCount@28, CommitCharge@32, CommitPeak@40, ANSI ImageName@48 — not reachable on 1809+.)

### Versions by Windows build

The kernel emits exactly one version per event per build — the newest its manifest defines
(verified on 25H2: only 1v4/2v2/15v2 appear). Per-build history from jdu2600's manifest
archive ([Windows10EtwEvents][jdu]; the Kernel-Process manifest changed only at 1607, 1703,
1903, Win11 21H2, 22H2, 24H2):

| Build range | ProcessStart | ProcessStop | ProcessRundown | Notes |
|---|---|---|---|---|
| Win10 1703 – 1809 | **v2** | **v1** | **v0** | No sequence numbers, no SID → ImageName at fixed @24. **This is the 1809 floor — re-verify on a real 1809 box** |
| Win10 1903 – Win11 23H2 | v3 | v2 | v1 | Adds ProcessSequenceNumber (+parent), token info, MandatoryLabel SID |
| Win11 24H2+ | v4 | v2 | v2 | Adds trailing SecurityMitigations u32 (verified locally on 25H2) |

Engine rule: implement (id, version) pairs {1v2, 1v3, 1v4, 2v1, 2v2, 15v0, 15v1, 15v2};
for any unknown newer version fall back to TDH-derived offsets computed once per
(id, version) — same policy as #2. Fields were *inserted* between v2→v3 (not appended), so
never parse an unknown version with old offsets.

### Keying and cold start

- **Row key: (PID, CreateTime-as-raw-u64).** Present in every version of start, stop, and
  rundown. Verified bit-identical between a process's start and stop events, and bit-identical
  to `GetProcessTimes` creation time (raw FILETIME `134311895675682977` from the event ==
  `Process.StartTime.ToFileTimeUtc()` for the same PID). PID-reuse collisions would need the
  same PID *and* the same 100 ns creation tick — effectively impossible.
- `ProcessSequenceNumber` (1903+) is a strictly-increasing per-boot u64 (observed: Idle=0,
  System=1, …1.5 M after 3 days) — use opportunistically as a cheaper unique key when
  version ≥ v3/2v2/15v1, but (PID, CreateTime) must remain the canonical key for 1809.
- **Cold start: CAPTURE_STATE rundown, not a snapshot API.** Sequence: enable provider →
  start consuming → issue `EnableTraceEx2(…CAPTURE_STATE…)` → ID-15 events stream in (one
  per live process, including PID 0 Idle / PID 4 System), carrying CreateTime + ParentPID +
  full image path. A process that started after enable appears as both a start event and a
  rundown row — dedupe on (PID, CreateTime), which matches exactly. CAPTURE_STATE can be
  re-issued at any time (e.g. after `EventsLost > 0`) — it is just another control call.
- Fallback snapshot (only if rundown ever fails): `CreateToolhelp32Snapshot` for PID/PPID
  enumeration ([CreateToolhelp32Snapshot][th32]), `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`
  + `GetProcessTimes` for the creation FILETIME ([GetProcessTimes][gpt]) — same time domain
  as the payload, verified — and `QueryFullProcessImageNameW` for the path ([QFPIN][qfpin]).
  `NtQuerySystemInformation(SystemProcessInformation)` also carries CreateTime but only in
  winternl-"Reserved" fields ([NtQuerySystemInformation][ntqsi]) — prefer the documented pair.

### Volume / CPU

Measured 60 s under deliberately heavy churn (multiple AI coding agents spawning shells
continuously): **1,649 events (841 starts, 807 stops) ≈ 27.5 events/s**, sizes 95–99 B
(stop), 174–520 B (start, path-length dependent), 86–182 B (rundown) → **≤ ~10 KB/s worst
case, ~0 idle**. That fills one 16 KB buffer every couple of seconds; delivery rides the
existing 100–150 ms flush tick. Kernel-side per-event cost is sub-µs, consumer parse is a
fixed-offset load + one string copy. No measurable threat to the < 1 % idle CPU budget.
One-time rundown burst at cold start: ~500 events ≈ 70 KB on a 500-process desktop.

---

## 1. Enable surface

### 1.1 Keyword mask

The manifest assigns events 1, 2, 15 (and 27) keyword `0x8000000000000010`; the top bit is
the Microsoft-reserved channel bit for the Analytic channel and is not part of the enable
mask — `MatchAnyKeyword = 0x10` (`WINEVENT_KEYWORD_PROCESS`), level 4, is the minimal and
sufficient enable (verified live via `logman … -p Microsoft-Windows-Kernel-Process 0x10 4`).
PerfView enables the same GUID with exactly `TraceEventLevel.Informational, 0x10`
([CommandProcessor.cs][perfview-cp]). Other keywords (`THREAD 0x20`, `IMAGE 0x40`,
`PROCESS_FREEZE 0x200`, `JOB 0x400`, …) stay off — thread and image-load events are the
high-volume categories of this provider and zPulsar does not need them.

### 1.2 Rundown is not keyword-gated

Plain enable with 0x10 produced **zero** ID-15 events in a trace that spanned session start
(empirical). Rundown fires only in response to `EVENT_CONTROL_CODE_CAPTURE_STATE`
("Requests that the provider log its state information", [EnableTraceEx2][enable]).
krabsetw documents the same: "the rundown events often cannot be enabled by keyword alone.
The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE"
([UserTrace006_Rundown.cs][krabs-rundown]). The CAPTURE_STATE call returned 0 and delivered
500 rundown events within the same second (empirical, local).

### 1.3 Zig header gaps

Verified in the mingw-w64 headers bundled with Zig 0.16
(`lib/libc/include/any-windows-any/`): `EVENT_CONTROL_CODE_CAPTURE_STATE 2` (evntrace.h:705),
`ENABLE_TRACE_PARAMETERS` + `ENABLE_TRACE_PARAMETERS_VERSION_2` (evntrace.h:787/823),
`EVENT_FILTER_DESCRIPTOR` (evntprov.h:99). **Missing**: `EVENT_FILTER_TYPE_EVENT_ID`
(SDK value 0x80000200), `MAX_EVENT_FILTER_EVENT_ID_COUNT` (64), the `EVENT_FILTER_EVENT_ID`
struct, and post-Vista `EVENT_ENABLE_PROPERTY_*` values (only SID/TS_ID/STACK_TRACE are
present). If event-ID filtering or `EVENT_ENABLE_PROPERTY_PROCESS_START_KEY` is ever wanted,
zPulsar must define those constants itself; for the recommended keyword-only enable, nothing
is missing.

## 2. Event schema notes

### 2.1 Source of truth and empirical confirmation

The Verdict tables are the OS's registered manifest templates (`Get-WinEvent -ListProvider`
dump of every version of events 1/2/15), cross-checked against raw `UserData` bytes from a
live trace. Example, ProcessStart v4 for `PING.EXE` (UserDataLength 176): PID@0 = 45556,
seq@4 = 1518780, CreateTime@12 = `0x01DD2BF51EDBC0A1`, ParentPID@20 = 47284 (the spawning
powershell), SessionID@32 = 1, SID@48 = `01-01-00-00-00-00-00-10-00-30-00-00` (S-1-16-12288,
12 bytes), ImageName@60 = `\Device\HarddiskVolume3\Windows\System32\PING.EXE`, then
checksum/timestamp/two empty package strings/SecurityMitigations — total exactly 176 bytes,
proving tight packing with zero padding.

### 2.2 SID parse (v3+ only)

`win:SID` in a manifest payload is a raw SID structure, not a MOF-style TOKEN_USER blob:
`Revision u8, SubAuthorityCount u8, IdentifierAuthority u8[6], SubAuthority u32×count` —
length `8 + 4×SubAuthorityCount` (observed 12 bytes for all S-1-16-x integrity labels, but
compute it from byte 1; do not hardcode 12). This is the only variable-length field before
ImageName, so `ImageName` starts at `48 + 8 + 4×payload[49]`.

### 2.3 ImageName in start/rundown events: full NT device path

- Normal processes: full kernel path, e.g.
  `\Device\HarddiskVolume3\Windows\System32\cmd.exe`, including packaged apps
  (`…\Program Files\WindowsApps\Microsoft.WindowsNotepad_…\Notepad\Notepad.exe`, with
  `PackageFullName`/`PackageRelativeAppId` populated) and executables in arbitrary user
  directories (verified with a test exe under `%TEMP%`).
- Protected processes come through like any other — rundown showed the full path for
  `csrss.exe` (a PPL) with no access checks, because the payload is produced by the kernel,
  not by an `OpenProcess` from our side.
- Kernel-managed / minimal processes carry a bare name with no path: `Idle` (PID 0),
  `System` (PID 4), `Secure System`, `Registry`, `MemCompression`. Display these as-is.
- Path domain caveats: convert `\Device\HarddiskVolumeN\` → drive letter via a
  `QueryDosDeviceW` mapping table (refresh on device arrival/removal); network-image
  processes will show `\Device\Mup\…`. WOW64 has no effect — this is the kernel's record of
  the image file object, not a redirected filesystem lookup, so 32-bit processes show their
  true path.

### 2.4 ImageName in stop events: ANSI, truncated — never display it

Stop-event ImageName is `win:AnsiString` sourced from the EPROCESS embedded name buffer: a
test process named `zp_longname_processfortest.exe` produced `zp_longname_pr` (14 chars +
NUL) in its stop event while its start event carried the full path (empirical). Use the stop
payload only for (PID, CreateTime, ExitTime, ExitCode); take names from start/rundown.

### 2.5 Extra stop-event goodies

Stop v1+ carries `CPUCycleCount`, read/write op counts and KB, `HardFaultCount`, commit
peaks — lifetime process totals for free, should the UI ever want an "exited process
summary". No action needed now.

## 3. Time domains: QPC header vs FILETIME payload

Two clocks are in play and they never need cross-conversion:

- **Payload `CreateTime`/`ExitTime` are wall-clock FILETIME** written by the kernel from the
  same source `GetProcessTimes` reads — verified bit-exact (§Verdict). The Process Row key
  uses these raw u64s. Snapshot-vs-event consistency is therefore exact, not approximate.
- **Header `TimeStamp` is in the session's clock domain (QPC for `Wnode.ClientContext = 1`,
  per #2), but consumers receive it already converted**: "The resolution is system time
  unless the ProcessTraceMode member of EVENT_TRACE_LOGFILE contains the
  PROCESS_TRACE_MODE_RAW_TIMESTAMP flag, in which case the resolution depends on the value
  of the Wnode.ClientContext member" ([EVENT_HEADER][hdr]). Observed: with ClientContext = 1
  and default consumption, header timestamps arrived as FILETIME ~28 µs after the payload
  CreateTime of the same start event. zPulsar does not set RAW_TIMESTAMP (#2), so header
  times are directly comparable to payload times if ever needed — but the key must still be
  the payload CreateTime (the header stamp is event-write time, not process-create time).

## 4. Does this replace lazy image-name resolution from #2?

Yes for every process the engine will attribute traffic to:

| Process population | Name source | OpenProcess needed? |
|---|---|---|
| Started after zPulsar (start event) | full NT path in payload | No |
| Alive at cold start (rundown event) | full NT path in payload | No |
| Protected / PPL processes | payload (kernel-written) | No — avoids access-denied entirely |
| Minimal/kernel processes (System, Registry, …) | bare name in payload | No (nothing more exists) |
| Missed events (`EventsLost > 0` window) | re-issue CAPTURE_STATE; fallback `QueryFullProcessImageNameW` | Rarely |

Keep the `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW`
path only as the degraded-mode fallback ([QFPIN][qfpin] works for most protected processes
with QUERY_LIMITED, but the ETW path never has to try). Device-path → DOS-path prettifying
is a display concern (§2.3), not a keying concern — key/cache on the raw payload string.

## 5. Consumer mechanics (delta on #2)

Same session, same `ProcessTrace` thread, same callback. The only additions:

1. Second `EnableTraceEx2` for GUID `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` after
   `StartTrace` (order vs Kernel-Network enable is irrelevant).
2. After the consumer thread is pumping, one `EnableTraceEx2(EVENT_CONTROL_CODE_CAPTURE_STATE)`.
   Issue it *after* `OpenTrace`/`ProcessTrace` are live so the rundown burst cannot race the
   consumer's startup (events buffered before the consumer opens the session are delivered
   anyway in real-time mode only after opening — being live first avoids relying on that).
3. Dispatch: `if (rec->EventHeader.ProviderId == KernelProcessGuid)` → switch on
   `(Id, Version)`; bounds-check `UserDataLength` against the fixed prefix size before loads;
   unaligned u64 loads are required (packed payload).
4. Process-exit marking latency = delivery latency = the existing flush-tick bound
   (100–150 ms under trickle, buffer-fill under load) — comfortably below any UI-visible
   threshold for greying out an exited process's rows.

## 6. Volume and CPU detail

- 60 s measurement on the dev machine while several agent processes were compiling and
  shelling out continuously: 841 starts + 807 stops = 1,649 events. This is a *pessimistic*
  desktop (typical idle desktops sit at ~0–2 process events/s; bursty peaks during builds
  can reach hundreds/s for short periods).
- Even a 100×-worse sustained burst (2,750 ev/s ≈ 700 KB/s) is a fraction of what the
  Kernel-Network side already handles per #2's budget analysis; buffers shed load safely via
  `EventsLost`, and the recovery action (re-CAPTURE_STATE + re-snapshot per #2) already
  exists.
- The rundown burst is bounded by process count: 500 events / ~70 KB / a few dozen 16 KB
  buffer flushes, once at startup and once per loss-recovery.

## 7. Risks / open items

1. **1809 emitted-version assumption** — versions 1v2/2v1/15v0 for 1703–1809 come from the
   per-build manifest archive plus the (locally verified) rule "the kernel emits the newest
   manifest version". **Re-verify on Win10 1809**: run the same 30-line trace harness on a
   1809 VM and confirm the (id, version) pairs and that CAPTURE_STATE rundown works there
   (krabsetw's rundown example predates 1809, and event 15 exists since 1511's manifest, so
   risk is low).
2. **Event 27 (ProcessInPrivateSet)** shares keyword 0x10 on 24H2+; never observed. The
   unknown-ID/unknown-version guard covers it.
3. **Rundown burst vs 16 KB buffers**: 500 × ~140 B arrives faster than the flush tick
   drains; ETW just cycles buffers (min 2/CPU). If `EventsLost` shows up specifically at
   startup on low-core machines, raise `MaximumBuffers` — cheap knob, already planned in #2.
4. **`Flags` field semantics** are undocumented (observed 0 for plain processes, 3 for a
   packaged app); do not interpret.
5. **Clock skew edge**: payload CreateTime is wall-clock; a system-time change between a
   process's start and stop does not affect the key (the kernel stores absolute create time
   once), but rows keyed while the clock was wrong will show odd display times. Cosmetic.

## Sources

- Provider manifest dump (primary): `wevtutil gp Microsoft-Windows-Kernel-Process /ge:true /gm:true`
  and `Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process` — GUID, channel
  (Analytic), keywords (`WINEVENT_KEYWORD_PROCESS 0x10`), events 1 v0–v4 / 2 v0–v2 /
  15 v0–v2 full templates. Local machine: Windows 11 25H2 build 26200.
- Local empirical trace (elevated): `StartTrace` file-mode session, `EnableTraceEx2` enable +
  `EVENT_CONTROL_CODE_CAPTURE_STATE`, raw `EVENT_RECORD` hex dump via `OpenTrace`/`ProcessTrace`
  P/Invoke — byte offsets, tight packing, SID width, NT-device-path image names, stop-name
  truncation, 500-process rundown, bit-exact `GetProcessTimes` == payload CreateTime, 60 s
  volume numbers.
- [jdu2600/Windows10EtwEvents — per-build Kernel-Process manifest history][jdu] (file changed
  at 1607 / 1703 / 1903 / Win11 21H2 / 22H2 / 24H2; basis of the versions-by-build table).
- [microsoft/krabsetw UserTrace006_Rundown.cs — CAPTURE_STATE requirement for rundown][krabs-rundown] ·
  [UserTrace008_ProcessStartKey.cs — start-key/PID-reuse notes][krabs-psk]
- [microsoft/perfview CommandProcessor.cs — Microsoft's own enable mask (level 4, 0x10) for this GUID][perfview-cp]
  (PerfView has no static parser for this provider — it decodes via TDH/registered manifest,
  reinforcing the manifest dump as the schema authority.)
- [EnableTraceEx2 — CAPTURE_STATE, keyword semantics, EVENT_FILTER_TYPE_EVENT_ID limits, 8-session limit, privileges][enable]
- [EVENT_HEADER — TimeStamp domain/conversion rule][hdr] · [EVENT_RECORD][rec]
- [GetProcessTimes — creation FILETIME (fallback snapshot)][gpt] ·
  [CreateToolhelp32Snapshot][th32] · [QueryFullProcessImageNameW][qfpin] ·
  [NtQuerySystemInformation — SystemProcessInformation reserved fields][ntqsi]
- [Retrieving Event Data Using TDH — fallback decoder for unknown versions][tdh]
- mingw-w64 headers bundled with Zig 0.16 (`lib/libc/include/any-windows-any/evntrace.h`,
  `evntprov.h`, `evntcons.h`) — present/missing constants per §1.3.

[enable]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
[hdr]: https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
[rec]: https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
[gpt]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
[th32]: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
[qfpin]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
[ntqsi]: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
[tdh]: https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-data-using-tdh
[jdu]: https://github.com/jdu2600/Windows10EtwEvents
[krabs-rundown]: https://github.com/microsoft/krabsetw/blob/master/examples/ManagedExamples/UserTrace006_Rundown.cs
[krabs-psk]: https://github.com/microsoft/krabsetw/blob/master/examples/ManagedExamples/UserTrace008_ProcessStartKey.cs
[perfview-cp]: https://github.com/microsoft/perfview/blob/main/src/PerfView/CommandProcessor.cs
