# Microsoft-Windows-DNS-Client ETW: per-PID hostname attribution

Research ticket: [#4](https://github.com/cyljacky02/zpulsar/issues/4)
Date: 2026-08-14

## Verdict

**Yes — the `Microsoft-Windows-DNS-Client` ETW provider delivers per-PID name-observed-at-lookup-time attribution, and cache hits are NOT silent.** Event **3008** (query completed) fires in the *calling process* for every completed `DnsQueryEx`/`getaddrinfo` resolution — **wire query, cache hit, or failure alike** — carrying the query name, result IPs (including CNAME chain), and status; the querying PID comes from the ETW event header. The charting stance (DNS-observation primary, async reverse lookup fallback) is workable. The real gaps are not cache hits but (a) names resolved *before zPulsar starts* (mitigated by a one-shot `MSFT_DnsClientCache` snapshot), and (b) processes that bypass the Windows resolver entirely — verified for `nslookup`, documented for Firefox DoH — which is exactly what the `GetNameInfoW` fallback is for. Event volume is trivial (~11 events/s total, ~4/s for 3006+3008, on an idle desktop; ~220 KB ETL per minute).

Method note: primary sources are (1) the provider's **registered manifest dumped from this machine** (`wevtutil gp Microsoft-Windows-DNS-Client` / `Get-WinEvent -ListProvider`, dnsapi.dll 10.0.26100.1591, Windows 11 26200), (2) **controlled live ETW traces** captured with `logman -ets` + `tracerpt` during scripted resolutions, and (3) Microsoft Learn documentation. Claims that could not be traced to one of these are marked **unverified**.

## 1. Provider basics

| Property | Value | Source |
|---|---|---|
| Provider name | `Microsoft-Windows-DNS-Client` | registered manifest (local dump) |
| GUID | `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` | registered manifest (local dump) |
| Resource DLL | `%SystemRoot%\system32\dnsapi.dll` | registered manifest (local dump) |
| Channels | `Microsoft-Windows-DNS-Client/Operational` (id 16, off by default), `System` (id 8) | registered manifest (local dump) |
| 3000-series keyword | `0x8000000000000000` (Microsoft reserved bit only) for the trace events 3006–3020; `0x8000000040000000` for 3000–3005 | registered manifest (local dump) |
| Level | all events of interest are `win:Informational` (4) | registered manifest (local dump) |

For zPulsar: enable the provider GUID in a realtime trace session at level `TRACE_LEVEL_INFORMATIONAL` with `MatchAnyKeyword = 0` (or `~0`). No event-log channel needs to be enabled — the 3000-series events flow to any ETW session that enables the provider (verified live: `logman create trace -p {1C95126E-...} 0xFFFFFFFFFFFFFFFF 5 -ets` received them with the Operational channel left disabled). Kernel-side filtering to just event 3008 is possible via `EnableTraceEx2` + `ENABLE_TRACE_PARAMETERS` with an `EVENT_FILTER_TYPE_EVENT_ID` filter (supported Windows 8.1+): <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters>

## 2. Event catalog (from the registered manifest, confirmed live)

Two distinct emitters, confirmed by observing `Execution.ProcessID` in live traces:

- **In-process events** (emitted by `dnsapi.dll` inside the *calling* process): 3006, 3007, 3008, 3015. These have **no `ClientPID` payload field — the PID is the ETW header's `ProcessId`**.
- **Service-side events** (emitted by the DNS Cache service `dnscache`, observed as `svchost` PID 2660): 3009–3014, 3016, 3018, 3019, 3020. Because the header PID would be svchost's, these gained an explicit **`ClientPID`** payload field in version 1 of each template (and `QueryBlob` correlation pointers in v2).

Payload templates below are verbatim from `Get-WinEvent -ListProvider "Microsoft-Windows-DNS-Client"` (types abbreviated; all names `win:UnicodeString`, all numeric fields `win:UInt32` except `QueryOptions` which is `win:UInt64`, blobs `win:Pointer`).

| ID | Manifest message (abbrev.) | Emitter | Payload (highest version) |
|---|---|---|---|
| **3006** | "DNS query is called for the name %1, type %2, query options %3 …" | caller | `QueryName, QueryType, QueryOptions, ServerList, IsNetworkQuery, NetworkQueryIndex, InterfaceIndex, IsAsyncQuery` (v0 only) |
| 3007 | "DnsQueryEx for the name %1 is pending" | caller | `QueryName` |
| **3008** | "DNS query is completed for the name %1, type %2, query options %3 with status %4 Results %5" | caller | `QueryName, QueryType, QueryOptions, QueryStatus, QueryResults` (v0 only — schema stable) |
| 3009 | "Network query initiated …" | dnscache | v1 adds `ClientPID`; v2 adds `QueryBlob, ParentBlob` |
| 3010 | "DNS Query sent to DNS Server %3 for name %1 and type %2" | dnscache | `QueryName, QueryType, DnsServerIpAddress` (+`ClientPID` v1) |
| 3011 | "Received response from DNS Server %3 … with response status %4" | dnscache | `QueryName, QueryType, DnsServerIpAddress, ResponseStatus` (+`ClientPID` v1; +blobs v2) |
| **3016** | "Cache lookup called for name %1, type %2, options %3 …" | dnscache | `QueryName, QueryType, QueryOptions, InterfaceIndex` (+`ClientPID` v1; +`QueryBlob` v2) |
| **3018** | "Cache lookup for name %1, type %2 and option %3 returned %4 with results %5" | dnscache | `QueryName, QueryType, QueryOptions, Status, QueryResults` (+`ClientPID` v1; +`QueryBlob` v2) |
| **3019** | "Query wire called for name %1, type %2 …" | dnscache | `QueryName, QueryType, InterfaceIndex, NetworkIndex` (+`ClientPID` v1; +`QueryBlob` v2) |
| **3020** | "Query response for name %1, type %2 … returned %5 with results %6" | dnscache | `QueryName, QueryType, NetworkIndex, InterfaceIndex, Status, QueryResults` (+`ClientPID` v1; +`QueryBlob` v2) |

So the commonly-cited "3008 = query completed with name + results" is **confirmed from the manifest, and its PID attribution is via the event header**, not a payload field. `EVENT_HEADER.ProcessId` is documented as "Identifies the process that generated the event": <https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header>

## 3. Cache hits are NOT silent (verified live)

Trace of two consecutive `getaddrinfo("example.com")` calls from PID 42576 (cache cleared before the first):

**Cold (wire) resolution** — 3006 → 3016/3018 (cache miss, `Status=9701`, `ClientPID=42576`) → 3019 → 3010 (server 8.8.8.8) → 3011 → **3020 `Status=0 QueryResults=104.20.23.154;172.66.147.243;`** → **3008 (header pid=42576) `QueryStatus=0 QueryResults=::ffff:104.20.23.154;::ffff:172.66.147.243;`** — ~16 events total.

**Warm (cache-hit) resolution** — 3006 → 3016 → **3018 `Status=0 QueryResults=104.20.23.154;172.66.147.243; ClientPID=42576`** → **3008 (header pid=42576) `QueryStatus=0`, same results** — ~6 events, no 3019/3020/3010/3011. Name, IPs, and PID all present.

Corroboration: Microsoft's Sysmon documentation for Event ID 22 (DNSEvent, which reports per-process DNS queries) states it "is generated when a process executes a DNS query, whether the result is successful or fails, **cached or not**. The telemetry for this event was added for Windows 8.1" — i.e. Microsoft itself ships a consumer of this telemetry with cached-result coverage, available well before our Windows 10 1809 floor: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query>

`QueryOptions` did **not** differ between the cached and wire 3008 in the trace, so cached-vs-wire cannot be distinguished from 3008 alone (only by the presence/absence of surrounding 3019/3020, or 3018 `Status`). zPulsar does not need the distinction.

### Names resolved before zPulsar starts

No retroactive events exist. Mitigation: snapshot the resolver cache once at startup via the documented **`MSFT_DnsClientCache`** CIM class (`root\StandardCimv2`; surfaced by `Get-DnsClientCache`), which returns `Entry, Name, Type, Data, TimeToLive, Status, Section` per record — enough to pre-populate the IP→name table (with TTLs, but **without PID attribution**; mark such entries "cache-derived"): <https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientcache>. (The `DnsGetCacheDataTable` export of dnsapi.dll returns the same data natively but is **undocumented** — prefer a one-shot WMI/CIM query despite the extra plumbing.)

## 4. `QueryResults` / `QueryStatus` wire format (verified live)

- Semicolon-delimited list. Address records are bare IP literals; non-address records are prefixed `type: <n> <data>`. Observed for `www.microsoft.com` (A): `type: 5 www.microsoft.com-c-3.edgekey.net;type: 5 e13678.dscb.akamaiedge.net;23.46.90.101;` — the CNAME chain (type 5) precedes the addresses.
- Dual-family lookups (`getaddrinfo`) complete as a single `QueryType=28` 3008 whose results carry IPv4 answers as **IPv4-mapped IPv6** literals (`::ffff:104.20.23.154`). The engine must normalize `::ffff:a.b.c.d` → IPv4 before matching flows.
- Each `getaddrinfo` also emits a preliminary `QueryType=1` 3008 with `QueryStatus=87` (ERROR_INVALID_PARAMETER) and empty results — **ignore 3008 events with empty `QueryResults` or nonzero `QueryStatus`**.
- Observed `QueryStatus`/`Status` values: `0` success, `87` internal probe noise, `9701` DNS_INFO_NO_RECORDS, `9003` DNS_ERROR_RCODE_NAME_ERROR (NXDOMAIN), `1460` ERROR_TIMEOUT (interface with no DNS server, e.g. the WSL vEthernet adapter — a recurring noise pattern). Codes are standard Win32/DNS status codes: <https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes>

## 5. Name-to-flow mapping strategy (the engine design)

**Subscribe to event 3008 only** (kernel-filtered by event ID if desired). It is the single event that fires for every completed resolution — cached or wire — in the caller's process, with name, full result set, and header PID. 3018/3020 are redundant for attribution (same data, service-side, needs `ClientPID` version handling); 3016/3019 carry no results.

Per accepted 3008 (`QueryStatus==0`, non-empty results): parse `QueryResults`, keep the CNAME chain tail for optional display, normalize v4-mapped literals, then upsert into a **three-tier lookup structure**:

1. **Tier 1 — per-process map** `(PID, IP) → {name, lastSeen}`. Authoritative: "the name this process actually resolved." Handles multiple processes resolving the same IP under different names (CDN/SNI reality). Flow attribution: exact `(flow.pid, flow.remoteIP)` hit.
2. **Tier 2 — global map** `IP → {name, lastSeen}` (last-writer-wins). Fallback for flows whose PID never emitted a 3008 for that IP (e.g. the name was resolved by a parent/helper process, or connection handed off). Display normally but attribution is inferred.
3. **Tier 3 — startup cache snapshot** (`MSFT_DnsClientCache`, no PID) and, after that, **reverse-lookup results** (section 7). Both visually distinguished.

Precedence on lookup: Tier 1 → Tier 2 → Tier 3 → raw IP.

**TTL / eviction:** 3008 carries **no TTL** (neither does 3018/3020 — verified from the templates). Do not try to mirror resolver TTLs. Instead: refresh `lastSeen` on every 3008 upsert *and* on every attributed flow; evict entries idle for a fixed window (suggest 30 min) under a bounded LRU (suggest 64K entries global, 1K per PID). Rationale: an active flow keeps its attribution alive regardless of DNS TTL (correct — the process connected under that name), and CDN churn is handled because a re-resolution overwrites the mapping before new flows appear; old flows retain the name they were attributed at flow-creation time (attribute once at flow creation, store the name on the flow record — do not re-derive per repaint).

**PID reuse:** attribute at flow-creation time and store on the flow; additionally clear a PID's Tier-1 entries on process-exit notification. Short-lived processes are fine — 3008 is realtime and emitted in-process before the connect typically happens.

## 6. Event volume / overhead (measured)

54-second passive trace on an idle-ish Windows 11 desktop (all keywords, all 3000-series events): **616 events ≈ 11.4 events/s**, 221 KB ETL. Breakdown: 3006/3008 = 210 each (~105 completed queries/min), 3009/3016/3018 = 34 each, 3019/3020 = 26 each, 3010/3011 = 13 each. Filtering to 3008 alone cuts this to ~4 events/s. Payloads are a few hundred bytes. Even at 100× busier this is negligible for a realtime ETW consumer; ETW sessions drop events rather than block providers if the consumer stalls, so size the session buffers generously (e.g. 64 KB × 32) — buffer sizing per <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties>.

## 7. Coverage gaps and the reverse-lookup fallback

**Verified gap — private resolvers bypass the provider entirely.** A traced `nslookup example.org` produced **zero** 3006/3008 events (nslookup carries its own resolver stub and sends DNS packets directly), while `ping example.org` from the same shell produced the normal pair. Likewise, browsers doing in-app DoH bypass the OS resolver: Firefox's TRR is documented as "Only use TRR, never use the native resolver" (mode 3) and "TRR bypasses system DNS": <https://wiki.mozilla.org/Trusted_Recursive_Resolver>. (Chrome's built-in async resolver when Secure DNS is enabled is the same class of gap — **unverified here**.) Windows 11's OS-level DoH is performed *by the dnscache service itself*, so those resolutions are expected to still emit these events — **unverified** (test machine used plain UDP DNS); irrelevant for the Windows 10 1809 floor, which has no OS DoH.

**Fallback: async reverse lookup.** Triggers when a flow's remote IP misses all three tiers (grace period ~2 s after flow creation to let a late 3008 land). Implementation facts from Microsoft Learn (<https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getnameinfow>):

- `GetNameInfoW` is **synchronous only** — no overlapped/async variant exists for address→name (unlike `GetAddrInfoExW` for forward lookups). "Async" therefore means a small dedicated thread pool (1–2 threads, bounded queue) so the UI/engine never blocks.
- Call with `NI_NAMEREQD | NI_NUMERICSERV`; when no PTR exists it fails with `WSAHOST_NOT_FOUND` (EAI_NONAME) instead of echoing the IP back.
- **Negative caching:** on `WSAHOST_NOT_FOUND`/`WSANO_RECOVERY`, record `IP → negative` with a ~10-minute suppression TTL (bounded LRU) so unresolvable ranges (most cloud IPs have generic or no PTR) don't trigger repeated lookups; successful PTR results enter Tier 3 with the normal idle-eviction policy.
- **Visual distinction is mandated by the semantics:** Microsoft's own docs say reverse lookups "are considered inherently unreliable, and should be used only as a hint," and PTR names (e.g. `ec2-52-1-2-3.compute-1.amazonaws.com`) are *not* "the name the process resolved." Render Tier-3/rDNS names dimmed/italic with a marker (e.g. a `~` prefix or `rDNS` badge), and cache-snapshot names similarly (e.g. `cache` badge), reserving plain styling for Tier-1/Tier-2 DNS-observed names.

## 8. Version caveats (Windows 10 1809 floor)

- All schema facts above were dumped from dnsapi.dll 10.0.26100.1591 on Windows 11 (26200). **Event 3008 exists only as version 0 even on this build** — its 5-field schema is stable, and 3008-based engines documented on Windows 10 in 2019 show the identical layout (corroboration, secondary: <https://blog.davidvassallo.me/2019/04/19/monitoring-dns-requests-with-powershell/>). Microsoft's Sysmon doc dates the underlying telemetry to Windows 8.1 (link in §3).
- The service-side `ClientPID` field (v1 of 3009–3020) — exact build of introduction **unverified**; if the engine ever consumes service-side events it must dispatch on `EventDescriptor.Version` and treat `ClientPID` as optional. The recommended 3008-only design sidesteps this entirely.
- Real consumers of this provider as sanity checks: Sysmon Event 22 (link in §3) and SilkETW, whose stock example collects exactly this provider (`SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -l Always -ot file -p out.json`): <https://github.com/mandiant/SilkETW>

## Sources

- Registered provider manifest, this machine: `wevtutil gp Microsoft-Windows-DNS-Client` and `Get-WinEvent -ListProvider "Microsoft-Windows-DNS-Client"` (dnsapi.dll 10.0.26100.1591, Windows 11 build 26200) — event IDs, versions, keywords, channels, message strings, payload templates.
- Live ETW traces, this machine: `logman create trace -p {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} -ets` + `tracerpt` — cache-hit behavior, emitter PIDs, QueryResults format, status codes, nslookup bypass, event volume.
- EVENT_HEADER (ProcessId semantics): <https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header>
- ENABLE_TRACE_PARAMETERS / event-ID filters: <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters>
- Sysmon Event ID 22 (cached-or-not, Windows 8.1+): <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query>
- GetNameInfoW (sync-only, NI_NAMEREQD, WSAHOST_NOT_FOUND, "hint" caveat): <https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getnameinfow>
- Get-DnsClientCache / MSFT_DnsClientCache: <https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientcache>
- Firefox TRR/DoH bypasses native resolver: <https://wiki.mozilla.org/Trusted_Recursive_Resolver>
- SilkETW (real consumer of this provider): <https://github.com/mandiant/SilkETW>
- Corroboration (secondary), 3008 on Windows 10 in 2019: <https://blog.davidvassallo.me/2019/04/19/monitoring-dns-requests-with-powershell/>
