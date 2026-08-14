# Research: per-service attribution inside svchost.exe

Ticket: [#5](https://github.com/cyljacky02/zpulsar/issues/5) · Date: 2026-08-14 · Scope: user mode, admin-elevated, Windows 10 x64 1809+

## Verdict

**Per-service attribution of network flows is feasible from elevated user mode, and the load-bearing path is fully documented API.** zPulsar should attribute in three tiers:

1. **PID attribution alone already resolves the service on most target machines.** Microsoft documents that since Windows 10 1703, services run in *separate* svchost processes on Client Desktop SKUs with more than 3.5 GB RAM — so on virtually every machine zPulsar targets (1809+, x64), most svchost PIDs host exactly one service, and the PID → service mapping from `EnumServicesStatusEx` (documented) is the whole answer.
2. **For the PIDs that still share** (deliberately grouped services such as RpcEptMapper+RpcSs and BFE+MpsSvc, services with `SvcHostSplitDisable=1`, machines ≤ 3.5 GB RAM, or admin-raised split thresholds), the TCP/UDP connection tables carry per-socket ownership info: `GetExtendedTcpTable(TCP_TABLE_OWNER_MODULE_*)` returns rows with an `OwningModuleInfo` blob, and the **documented** `GetOwnerModuleFromTcpEntry` / `GetOwnerModuleFromUdpEntry` resolve a row to a module name that Microsoft explicitly says "can be … a service name". This works per-socket/per-flow, not just per-thread, because the stack captures the creating thread's service tag at context-bind time. Elevation is required for real results on system processes — zPulsar is always elevated, so this is satisfied.
3. **Only when both tiers fail** does the UI fall back to "svchost.exe (N services)" with the service list from `EnumServicesStatusEx`. The undocumented fast path (`I_QueryTagInformation` on the raw service tag) is an optional performance optimization, not a correctness dependency.

**Recommendation: Service Attribution is safe to keep as a headline v1 feature.** Nothing undocumented is load-bearing; the honest-fallback case is a shrinking minority of flows on modern machines.

---

## 1. Service Host splitting since Windows 10 1703 (documented)

Microsoft's own doc, [Service host grouping in Windows 10](https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring), confirms:

> "Beginning with Windows 10 Creators Update (version 1703), services that were previously grouped will instead be separated - each will run in its own SvcHost process. This change is automatic for systems with **more than 3.5 GB** of RAM running the Client Desktop SKU. On systems with 3.5 GB or less RAM, we'll continue to group services into a shared SvcHost process."

One of the stated goals is exactly zPulsar's use case: "report CPU, I/O and network usage per service."

Consequences for zPulsar (target: Windows 10 x64 1809+):

- **On most target machines the problem reduces to plain PID attribution.** 1809 > 1703, and >3.5 GB RAM is near-universal on x64 desktops. A svchost PID that hosts one service is attributed by the PID → service map alone.
- **The split is not total.** The same doc lists exceptions: "the Base Filtering Engine (BFE) and the Windows Firewall (Mpssvc) will be grouped together in a single host group, as will the RPC Endpoint Mapper and Remote Procedure Call services." Grouped services are marked with a **`SvcHostSplitDisable`** value (default `1` = prevent splitting) in their service key under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`.
- **The split applies to the "Client Desktop SKU"** — Windows Server keeps grouping. Out of scope for v1 (client-only target) but worth noting in the spec.
- **Global threshold knob** (not Microsoft-documented; community-documented only): `HKLM\SYSTEM\CurrentControlSet\Control\SvcHostSplitThresholdInKB`, default `3670016` (0x380000 KB = 3.5 GB). Some "optimization guides" set it above installed RAM to force full grouping, so zPulsar cannot *assume* splitting — it must detect multi-service PIDs at runtime. Sources: [Winaero](https://winaero.com/set-split-threshold-svchost-windows-10/), [TenForums](https://www.tenforums.com/tutorials/94628-change-split-threshold-svchost-exe-windows-10-a.html). Microsoft's page documents only the per-service `SvcHostSplitDisable` value.

Instance-count reality check from the Microsoft doc: grouped mode runs ~17–21 svchost instances, split mode ~67–74 — i.e., on split machines the overwhelming majority of svchost PIDs are single-service.

## 2. Per-flow owner resolution via the TCP table (documented, the primary path)

The chain, all on Microsoft Learn:

- [`GetExtendedTcpTable`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) with `TCP_TABLE_OWNER_MODULE_ALL` (or `_CONNECTIONS`/`_LISTENER`) returns [`MIB_TCPROW_OWNER_MODULE`](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module) rows.
- Each row carries `dwOwningPid` ("The PID of the process that issued a context bind for this TCP connection"), `liCreateTimestamp` ("when the context bind operation that created this TCP link occurred"), and `OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE]` — documented only as "**an array of opaque data that contains ownership information**".
- [`GetOwnerModuleFromTcpEntry`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getownermodulefromtcpentry) takes that row and returns a `TCPIP_OWNER_MODULE_BASIC_INFO` with module name and path. The Remarks state the key fact for service attribution:

  > "In a few cases, the owner module name returned … can be a process name, such as 'svchost.exe', **a service name (such as 'RPC')**, or a component name, such as 'timer.dll'."

  So for a socket created by a service inside svchost, the documented API returns the *service's* name, not just "svchost.exe". This is **per-socket** resolution — no thread context is needed by the caller; ownership was recorded when the endpoint was created (see §3).
- **Elevation requirement (documented):** the same Remarks say that for connections of "protected" applications (those in the Windows system folder), a caller that is not elevated gets empty `pModuleName`/`pModulePath` strings; the app must run elevated (`requestedExecutionLevel: requireAdministrator`) to read them. zPulsar is admin-elevated by design, so this path is fully available.
- **UDP twin:** [`GetOwnerModuleFromUdpEntry`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getownermodulefromudpentry) / [`MIB_UDPROW_OWNER_MODULE`](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_module) provide the same mechanism for UDP endpoints.
- **In-box precedent:** [`netstat -b`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) is the shipping consumer of this machinery — Microsoft documents that it "displays the executable involved in creating each connection", including the component sequence for "well-known executables [that] host multiple independent components", and warns it "can be time-consuming and will fail unless you have sufficient permissions." The time-consuming warning is a real signal: resolve lazily and cache (see §5).

Caveats documented on the same pages: resolution is best-effort (the docs' phrase "resolution of TCP table entries to owner modules is a best practice" is best read as best-*effort*); the returned name may be a component name (e.g. "timer.dll") rather than a service name; `ERROR_NOT_FOUND` is returned when `dwOwningPid` is 0 or the endpoint's owner is gone.

## 3. Service tags — the mechanism underneath (undocumented; optional for zPulsar)

How per-socket service identity exists at all — from Alex Ionescu's [ScTagQuery writeup](https://www.alex-ionescu.com/sctagquery-mapping-service-hosting-threads-with-their-owner-service/):

- Since Vista, the SCM assigns each registered service a unique numeric **service tag**. The tag is stored in the **TEB `SubProcessTag` field** of the main service thread and "propagated to every thread created by the main service thread" (e.g. a service's RPC worker threads carry the service's tag).
- The TCP/IP stack records this tag when an endpoint is created (the "context bind" the MIB docs refer to) — which is why the connection table rows carry ownership info **per-socket**, and why netstat's `-b` "has been improved to use service tags" to show actual service names.
- The tag → name mapping is queried through the **undocumented** `I_QueryTagInformation` (a.k.a. `I_ScQueryTagInformation`) exported from `advapi32.dll` / `sechost.dll`. It is absent from Microsoft Learn and the SDK ships no prototype for it.

**Source-code verification** — System Informer (Process Hacker's successor) implements exactly this pipeline ([DeepWiki query on winsiderss/systeminformer](https://deepwiki.com/search/how-does-system-informer-attri_5d1419d4-4900-441a-9b6d-f2fb81eaa887)):

- `SystemInformer/netprv.c` (`PhGetNetworkConnections`, `PhpUpdateNetworkItemOwner`) reads `OwningModuleInfo` from `GetExtendedTcpTable`/`GetExtendedUdpTable` rows and treats it as the **service tag**.
- `phlib/svcsup.c` (`PhGetServiceNameFromTag`) dynamically loads `I_QueryTagInformation` — `sechost.dll` first (Win 8.1+), falling back to `advapi32.dll` — and calls it with `eTagInfoLevelNameFromTag` passing `{ProcessId, ServiceTag}` in a `TAG_INFO_NAME_FROM_TAG` structure (defined in `phnt/include/subprocesstag.h`).

**Undocumented-surface assessment (load-bearing map):**

| Surface | Status | zPulsar reliance |
| --- | --- | --- |
| `GetExtendedTcpTable` / `MIB_*_OWNER_MODULE` / `GetOwnerModuleFrom{Tcp,Udp}Entry` | Documented (Microsoft Learn) | **Load-bearing** — primary attribution path |
| `EnumServicesStatusEx(SC_ENUM_PROCESS_INFO)` | Documented | **Load-bearing** — PID → service-list map and fallback |
| Interpreting `OwningModuleInfo[0]` as a service tag | Undocumented (docs say "opaque"); verified in System Informer source | Optional fast path only |
| `I_QueryTagInformation` (`eTagInfoLevelNameFromTag`) | Undocumented; no SDK header; used by netstat, System Informer, ScTagQuery since Vista — stable in practice but unsupported | Optional fast path only |
| TEB `SubProcessTag` thread-level lookup | Undocumented | Not needed — the table rows already carry per-socket tags |

zPulsar can ship v1 with **zero** undocumented dependencies by calling `GetOwnerModuleFromTcpEntry` (with caching). If profiling shows it is too slow per-row, the System Informer approach (raw tag + `I_QueryTagInformation`, aggressively cached) is the escape hatch — flagged as undocumented in the spec.

## 4. Fallbacks: PID → service list, and per-service SIDs

- **SCM enumeration (documented):** [`EnumServicesStatusEx`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw) with `SC_ENUM_PROCESS_INFO` returns [`ENUM_SERVICE_STATUS_PROCESS`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-enum_service_status_processw) entries whose [`SERVICE_STATUS_PROCESS`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process) contains `dwProcessId`. Requires only `SC_MANAGER_ENUMERATE_SERVICE` (services the caller can't `SERVICE_QUERY_STATUS` are silently omitted — a non-issue elevated). Inverting this gives the PID → [services] map that powers both single-service PID attribution (tier 1) and the honest "N services" fallback (tier 3). Refresh on service start/stop or per poll tick; PIDs are reused, so key the cache by (PID, process start time).
- **Per-service SIDs are *not* a flow-attribution path.** [`SERVICE_SID_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info) documents `NT SERVICE\<name>` SIDs (convertible via `LookupAccountName`) that the SCM adds to the *process token*. In a shared svchost, the one process token contains the SIDs of *all* hosted services, and TCP table rows expose no token information — so service SIDs cannot disambiguate which service owns a flow from user mode. They are the mechanism WFP/Windows Firewall uses in-kernel to scope rules per service, not something a user-mode table poller can read per-flow. Useful to zPulsar only as display metadata.

## 5. Exactly when zPulsar can only say "svchost.exe (N services)"

The fallback label applies to a flow when **all** of the following hold: the owning PID hosts ≥ 2 services (per `EnumServicesStatusEx`), **and** per-socket resolution fails or is ambiguous. Concrete failure cases:

1. **No table row for the flow** — e.g. a connection observed only via ETW (`Microsoft-Windows-Kernel-Network` events carry PID only, no service tag) that closed before the next `GetExtendedTcpTable` poll. Short-lived flows in shared svchost processes land here.
2. **Tag is zero / owner not found** — the socket was created by a thread with no service tag (documented as `ERROR_NOT_FOUND`, or an owner name that is just "svchost.exe"). Happens for sockets created by non-service components loaded in the process.
3. **Wrong-context creation** — tags propagate from the *creating* thread (Ionescu, §3), so a socket created on a shared/borrowed thread pool or on behalf of another component can carry a misleading tag; the resolved name may also be a component ("timer.dll") rather than a service. Treat non-service module names in svchost as unresolved.
4. **Stale row / PID reuse** — service stopped between capture and resolution; guard with `liCreateTimestamp` and process start time.

When the fallback fires, the UI can honestly show `svchost.exe (N services)` with a tooltip/expansion listing the N service names from the PID map — never a guessed single service. On split machines (the norm), cases 1–4 still resolve at *process* granularity to a single service, so the fallback is genuinely rare: it requires a deliberately-grouped host (RPC pair, firewall pair, `SvcHostSplitDisable`, low-RAM or threshold-tweaked machines) *and* a resolution failure on that flow.

### Recommended pipeline (summary for the spec)

```
flow (5-tuple, PID)
  ├─ PID hosts 1 service (EnumServicesStatusEx map) ──────────→ that service   [most flows on 1703+/>3.5GB]
  ├─ PID hosts N services:
  │    ├─ match flow to MIB_*_OWNER_MODULE row (5-tuple)
  │    │    └─ GetOwnerModuleFrom{Tcp,Udp}Entry → service name → that service  [documented, needs elevation]
  │    │         (optional fast path: tag + I_QueryTagInformation — UNDOCUMENTED)
  │    └─ no row / tag 0 / non-service name ──────────────────→ "svchost.exe (N services)" + list
  └─ non-svchost PID ─────────────────────────────────────────→ plain PID attribution
```

## Sources

- Microsoft Learn — Service host grouping in Windows 10: https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring
- Microsoft Learn — GetOwnerModuleFromTcpEntry: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getownermodulefromtcpentry
- Microsoft Learn — MIB_TCPROW_OWNER_MODULE: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module
- Microsoft Learn — GetExtendedTcpTable: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
- Microsoft Learn — GetOwnerModuleFromUdpEntry: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getownermodulefromudpentry
- Microsoft Learn — EnumServicesStatusExW: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw
- Microsoft Learn — SERVICE_STATUS_PROCESS: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
- Microsoft Learn — SERVICE_SID_INFO: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info
- Microsoft Learn — netstat: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat
- Alex Ionescu — ScTagQuery: Mapping Service Hosting Threads With Their Owner Service: https://www.alex-ionescu.com/sctagquery-mapping-service-hosting-threads-with-their-owner-service/
- System Informer source (via DeepWiki): `SystemInformer/netprv.c`, `phlib/svcsup.c`, `phnt/include/subprocesstag.h` — https://deepwiki.com/search/how-does-system-informer-attri_5d1419d4-4900-441a-9b6d-f2fb81eaa887 and https://github.com/winsiderss/systeminformer
- SvcHostSplitThresholdInKB (community-documented registry value; not on Microsoft Learn): https://winaero.com/set-split-threshold-svchost-windows-10/ ; https://www.tenforums.com/tutorials/94628-change-split-threshold-svchost-exe-windows-10-a.html
