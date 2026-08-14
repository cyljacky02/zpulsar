//! zPulsar's win32 facade — the only module in the repo that imports the
//! zigwin32 binding (ADR-0002; docs/research/zig-win32-interop.md). The rest
//! of the codebase imports this module as `win32`. Upstream reorganizations
//! and generator bugs are absorbed here: every struct we pass across the ABI
//! is guarded by comptime layout asserts against Windows SDK 10.0.26100.0
//! ground truth (x64), so a zigwin32 upgrade that shifts a layout is a
//! compile error, never silent corruption.

const std = @import("std");
const zigwin32 = @import("zigwin32");

const etw = zigwin32.system.diagnostics.etw;
const ip_helper = zigwin32.network_management.ip_helper;
const win_sock = zigwin32.networking.win_sock;
const foundation = zigwin32.foundation;

// ---------------------------------------------------------------------------
// Foundation
// ---------------------------------------------------------------------------

pub const Guid = zigwin32.zig.Guid;
/// Upstream's `foundation.BOOL` (= i32) is not marked pub at the pinned
/// commit; declare the ABI-identical type here.
pub const BOOL = i32;
pub const TRUE = foundation.TRUE;
pub const FALSE = foundation.FALSE;
pub const WIN32_ERROR = foundation.WIN32_ERROR;

/// Error codes for APIs that return plain `u32` (iphlpapi) rather than the
/// typed `WIN32_ERROR`.
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

// ---------------------------------------------------------------------------
// ETW session control (advapi32)
// ---------------------------------------------------------------------------

pub const StartTraceW = zigwin32.advapi32.StartTraceW;
pub const ControlTraceW = zigwin32.advapi32.ControlTraceW;
pub const EnableTraceEx2 = zigwin32.advapi32.EnableTraceEx2;

pub const CONTROLTRACE_HANDLE = etw.CONTROLTRACE_HANDLE;
pub const EVENT_TRACE_PROPERTIES = etw.EVENT_TRACE_PROPERTIES;
pub const WNODE_HEADER = etw.WNODE_HEADER;
pub const EVENT_TRACE_CONTROL = etw.EVENT_TRACE_CONTROL;

pub const EVENT_TRACE_REAL_TIME_MODE = etw.EVENT_TRACE_REAL_TIME_MODE;
pub const WNODE_FLAG_TRACED_GUID = etw.WNODE_FLAG_TRACED_GUID;
/// `EnableTraceEx2` takes Level as `u8`; the upstream constant is `u32`.
pub const TRACE_LEVEL_INFORMATION: u8 = @intCast(etw.TRACE_LEVEL_INFORMATION);
/// `EnableTraceEx2` takes ControlCode as `u32`; the upstream constant is an enum.
pub const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 =
    @intFromEnum(etw.EVENT_CONTROL_CODE_ENABLE_PROVIDER);

// ---------------------------------------------------------------------------
// ETW consumption (the consumer thread lands in a later ticket; the types are
// declared here now because the buffer-callback signature fix is facade
// policy, not call-site policy)
// ---------------------------------------------------------------------------

pub const EVENT_TRACE_LOGFILEW = etw.EVENT_TRACE_LOGFILEW;
pub const PROCESSTRACE_HANDLE = etw.PROCESSTRACE_HANDLE;

/// The true SDK signature of the ETW buffer callback:
/// `ULONG (WINAPI *PEVENT_TRACE_BUFFER_CALLBACKW)(PEVENT_TRACE_LOGFILEW)`
/// (evntrace.h:1521). zigwin32 stubs `PEVENT_TRACE_BUFFER_CALLBACKW` as
/// `*const fn () callconv(.winapi) void` due to a generator dependency loop
/// (etw.zig:1608 at the pinned commit); ETW itself calls through the real ABI,
/// so callbacks must be written against this type and assigned via
/// `setEtwBufferCallback`.
pub const EtwBufferCallbackW = *const fn (logfile: ?*EVENT_TRACE_LOGFILEW) callconv(.winapi) u32;

pub fn setEtwBufferCallback(logfile: *EVENT_TRACE_LOGFILEW, callback: EtwBufferCallbackW) void {
    logfile.BufferCallback = @ptrCast(callback);
}

// ---------------------------------------------------------------------------
// IP Helper (iphlpapi) — TCP/UDP owner tables
// ---------------------------------------------------------------------------

pub const GetExtendedTcpTable = zigwin32.iphlpapi.GetExtendedTcpTable;
pub const GetExtendedUdpTable = zigwin32.iphlpapi.GetExtendedUdpTable;

pub const TCP_TABLE_CLASS = ip_helper.TCP_TABLE_CLASS;
pub const UDP_TABLE_CLASS = ip_helper.UDP_TABLE_CLASS;

pub const MIB_TCPROW_OWNER_PID = ip_helper.MIB_TCPROW_OWNER_PID;
pub const MIB_TCPTABLE_OWNER_PID = ip_helper.MIB_TCPTABLE_OWNER_PID;
pub const MIB_TCP6ROW_OWNER_PID = ip_helper.MIB_TCP6ROW_OWNER_PID;
pub const MIB_TCP6TABLE_OWNER_PID = ip_helper.MIB_TCP6TABLE_OWNER_PID;
pub const MIB_UDPROW_OWNER_PID = ip_helper.MIB_UDPROW_OWNER_PID;
pub const MIB_UDPTABLE_OWNER_PID = ip_helper.MIB_UDPTABLE_OWNER_PID;
pub const MIB_UDP6ROW_OWNER_PID = ip_helper.MIB_UDP6ROW_OWNER_PID;
pub const MIB_UDP6TABLE_OWNER_PID = ip_helper.MIB_UDP6TABLE_OWNER_PID;

/// `GetExtendedTcpTable`/`GetExtendedUdpTable` take the address family as
/// `u32`; zigwin32's `AF_*` are `ADDRESS_FAMILY` enum(u16) values.
pub const AF_INET: u32 = @intFromEnum(win_sock.AF_INET);
pub const AF_INET6: u32 = @intFromEnum(win_sock.AF_INET6);

// ---------------------------------------------------------------------------
// Console control (kernel32)
// ---------------------------------------------------------------------------

pub const SetConsoleCtrlHandler = zigwin32.kernel32.SetConsoleCtrlHandler;
pub const Sleep = zigwin32.kernel32.Sleep;

// ---------------------------------------------------------------------------
// Comptime ABI asserts — Windows SDK 10.0.26100.0, x64.
// Ground truth: wmistr.h (WNODE_HEADER), evntrace.h (EVENT_TRACE_PROPERTIES
// :1238, EVENT_TRACE_LOGFILEW :1600ff, EVENT_TRACE, TRACE_LOGFILE_HEADER),
// tcpmib.h/udpmib.h (MIB_* owner-PID rows). Sizes/offsets verified in
// docs/research/zig-win32-interop.md (F5/F8) or derived field-by-field from
// the header layouts (all-DWORD structs have no padding on x64).
// ---------------------------------------------------------------------------

comptime {
    const assert = std.debug.assert;

    assert(@sizeOf(Guid) == 16);

    // wmistr.h WNODE_HEADER
    assert(@sizeOf(WNODE_HEADER) == 48);
    assert(@offsetOf(WNODE_HEADER, "BufferSize") == 0);
    assert(@offsetOf(WNODE_HEADER, "Guid") == 24);
    assert(@offsetOf(WNODE_HEADER, "ClientContext") == 40);
    assert(@offsetOf(WNODE_HEADER, "Flags") == 44);

    // evntrace.h EVENT_TRACE_PROPERTIES
    assert(@sizeOf(EVENT_TRACE_PROPERTIES) == 120);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "Wnode") == 0);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "BufferSize") == 48);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "MinimumBuffers") == 52);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "MaximumBuffers") == 56);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "LogFileMode") == 64);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "FlushTimer") == 68);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "EventsLost") == 88);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "LoggerThreadId") == 104);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "LogFileNameOffset") == 112);
    assert(@offsetOf(EVENT_TRACE_PROPERTIES, "LoggerNameOffset") == 116);

    // evntrace.h EVENT_TRACE (embedded in EVENT_TRACE_LOGFILEW):
    // EVENT_TRACE_HEADER(48) + InstanceId(4) + ParentInstanceId(4)
    // + ParentGuid(16) + MofData(8) + MofLength(4) + BufferContext(4)
    assert(@sizeOf(etw.EVENT_TRACE) == 88);
    // evntrace.h TRACE_LOGFILE_HEADER: ...TimeZone(172)@72, pad to 8,
    // BootTime@248, PerfFreq@256, StartTime@264, ReservedFlags@272,
    // BuffersLost@276
    assert(@sizeOf(etw.TRACE_LOGFILE_HEADER) == 280);

    // evntrace.h EVENT_TRACE_LOGFILEW
    assert(@sizeOf(EVENT_TRACE_LOGFILEW) == 448);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "LoggerName") == 8);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "BuffersRead") == 24);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "Anonymous1") == 28); // LogFileMode/ProcessTraceMode
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "CurrentEvent") == 32);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "LogfileHeader") == 120);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "BufferCallback") == 400);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "EventsLost") == 416);
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "Anonymous2") == 424); // EventCallback/EventRecordCallback
    assert(@offsetOf(EVENT_TRACE_LOGFILEW, "Context") == 440);

    // tcpmib.h MIB_TCPROW_OWNER_PID / MIB_TCPTABLE_OWNER_PID
    assert(@sizeOf(MIB_TCPROW_OWNER_PID) == 24);
    assert(@offsetOf(MIB_TCPROW_OWNER_PID, "dwOwningPid") == 20);
    assert(@offsetOf(MIB_TCPTABLE_OWNER_PID, "dwNumEntries") == 0);
    assert(@offsetOf(MIB_TCPTABLE_OWNER_PID, "table") == 4);

    // tcpmib.h MIB_TCP6ROW_OWNER_PID / MIB_TCP6TABLE_OWNER_PID
    assert(@sizeOf(MIB_TCP6ROW_OWNER_PID) == 56);
    assert(@offsetOf(MIB_TCP6ROW_OWNER_PID, "ucRemoteAddr") == 24);
    assert(@offsetOf(MIB_TCP6ROW_OWNER_PID, "dwState") == 48);
    assert(@offsetOf(MIB_TCP6ROW_OWNER_PID, "dwOwningPid") == 52);
    assert(@offsetOf(MIB_TCP6TABLE_OWNER_PID, "dwNumEntries") == 0);
    assert(@offsetOf(MIB_TCP6TABLE_OWNER_PID, "table") == 4);

    // udpmib.h MIB_UDPROW_OWNER_PID / MIB_UDPTABLE_OWNER_PID
    assert(@sizeOf(MIB_UDPROW_OWNER_PID) == 12);
    assert(@offsetOf(MIB_UDPROW_OWNER_PID, "dwOwningPid") == 8);
    assert(@offsetOf(MIB_UDPTABLE_OWNER_PID, "dwNumEntries") == 0);
    assert(@offsetOf(MIB_UDPTABLE_OWNER_PID, "table") == 4);

    // udpmib.h MIB_UDP6ROW_OWNER_PID / MIB_UDP6TABLE_OWNER_PID
    assert(@sizeOf(MIB_UDP6ROW_OWNER_PID) == 28);
    assert(@offsetOf(MIB_UDP6ROW_OWNER_PID, "dwOwningPid") == 24);
    assert(@offsetOf(MIB_UDP6TABLE_OWNER_PID, "dwNumEntries") == 0);
    assert(@offsetOf(MIB_UDP6TABLE_OWNER_PID, "table") == 4);

    // ws2def.h address families
    assert(AF_INET == 2);
    assert(AF_INET6 == 23);
}

test {
    std.testing.refAllDecls(@This());
}
