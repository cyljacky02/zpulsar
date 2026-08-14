//! Lifecycle of the `zPulsarNet` ETW real-time session (issues #19, #21).
//!
//! Session configuration follows the v1 spec (issue #18, "Capture: TCP/UDP
//! byte accounting") and docs/research/etw-tcp-udp-pipeline.md: QPC clock,
//! real-time mode, 16 KB buffers, min/max buffers 2×/4× logical CPUs, 1 s
//! FlushTimer. Kernel-Network and Kernel-Process both enable into this one
//! session (docs/research/kernel-process-etw.md). A crash-orphaned session
//! is self-healing: on ERROR_ALREADY_EXISTS the orphan is stopped by name
//! and startup retried (ADR-0002).

const std = @import("std");
const win32 = @import("win32");

pub const session_name = "zPulsarNet";
pub const session_name_w = std.unicode.utf8ToUtf16LeStringLiteral(session_name);

/// ETW session names are limited to 1024 characters. The buffer reserves
/// space behind EVENT_TRACE_PROPERTIES for the logger name (written by
/// StartTraceW) and, on control operations, the log file name ETW writes back.
const max_name_chars = 1024;

pub const PropertiesBuffer = extern struct {
    props: win32.EVENT_TRACE_PROPERTIES,
    logger_name: [max_name_chars]u16,
    log_file_name: [max_name_chars]u16,
};

/// Fill `buf` with the spec session config for StartTraceW.
pub fn buildProperties(buf: *PropertiesBuffer, logical_cpus: u32) void {
    buf.* = std.mem.zeroes(PropertiesBuffer);
    buf.props.Wnode.BufferSize = @sizeOf(PropertiesBuffer);
    buf.props.Wnode.Flags = win32.WNODE_FLAG_TRACED_GUID;
    buf.props.Wnode.ClientContext = 1; // QPC clock
    buf.props.BufferSize = 16; // KB
    buf.props.MinimumBuffers = 2 * logical_cpus;
    buf.props.MaximumBuffers = 4 * logical_cpus;
    buf.props.LogFileMode = win32.EVENT_TRACE_REAL_TIME_MODE;
    buf.props.FlushTimer = 1; // seconds (documented minimum)
    buf.props.LogFileNameOffset = 0; // real-time only, no log file
    buf.props.LoggerNameOffset = @offsetOf(PropertiesBuffer, "logger_name");
}

/// Microsoft-Windows-Kernel-Network manifest provider
/// (docs/research/etw-tcp-udp-pipeline.md §1.1).
pub const kernel_network_guid = win32.Guid.initString("7dd42a49-5329-4832-8dfd-43d979153a88");
pub const kernel_network_keyword_ipv4: u64 = 0x10;
pub const kernel_network_keyword_ipv6: u64 = 0x20;

/// Microsoft-Windows-Kernel-Process manifest provider
/// (docs/research/kernel-process-etw.md §1.1): WINEVENT_KEYWORD_PROCESS
/// only — thread/image-load keywords are that provider's high-volume side
/// and stay off.
pub const kernel_process_guid = win32.Guid.initString("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
pub const kernel_process_keyword_process: u64 = 0x10;

pub const StartError = error{
    /// The controlling APIs require elevation; startup is fail-fast (ADR-0002).
    AccessDenied,
    /// The orphaned session could not be stopped, or a start attempt failed.
    StartFailed,
    /// The session started but the provider could not be enabled; the session
    /// has been stopped again.
    EnableFailed,
};

pub const Session = struct {
    handle: win32.CONTROLTRACE_HANDLE,
    /// True when startup found and stopped a crash-orphaned `zPulsarNet`
    /// session before starting its own.
    adopted_orphan: bool,

    /// Stop the session. Never skipped on any exit path — ETW sessions
    /// outlive their process (ADR-0002).
    pub fn stop(self: Session) void {
        var buf: PropertiesBuffer = undefined;
        buildControlProperties(&buf);
        _ = win32.ControlTraceW(self.handle, null, &buf.props, .STOP);
    }

    /// The latency tick: deliver the session's partially filled buffers now.
    /// Called every 100–150 ms so trickle traffic stays under the 200 ms
    /// Attribution Latency budget (research §3.3).
    pub fn flush(self: Session) void {
        var buf: PropertiesBuffer = undefined;
        buildControlProperties(&buf);
        _ = win32.ControlTraceW(self.handle, null, &buf.props, .FLUSH);
    }

    /// Ask Kernel-Process to log its state: one ProcessRundown (ID 15) event
    /// per live process. Rundown is not keyword-gated — only this control
    /// call triggers it (research §1.2). Issued after the consumer is live
    /// (cold start), and re-issued as part of loss recovery.
    pub fn captureState(self: Session) void {
        _ = win32.EnableTraceEx2(
            self.handle,
            &kernel_process_guid,
            win32.EVENT_CONTROL_CODE_CAPTURE_STATE,
            win32.TRACE_LEVEL_INFORMATION,
            kernel_process_keyword_process,
            0,
            0,
            null,
        );
    }

    /// Cumulative events the session lost, both channels: EventsLost (buffer
    /// exhaustion at write time) plus RealTimeBuffersLost (buffers undeliverable
    /// to the real-time consumer). Null when the query itself fails. Any
    /// growth triggers the unified loss recovery.
    pub fn queryEventsLost(self: Session) ?u64 {
        var buf: PropertiesBuffer = undefined;
        buildControlProperties(&buf);
        if (win32.ControlTraceW(self.handle, null, &buf.props, .QUERY) != .NO_ERROR)
            return null;
        return @as(u64, buf.props.EventsLost) + buf.props.RealTimeBuffersLost;
    }
};

/// Start the `zPulsarNet` session and enable Kernel-Network (IPv4|IPv6) and
/// Kernel-Process (keyword 0x10, level 4). On ERROR_ALREADY_EXISTS the
/// orphaned session is stopped by name and the start retried once.
pub fn start(logical_cpus: u32) StartError!Session {
    return startWith(Win32Ops, logical_cpus);
}

/// Stop any session named `zPulsarNet`, owned by this process or not.
/// Returns true if a session was stopped. Safe to call concurrently with or
/// after `Session.stop` — a second stop reports not-found and is ignored.
pub fn stopByName() bool {
    return stopByNameWith(Win32Ops) == .NO_ERROR;
}

/// The start flow with injectable trace-control ops (the test seam; ETW
/// session control cannot run unelevated or without side effects).
fn startWith(comptime Ops: type, logical_cpus: u32) StartError!Session {
    var buf: PropertiesBuffer = undefined;
    buildProperties(&buf, logical_cpus);

    var handle: win32.CONTROLTRACE_HANDLE = 0;
    var rc = Ops.startTrace(&handle, session_name_w, &buf.props);

    var adopted_orphan = false;
    if (rc == .ERROR_ALREADY_EXISTS) {
        // Crash orphan: stop it by name and retry (self-healing, ADR-0002).
        if (stopByNameWith(Ops) != .NO_ERROR)
            return error.StartFailed;
        adopted_orphan = true;
        buildProperties(&buf, logical_cpus); // ETW wrote into the buffer
        handle = 0;
        rc = Ops.startTrace(&handle, session_name_w, &buf.props);
    }
    switch (rc) {
        .NO_ERROR => {},
        .ERROR_ACCESS_DENIED => return error.AccessDenied,
        else => return error.StartFailed,
    }

    const enables = [_]struct { guid: *const win32.Guid, keywords: u64 }{
        .{
            .guid = &kernel_network_guid,
            .keywords = kernel_network_keyword_ipv4 | kernel_network_keyword_ipv6,
        },
        .{ .guid = &kernel_process_guid, .keywords = kernel_process_keyword_process },
    };
    for (enables) |e| {
        if (Ops.enableProvider(handle, e.guid, e.keywords) != .NO_ERROR) {
            _ = stopByNameWith(Ops);
            return error.EnableFailed;
        }
    }

    return .{ .handle = handle, .adopted_orphan = adopted_orphan };
}

fn stopByNameWith(comptime Ops: type) win32.WIN32_ERROR {
    var buf: PropertiesBuffer = undefined;
    buildControlProperties(&buf);
    return Ops.stopTraceByName(session_name_w, &buf.props);
}

/// Zeroed properties for ControlTraceW: ETW writes the session's properties
/// and names back, so the buffer must declare its size and name offsets.
fn buildControlProperties(buf: *PropertiesBuffer) void {
    buf.* = std.mem.zeroes(PropertiesBuffer);
    buf.props.Wnode.BufferSize = @sizeOf(PropertiesBuffer);
    buf.props.LoggerNameOffset = @offsetOf(PropertiesBuffer, "logger_name");
    buf.props.LogFileNameOffset = @offsetOf(PropertiesBuffer, "log_file_name");
}

/// Production ops: thin, untested-by-unit-tests pass-throughs to the facade.
const Win32Ops = struct {
    fn startTrace(
        handle: *win32.CONTROLTRACE_HANDLE,
        name: [*:0]const u16,
        props: *win32.EVENT_TRACE_PROPERTIES,
    ) win32.WIN32_ERROR {
        return win32.StartTraceW(handle, name, props);
    }

    fn stopTraceByName(
        name: [*:0]const u16,
        props: *win32.EVENT_TRACE_PROPERTIES,
    ) win32.WIN32_ERROR {
        return win32.ControlTraceW(0, name, props, .STOP);
    }

    fn enableProvider(
        handle: win32.CONTROLTRACE_HANDLE,
        provider: *const win32.Guid,
        any_keywords: u64,
    ) win32.WIN32_ERROR {
        return win32.EnableTraceEx2(
            handle,
            provider,
            win32.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            win32.TRACE_LEVEL_INFORMATION,
            any_keywords,
            0,
            0,
            null,
        );
    }
};

const TestOps = struct {
    const Call = enum { start, stop_by_name, enable_network, enable_process };

    var calls_buf: [8]Call = undefined;
    var calls_len: usize = 0;
    var start_rcs: []const win32.WIN32_ERROR = &.{};
    var stop_rc: win32.WIN32_ERROR = .NO_ERROR;
    var enable_network_rc: win32.WIN32_ERROR = .NO_ERROR;
    var enable_process_rc: win32.WIN32_ERROR = .NO_ERROR;
    var starts_seen: usize = 0;
    var network_keywords: u64 = 0;
    var process_keywords: u64 = 0;

    fn record(call: Call) void {
        calls_buf[calls_len] = call;
        calls_len += 1;
    }

    fn callsSeen() []const Call {
        return calls_buf[0..calls_len];
    }

    fn reset(start_results: []const win32.WIN32_ERROR) void {
        calls_len = 0;
        start_rcs = start_results;
        stop_rc = .NO_ERROR;
        enable_network_rc = .NO_ERROR;
        enable_process_rc = .NO_ERROR;
        starts_seen = 0;
        network_keywords = 0;
        process_keywords = 0;
    }

    fn startTrace(
        handle: *win32.CONTROLTRACE_HANDLE,
        name: [*:0]const u16,
        props: *win32.EVENT_TRACE_PROPERTIES,
    ) win32.WIN32_ERROR {
        _ = props;
        std.debug.assert(std.mem.eql(u16, std.mem.span(name), session_name_w));
        record(.start);
        const rc = start_rcs[starts_seen];
        starts_seen += 1;
        if (rc == .NO_ERROR) handle.* = 42;
        return rc;
    }

    fn stopTraceByName(
        name: [*:0]const u16,
        props: *win32.EVENT_TRACE_PROPERTIES,
    ) win32.WIN32_ERROR {
        _ = props;
        std.debug.assert(std.mem.eql(u16, std.mem.span(name), session_name_w));
        record(.stop_by_name);
        return stop_rc;
    }

    fn enableProvider(
        handle: win32.CONTROLTRACE_HANDLE,
        provider: *const win32.Guid,
        any_keywords: u64,
    ) win32.WIN32_ERROR {
        std.debug.assert(handle == 42);
        if (std.mem.eql(u8, &provider.Bytes, &kernel_network_guid.Bytes)) {
            record(.enable_network);
            network_keywords = any_keywords;
            return enable_network_rc;
        }
        std.debug.assert(std.mem.eql(u8, &provider.Bytes, &kernel_process_guid.Bytes));
        record(.enable_process);
        process_keywords = any_keywords;
        return enable_process_rc;
    }
};

test "clean start enables Kernel-Network (IPv4|IPv6) and Kernel-Process (0x10)" {
    TestOps.reset(&.{.NO_ERROR});
    const session = try startWith(TestOps, 4);
    try std.testing.expectEqual(@as(win32.CONTROLTRACE_HANDLE, 42), session.handle);
    try std.testing.expect(!session.adopted_orphan);
    try std.testing.expectEqualSlices(
        TestOps.Call,
        &.{ .start, .enable_network, .enable_process },
        TestOps.callsSeen(),
    );
    try std.testing.expectEqual(@as(u64, 0x10 | 0x20), TestOps.network_keywords);
    try std.testing.expectEqual(@as(u64, 0x10), TestOps.process_keywords);
}

test "already-exists: orphan stopped by name, then start retried" {
    TestOps.reset(&.{ .ERROR_ALREADY_EXISTS, .NO_ERROR });
    const session = try startWith(TestOps, 4);
    try std.testing.expect(session.adopted_orphan);
    try std.testing.expectEqualSlices(
        TestOps.Call,
        &.{ .start, .stop_by_name, .start, .enable_network, .enable_process },
        TestOps.callsSeen(),
    );
}

test "already-exists persisting after orphan stop is an error" {
    TestOps.reset(&.{ .ERROR_ALREADY_EXISTS, .ERROR_ALREADY_EXISTS });
    try std.testing.expectError(error.StartFailed, startWith(TestOps, 4));
}

test "access denied maps to its own error" {
    TestOps.reset(&.{.ERROR_ACCESS_DENIED});
    try std.testing.expectError(error.AccessDenied, startWith(TestOps, 4));
}

test "enable failure stops the just-started session" {
    TestOps.reset(&.{.NO_ERROR});
    TestOps.enable_network_rc = .ERROR_ACCESS_DENIED;
    try std.testing.expectError(error.EnableFailed, startWith(TestOps, 4));
    try std.testing.expectEqualSlices(
        TestOps.Call,
        &.{ .start, .enable_network, .stop_by_name },
        TestOps.callsSeen(),
    );
}

test "a failing second enable also stops the session — never a half-enabled tracer" {
    TestOps.reset(&.{.NO_ERROR});
    TestOps.enable_process_rc = .ERROR_ACCESS_DENIED;
    try std.testing.expectError(error.EnableFailed, startWith(TestOps, 4));
    try std.testing.expectEqualSlices(
        TestOps.Call,
        &.{ .start, .enable_network, .enable_process, .stop_by_name },
        TestOps.callsSeen(),
    );
}

test "session properties follow the spec config" {
    var buf: PropertiesBuffer = undefined;
    buildProperties(&buf, 8);

    // Ground truth: spec issue #18 session table.
    try std.testing.expectEqual(@as(u32, @sizeOf(PropertiesBuffer)), buf.props.Wnode.BufferSize);
    try std.testing.expectEqual(win32.WNODE_FLAG_TRACED_GUID, buf.props.Wnode.Flags);
    try std.testing.expectEqual(@as(u32, 1), buf.props.Wnode.ClientContext); // QPC
    try std.testing.expectEqual(@as(u32, 16), buf.props.BufferSize); // KB
    try std.testing.expectEqual(@as(u32, 16), buf.props.MinimumBuffers); // 2 x 8 CPUs
    try std.testing.expectEqual(@as(u32, 32), buf.props.MaximumBuffers); // 4 x 8 CPUs
    try std.testing.expectEqual(win32.EVENT_TRACE_REAL_TIME_MODE, buf.props.LogFileMode);
    try std.testing.expectEqual(@as(u32, 1), buf.props.FlushTimer); // seconds
    // Real-time only: no log file, logger name written after the fixed part.
    try std.testing.expectEqual(@as(u32, 0), buf.props.LogFileNameOffset);
    try std.testing.expectEqual(
        @as(u32, @offsetOf(PropertiesBuffer, "logger_name")),
        buf.props.LoggerNameOffset,
    );
}
