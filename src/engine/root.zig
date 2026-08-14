//! zPulsar Engine — the UI-independent core (ADR-0002). This module imports
//! only the standard library and the repo's win32 facade; the build graph in
//! build.zig enforces that (any other @import is a compile error).

const std = @import("std");

pub const etw_session = @import("etw_session.zig");
pub const tables = @import("tables.zig");

test {
    std.testing.refAllDecls(@This());
}
