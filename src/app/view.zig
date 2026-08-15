//! The window's presentation model: everything the UI decides that is not
//! drawing. Formatting rules, Snapshot aggregates, and the Ledger's frozen row
//! order all live here, and none of them import dvui or win32 — so the rules
//! the spec fixes are testable without a device, a window, or elevation.

const std = @import("std");

pub const format = @import("view/format.zig");
pub const order = @import("view/order.zig");
pub const totals = @import("view/totals.zig");

test {
    std.testing.refAllDecls(@This());
}
