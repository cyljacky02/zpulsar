//! PROTOTYPE — shared app state for the variant switcher and per-variant UI state.
const std = @import("std");
const data = @import("data.zig");

pub const Variant = enum {
    a_ledger,
    b_inspector,
    c_pulse,

    pub fn title(v: Variant) []const u8 {
        return switch (v) {
            .a_ledger => "A — Ledger (dense table)",
            .b_inspector => "B — Inspector (master–detail)",
            .c_pulse => "C — Pulse (dashboard)",
        };
    }

    pub fn next(v: Variant) Variant {
        return switch (v) {
            .a_ledger => .b_inspector,
            .b_inspector => .c_pulse,
            .c_pulse => .a_ledger,
        };
    }

    pub fn prev(v: Variant) Variant {
        return switch (v) {
            .a_ledger => .c_pulse,
            .b_inspector => .a_ledger,
            .c_pulse => .b_inspector,
        };
    }
};

pub const SortField = enum { name, down, up, down_total, up_total };

pub var variant: Variant = .a_ledger;
pub var cycle: u32 = 0; // teardown→tray-idle→recreate cycles completed (starts at 1 on first open)
pub var sort_field: SortField = .down;
pub var sort_descending: bool = true;
pub var selected_pid: u32 = 3412; // variant B selection (steam.exe)

fn lessThan(_: void, a: data.ProcRow, b: data.ProcRow) bool {
    const asc = !sort_descending;
    switch (sort_field) {
        .name => {
            const ord = std.ascii.lessThanIgnoreCase(a.name, b.name);
            return if (asc) ord else !ord;
        },
        .down => return if (asc) a.down_bps < b.down_bps else a.down_bps > b.down_bps,
        .up => return if (asc) a.up_bps < b.up_bps else a.up_bps > b.up_bps,
        .down_total => return if (asc) a.down_total < b.down_total else a.down_total > b.down_total,
        .up_total => return if (asc) a.up_total < b.up_total else a.up_total > b.up_total,
    }
}

/// Re-sorted every frame so the ordering is live (a UX question for the user).
pub fn sortProcs() void {
    std.mem.sort(data.ProcRow, data.procs, {}, lessThan);
}

pub fn findSelected() *data.ProcRow {
    for (data.procs) |*p| {
        if (p.pid == selected_pid) return p;
    }
    return &data.procs[0];
}
