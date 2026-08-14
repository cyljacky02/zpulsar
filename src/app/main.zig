//! zPulsar app (tray + main window). Stub until the UI tickets land — it
//! exists so `zig build` produces the app exe and the app→engine edge of the
//! module graph is compiled from day one.

const std = @import("std");
const engine = @import("engine");

pub fn main() void {
    std.debug.print(
        "zPulsar app stub — UI lands in later tickets. Session name: {s}. " ++
            "Use zpulsar-headless (debug build) for the engine rig.\n",
        .{engine.etw_session.session_name},
    );
}
