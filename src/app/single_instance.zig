//! One zPulsar per machine, and a second launch that hands off instead of
//! fighting.
//!
//! The thing being protected is not the window — it is the machine's single
//! `zPulsarNet` ETW session. Startup adopts an existing session by name and
//! stops it, which is exactly right for a crash orphan and exactly wrong for a
//! living instance: two zPulsars would take turns killing each other's capture.
//! So the claim is machine-wide, and a second launch's whole job is to point at
//! the one already running and leave.

const std = @import("std");
const dvui = @import("dvui");
const tray = @import("tray.zig");

const Backend = dvui.backend;
const win32 = Backend.win32;

/// `Global\` — across Windows sessions, matching the scope of the ETW session
/// it stands for. A per-session claim would let a second logged-in user start
/// a second zPulsar that stops the first one's capture.
const mutex_name = win32.L("Global\\zPulsarSingleInstance");

/// The running instance's tray window can lag its mutex by a few milliseconds,
/// so a second launch that starts during that window polls rather than
/// concluding nobody is home.
const handoff_timeout_ms: u32 = 2_000;
const handoff_poll_ms: u32 = 50;

/// Held for the process lifetime and never released by hand: Windows drops it
/// when the process ends, however it ends, so a crash leaves nothing to clean
/// up and the next launch simply wins the claim.
var handle: ?win32.HANDLE = null;

pub const Claim = enum { first, already_running };

pub fn claim() Claim {
    handle = win32.CreateMutexW(null, 0, mutex_name);
    // If the claim itself cannot be made — rights, a name collision — run
    // anyway. Refusing to start over a lock we could not take would be worse
    // than the duplicate it is meant to prevent.
    if (handle == null) return .first;
    return if (win32.GetLastError() == win32.ERROR_ALREADY_EXISTS)
        .already_running
    else
        .first;
}

/// Tell the instance that already holds the claim to show its window, and
/// hand it the right to come to the foreground — Windows will not let a
/// process that has focus be interrupted by one that does not, unless the one
/// with focus says so. False means nothing answered: the running instance is
/// out of reach (another Windows session), and the caller has to say so out
/// loud rather than exiting into silence.
pub fn handOff() bool {
    var waited: u32 = 0;
    while (true) {
        if (win32.FindWindowW(tray.class_name, null)) |hwnd| {
            var pid: u32 = 0;
            _ = win32.GetWindowThreadProcessId(hwnd, &pid);
            if (pid != 0) _ = win32.AllowSetForegroundWindow(pid);
            return win32.PostMessageW(hwnd, tray.showMessage(), 0, 0) != 0;
        }
        if (waited >= handoff_timeout_ms) return false;
        win32.Sleep(handoff_poll_ms);
        waited += handoff_poll_ms;
    }
}
