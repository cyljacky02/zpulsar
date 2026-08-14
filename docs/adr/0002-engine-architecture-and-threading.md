# Engine as a pull-based library with single-owner threading

zPulsar splits into an `engine` module (capture → attribution → aggregation; may import only std and the repo's win32 facade) and an `app` module (tray + dvui window), with the boundary enforced by the build.zig module graph — a UI dependency inside `engine` is a compile error, and a debug-only headless build target proves the boundary stays real. The engine exposes state exclusively by **pull**: refcounted, arena-backed immutable Snapshots published by pointer swap, plus a single wake event — no callbacks into the UI — so a different front-end can bolt on without touching engine internals.

All engine state is owned by **one Engine thread**. The ETW consumer thread (blocked in `ProcessTrace` on a single real-time session, `zPulsarNet`, enabling Kernel-Network + TCPIP-ICMP + DNS-Client + Kernel-Process) only parses events into fixed-size records and pushes them onto a bounded SPSC ring; blocking lookups run on two resolver lanes (metadata: image names / owner module / service map / table snapshots; reverse DNS: `GetNameInfoW`) that return results through completion queues. There are no locks on the hot path, and ticket #8's data model gets a single-threaded world to live in.

## Considered options

- **Consumer-owns-state + mutex-guarded tick thread** — rejected: a lock on the per-event path, and a multi-threaded data model for everything downstream.
- **Two ETW sessions (hot/cold split)** — rejected: DNS (~4 ev/s) and ICMP trickle don't perturb the hot path's buffers, and one session halves the orphan-cleanup and shutdown surface. Documented fallback if `EventsLost` ever says otherwise.
- **Push callbacks / delta queue to the UI** — rejected: re-imports the UI's threading into the engine; an immediate-mode UI re-reads everything per frame anyway.
- **One resolver lane** — rejected: a hung reverse lookup (sync-only `GetNameInfoW`) would starve owner-module resolution and break Attribution Latency for shared-svchost flows.

## Consequences

- Ring overflow and ETW `EventsLost` share one recovery: re-baseline from a fresh TCP/UDP table snapshot and flag it in the Snapshot — totals are honest or marked, never silently low.
- The < 200 ms Attribution Latency budget applies window-open; Tray-idle suspends the manual ETW flush tick and rides the 1 s FlushTimer at ~1 s cadence.
- The main window, D3D11 device, and dvui context are destroyed **wholesale** on close; the tray icon lives on a permanent hidden (non-message-only, so `TaskbarCreated` still arrives) window. The tray-idle RAM budget depends on this teardown, so the window↔tray-idle recreate cycle is a mandatory prototype target.
- Startup is manifest-elevated only and fail-fast (no degraded mode in v1); the fixed session name plus a single-instance mutex makes crash orphans self-healing (next launch adopts and stops the session by name); shutdown may abandon a stuck resolver thread after a 2 s join timeout, but `ControlTrace(STOP)` is never skipped — ETW sessions outlive their process.
