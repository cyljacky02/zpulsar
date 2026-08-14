# PROTOTYPE — zPulsar main-window UI (ticket #10)

**Throwaway code on fake data.** Answers one question: what does zPulsar's main window look
like? Delete this whole directory once the v1 layout is locked; only the decision survives.

## Run

```
zig build run
```

(Zig 0.16.0, dvui pinned to `7c597c55`, dx11 backend in attach mode.)

## What to react to

Three structurally different layouts on the same live fake data. Switch with the floating
bottom bar (◂ ▸ buttons) or ←/→ arrow keys (note: arrows are captured by a table once you've
clicked into it — a real conflict to decide on):

- **A — Ledger**: one dense sortable table (NetLimiter-style). Click a process row to expand
  its flows inline. Sortable columns re-sort *live* every frame.
- **B — Inspector**: master–detail. Activity-sorted process list left; click one to inspect
  its live speeds, in-session totals, and flow table on the right.
- **C — Pulse**: dashboard. Global down/up meters up top, processes as ranked activity bars
  (hot first), idle processes tucked below. Click a row to expand flows inline.

Shared chrome under test in every variant:

- **Tray icon** with a live-speed tooltip (updates every 500 ms — hover it).
- **Close-to-tray with wholesale teardown** (per the #9 architecture): closing the window
  destroys the window + D3D11 device + dvui context entirely; monitoring (fake) continues;
  clicking the tray icon recreates everything. The switcher bar shows `cycle N` — it grows
  each recreate, proving the full teardown→tray-idle→recreate cycle works.
- Tray right-click menu: Show / Exit (Exit is the only way to quit).

Domain details baked in (from the research decisions):

- svchost rows carry **Service Attribution** ("Windows Update (wuauserv)" etc.).
- **Hostname Attribution**: observed names normal, reverse-lookup fallbacks dimmed
  (`fritz.box`, `nas.lan`), no-hostname flows show the bare endpoint (`100.89.14.7:22`).
- **ICMP shows message counts, not bytes** (no per-process ICMP byte counts exist user-mode):
  PING.EXE reads "1.0 msg/s / 43 msgs".
- Process "icons" are colored initials — real exe icons are a build-phase question.

## Layout of this prototype

- `src/main.zig` — win32 shell: tray window (permanent), main-window lifecycle, D3D11 device
- `src/data.zig` — fake processes/flows with live jitter patterns
- `src/state.zig` — variant switcher + sort state
- `src/va_ledger.zig`, `src/vb_inspector.zig`, `src/vc_pulse.zig` — the three variants
- `src/switcher.zig` — floating variant bar (not part of the design under evaluation)
- `src/common.zig` — formatting + shared micro-widgets

## Findings worth keeping regardless of variant choice

- The teardown→tray-idle→recreate cycle (flagged by the GUI research as unexercised) works
  end-to-end with dvui dx11 attach mode. See `cycle N` in the switcher bar.
- dvui pre-1.0 bug note: synthetic `WM_KEYDOWN`/`WM_KEYUP` with a zero repeat-count in
  lparam panics the dx11 backend (`for (1..info.repeat_count)` integer overflow,
  dx11.zig:1416). Real keyboards always send repeat ≥ 1; only synthetic senders hit it.
- Arrow keys conflict with GridWidget keyboard navigation once a grid has focus.
- Live re-sorting every frame makes rows jump while speeds jitter — decide live reorder
  vs. periodic/frozen ordering.
