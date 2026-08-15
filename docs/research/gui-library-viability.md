# GUI library viability: pure-Zig vs Dear ImGui (research ticket #6)

Researched 2026-08-14 against library repos (cloned at the commits below) and trial builds with the
locally installed Zig 0.16.0 toolchain (`zig version` → `0.16.0`) on Windows 11.

- dvui: `david-vanderson/dvui` @ `7c597c5` (2026-08-12)
- zgui: `zig-gamedev/zgui` @ `0b468cc` (2026-08-07)

## Verdict

**Pure Zig is viable today. Choose dvui with its Direct3D 11 backend.** Dear ImGui via zgui is a
proven fallback (it builds clean on Zig 0.16.0), but it offers no advantage that outweighs adding a
C++ vendored dependency, and its only Windows-native backend is D3D12, not D3D11.

| Criterion | dvui evidence | Status |
|---|---|---|
| Zig 0.16.0 compatibility | `build.zig.zon` master: `minimum_zig_version = "0.16.0"`; README line 5: "Tested with Zig v0.16.0 (for Zig v0.15.2, use DVUI branch zig15 or tag v0.4.0)". Trial build of the dx11 example with local Zig 0.16.0 succeeded and the window opened. | Pass (verified by build) |
| Windows / D3D11 backend | `src/backends/dx11.zig` — full D3D11 backend over `zigwin32` (device, swapchain, per-window state). | Pass |
| Sortable multi-column table | `GridWidget` (`src/widgets/GridWidget.zig`): `CellWidget.headerSortable()` (line 615) returns the new `SortDirection`; sort state persisted per grid (`sort_dir`/`sort_col`, lines 122–123). Used per-column in `src/Examples/grid.zig` lines 404–459. | Pass |
| Per-cell coloring | Every cell is a widget taking full `dvui.Options`; examples set `opts.color_fill` + `.background` per cell (`src/Examples/grid.zig` lines 138–149, 484–490). Verified working in my trial app. | Pass |
| Expandable rows | No built-in tree-table, but rows have independent heights (`row_heights: []RowHeight`, GridWidget.zig lines 107–109; binary-searched offsets lines 71–75) and dvui ships an `expander` widget — an expanded detail row is a composition, not a fight. | Pass with assembly |
| ~60 fps at ~500 rows | Grid virtualizes: `grid.rowsVisible()` returns the visible row span and only those rows are emitted (Examples/grid.zig lines 134, 287); the styling example scales its slider to 100,000 rows. Only ~30 visible rows exist per frame regardless of dataset size, GPU-rendered via D3D11. 500 rows is far below the widget's design envelope. | Pass (by construction; not frame-timed) |
| Coexists with Win32 tray + message loop | `dx11.zig` exposes `attach(hwnd, ...)` (line 1181) to bolt dvui onto a caller-owned HWND and a public `wndProc` (line 1221) you call from your own window procedure. `examples/dx11-ontop.zig` demonstrates exactly this: app creates the window, wndproc, D3D11 device/swapchain; dvui attaches. Tray messages (`Shell_NotifyIconW` is in zigwin32, which dvui's dx11 backend already depends on) are handled in the same wndproc before forwarding. | Pass (designed-for use case) |
| GPU teardown / recreate in-process | Window-class registration is separated from window life: `RegisterClass` once per process ("Typically there's no reason to unregister", dx11.zig lines 236–241); `initWindow`/`deinit` are per-window, and `WindowState.deinit` releases the D3D objects. Destroy the dvui window + device while the monitor thread keeps running; recreate on tray click. | Pass (by design; recreate cycle not exercised in trial) |
| Exe < 5 MB | Minimal representative app (dvui.App + 3-column sortable grid, 500 rows, per-cell coloring, `-Dfreetype=false -Dtree-sitter=false -Dtiny-file-dialogs=false`, ReleaseSmall): **1.92 MB** (2,014,720 bytes). Caution: the kitchen-sink demo is 8.5 MB — size discipline means not embedding extra fonts/assets. | Pass (1.92 MB measured) |
| Window-open RAM < 80 MB | Minimal app running with grid visible: **51.5 MB working set / 59.0 MB private** (4 s after launch). Full demo app: 48.0 MB WS / 60.9 MB private. | Pass (measured) |
| Tray-idle RAM < 30 MB | Not a GUI-library property — per the charting decision the GPU context and window are torn down while monitoring continues, so tray-idle RAM is owned by the monitor core, not dvui. Teardown capability: see above. | N/A to library choice |

Maintenance health: 1,618 stars / 138 forks / 93 open issues, pushed 2026-08-12 (GitHub API);
contributor spread beyond the founder (david-vanderson 2,248 commits, RedPhoenixQ 590, phatchman
287, VisenDev 147, foxnne 88); versioned releases v0.2.0 (2025-01), v0.3.0 (2025-08), v0.4.0
(2026-04) plus a maintained `zig15` compatibility branch; MIT licensed (LICENSE file; the GitHub
API's `NOASSERTION` is just a non-standard file header). This is a healthy, actively developed
project that tracks Zig releases deliberately.

## Supporting findings

### dvui (chosen)

- **Trial builds (definitive for 0.16 compat).** `zig build -Dbackend=dx11 dx11-standalone
  -Doptimize=ReleaseSmall` at `7c597c5` compiled and launched (dvui logged
  `window logical Size.Natural{ 1424 720 }...`). A from-scratch consumer project
  (`b.dependency("dvui", .{ .backend = .dx11, ... })`, import `dvui_dx11` module per README
  "Getting Started") built first try apart from one intentional API probe. The consumer wiring is
  two lines of build.zig, matching README lines 221–229.
- **The grid API maps 1:1 to zPulsar's process table.** My trial `main.zig` implemented name/PID/
  bytes columns with `headerSortable` sort callbacks, virtualized rows via `rowsVisible()`, and
  red-tinted cells for heavy talkers — ~60 lines of frame code.
- **Immediate-mode with power-saving.** dvui is immediate-mode but supports render-on-demand:
  `win.beginWait(backend.hasEvent())` runs frames only when input/animation demands
  (`examples/dx11-ontop.zig` lines 35–58, README "for applications DVUI can manage waiting for
  input so you only render frames when needed"). Good fit for a monitor that idles.
- **Size levers.** Build options `-Dfreetype=false` (stb_truetype instead of FreeType),
  `-Dtree-sitter=false`, `-Dtiny-file-dialogs=false` (`build.zig` lines 160–165). The 8.5 MB demo
  exe is demo assets (icon set, embedded fonts, code-editor demo), not framework floor — the
  floor measured 1.92 MB.
- **Caveat: pre-1.0 API churn.** Version is `0.5.0-dev`; releases have breaking changes (README
  points 0.15.2 users at a branch/tag). Pinning a commit and upgrading deliberately is the play.
- **Caveat: dx11 backend requires u16 vertex indices** (`build.zig` line 862–864 errors otherwise)
  — irrelevant at our widget counts, just don't override the vertex-index option.

### Dear ImGui routes (fallback: viable, not needed)

- **zgui (zig-gamedev/zgui).** Commit `9c0b41a` "Upgrade to Zig 0.16.0" (2026-05-12);
  `build.zig.zon` `minimum_zig_version = "0.16.0"`. Trial `zig build -Dbackend=win32_dx12` with
  local Zig 0.16.0: **exit 0**. Table API fully exposed in `src/gui.zig`: `beginTable` (line 3476),
  `TableFlags.sortable` (3369), `tableGetSortSpecs` (3533), `tableSetBgColor` (3567) — i.e.
  `ImGuiTableFlags_Sortable` and per-cell background color are covered. Vendors Dear ImGui 1.92.1
  (`libs/imgui/imgui.h`). Win32 integration mirrors dvui's: `backend_win32_dx12.zig` `init(hwnd,
  ...)` on a caller-owned HWND + `defaultWndProcHandler` for the app's wndproc, `deinit()` for
  teardown.
- **But: no D3D11 backend.** `build.zig` backend enum offers `win32_dx12` and `glfw_dx12`; the
  vendored `libs/imgui/backends/` contains `imgui_impl_dx12.cpp` but **no `imgui_impl_dx11.cpp`**.
  Going D3D11 under zgui means vendoring that file from upstream ourselves; going D3D12 means more
  boilerplate on our side of the device setup. Either way it drags in a C++ toolchain and ~6 MB of
  static lib (Debug `imgui.lib` measured 6.2 MB; linked release exe would land roughly 2–3 MB, so
  the exe budget still holds).
- **cimgui / dear_bindings DIY.** Always available (zgui itself is a hand-rolled C++ shim,
  `zgui.cpp`); floooh's sokol-zig + dcimgui is another maintained C-backed route. Not evaluated in
  depth — there is no reason to hand-roll bindings when zgui already builds on 0.16.0.

### Other candidates (surveyed, rejected)

- **capy (capy-ui/capy):** retained-mode ("declarative UI library"), targets Zig **0.14.1**, README:
  "NOT ready for use in production as I'm still making breaking changes". Fails paradigm, version,
  and maturity. (README @ master, fetched 2026-08-14.)
- **Webview-based (zig-webui, Positron):** a browser/WebView renderer cannot meet the 30 MB
  tray-idle or 80 MB window budgets and isn't immediate-mode. Rejected on budget.
- **microui ports / raygui:** no sortable-table widget of any kind; would mean building the table
  from scratch. Rejected on capability.
- Community surveys (ziggit "How do you do UI in zig", awesome-zig, HN 45853674) name no other
  pure-Zig immediate-mode toolkit of substance — dvui is the category.

## Measurement log

| Build | Command | Result |
|---|---|---|
| dvui demo, dx11 | `zig build -Dbackend=dx11 dx11-standalone -Doptimize=ReleaseSmall` | Built + ran; exe 9,058,816 B; 48.0 MB WS / 60.9 MB private |
| dvui demo, no freetype | `... -Dfreetype=false` | exe 8,537,600 B (demo assets dominate, not FreeType) |
| Minimal grid app | consumer project, ReleaseSmall, freetype/tree-sitter/tfd off | **exe 2,014,720 B; 51.5 MB WS / 59.0 MB private**, sortable 500-row grid renders |
| zgui | `zig build -Dbackend=win32_dx12` | exit 0 on Zig 0.16.0 |

## Recommendation for the next milestone

Adopt dvui pinned to a known-good master commit (≥ `7c597c5`), dx11 backend in **attach mode**
(own HWND + wndproc, per `examples/dx11-ontop.zig`), build flags `-Dfreetype=false`
`-Dtree-sitter=false` `-Dtiny-file-dialogs=false`, ReleaseSmall for dist. First spike should
exercise the one thing not yet proven end-to-end: a full window+device teardown → tray-only →
recreate cycle in one process.

## Addendum — what the teardown cycle cost (issue #24, 2026-08-15)

The recommendation above held: dvui at the pinned `7c597c5` builds the real app shell, and the
teardown → Tray-idle → recreate cycle works in one process.

Method, so this is repeatable: launch `zig-out/bin/zpulsar.exe`, find its windows by class name
(`zPulsarMainWindow`, `zPulsarTrayWindow`) with `EnumWindows` — `FindWindow` from .NET/PowerShell
does not see them — then drive a cycle by posting `WM_CLOSE` to the main window and launching a
second instance to trigger the tray hand-off that restores it, sampling
`Process.WorkingSet64`/`HandleCount`/`Threads.Count` and the `Private Bytes` counter at each
Tray-idle and window-open point. `WM_ENDSESSION` (wparam 1) to the tray window exercises the
session-end exit; `WM_QUIT` posted to its thread exercises the tray-menu exit. Note that
`logman query -ets` intermittently fails with 0x800710E8, so retry before believing it when
checking whether `zPulsarNet` is up.

Measured on the ReleaseSmall build, six consecutive cycles, hardware D3D11:

| | window open | Tray-idle |
|---|---|---|
| Working set | ~58 MB | ~35 MB |
| Private bytes | ~135 MB | ~90 MB |
| Handles | 651 | 272 |
| Threads | 113 | 10 |

Flat across all six cycles — every recreate returns to the same numbers. Exe: **2,181,632 B**
ReleaseSmall, consistent with the 1.92 MB floor measured above.

But two pre-1.0 dvui defects sit directly on that path, and both are worked around in
`src/app/window.zig`. Neither is reachable by an app that creates one device and exits, which
is presumably why they survive upstream:

- **`createSampler` leaks an `ID3D11BlendState` per window** (`src/backends/dx11.zig`). It
  builds a blend state on every call and overwrites the previous one without releasing it, and
  it runs twice per window — once per texture interpolation. One stranded device child keeps
  the whole `ID3D11Device` alive, so *nothing* is reclaimed on teardown: measured at +103
  threads, +364 handles and +27 MB private **per cycle**, none of it returned. Confirmed by
  refcount probe (the device sat at 1 reference after `WindowState.deinit`) and isolated by
  bisect (a bare create/destroy of window + device with dvui out of the loop reached 0 refs and
  leaked nothing). Worked around by supplying the nearest sampler ourselves so dvui's creation
  path runs once instead of twice; the device then reaches 0 references and the table above is
  what teardown actually returns.
- **Zero-repeat key messages panic the backend**, the pitfall the UI prototype recorded:
  `for (1..info.repeat_count)` underflows when a synthetic `WM_KEYDOWN`/`WM_KEYUP` carries a
  zero repeat count. Real keyboards never send one. The app's wndproc normalizes the count to
  at least 1 before forwarding.

One layout note, not a defect: `GridWidget` reports the height it was given as its own minimum,
which is self-fulfilling inside a vertical box — the box then has nothing left for a status bar
under it and pushes it off the window. `.max_size_content = .height(0)` on the grid is dvui's
own lever for this (`WidgetData.minSizeSetAndRefresh` clamps the reported minimum).
