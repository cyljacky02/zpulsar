//! PROTOTYPE — fake data only. Shapes match the zPulsar glossary (CONTEXT.md):
//! Process Rows (incl. Service Attribution inside svchost), Flows, In-session Totals.
const std = @import("std");

pub const Proto = enum { tcp, udp, icmp };

pub const Pattern = enum { steady, wave, bursty, trickle, idle };

pub const Flow = struct {
    proto: Proto,
    endpoint: []const u8, // remote ip:port as observed
    hostname: ?[]const u8 = null, // Hostname Attribution (observed at lookup time)
    reverse_fallback: bool = false, // hostname came from reverse lookup — render dimmed
    pattern: Pattern,
    base_down: f64, // bytes/s (for icmp: messages/s)
    base_up: f64,
    phase: f64 = 0,
    down_bps: f64 = 0,
    up_bps: f64 = 0,
    down_total: f64 = 0, // bytes (for icmp: message count)
    up_total: f64 = 0,
};

pub const ProcRow = struct {
    name: []const u8,
    service: ?[]const u8 = null, // Service Attribution display name
    pid: u32,
    color: [3]u8, // badge color (stand-in for the real process icon)
    flows: []Flow,
    expanded: bool = false,
    down_bps: f64 = 0,
    up_bps: f64 = 0,
    down_total: f64 = 0,
    up_total: f64 = 0,

    pub fn isIcmp(p: *const ProcRow) bool {
        return p.flows.len > 0 and p.flows[0].proto == .icmp;
    }
};

const KB = 1024.0;
const MB = 1024.0 * 1024.0;

var flows_chrome = [_]Flow{
    .{ .proto = .udp, .endpoint = "173.194.182.201:443", .hostname = "rr3---sn-5hne6nsz.googlevideo.com", .pattern = .wave, .base_down = 6.2 * MB, .base_up = 45 * KB, .phase = 0.4 },
    .{ .proto = .tcp, .endpoint = "142.250.74.35:443", .hostname = "fonts.gstatic.com", .pattern = .trickle, .base_down = 120 * KB, .base_up = 6 * KB, .phase = 1.1 },
    .{ .proto = .tcp, .endpoint = "140.82.121.4:443", .hostname = "github.com", .pattern = .trickle, .base_down = 60 * KB, .base_up = 14 * KB, .phase = 2.9 },
    .{ .proto = .udp, .endpoint = "162.159.130.234:443", .hostname = "cloudflare-ech.com", .pattern = .steady, .base_down = 18 * KB, .base_up = 4 * KB, .phase = 4.2 },
};

var flows_steam = [_]Flow{
    .{ .proto = .tcp, .endpoint = "23.55.98.114:443", .hostname = "cache1-fra2.steamcontent.com", .pattern = .bursty, .base_down = 44 * MB, .base_up = 350 * KB, .phase = 0.0 },
    .{ .proto = .tcp, .endpoint = "23.55.98.201:443", .hostname = "cache7-fra2.steamcontent.com", .pattern = .bursty, .base_down = 31 * MB, .base_up = 280 * KB, .phase = 2.4 },
    .{ .proto = .udp, .endpoint = "162.254.197.39:27017", .hostname = "cm2-fra1.cm.steampowered.com", .pattern = .steady, .base_down = 3 * KB, .base_up = 2 * KB, .phase = 1.0 },
};

var flows_discord = [_]Flow{
    .{ .proto = .udp, .endpoint = "35.214.226.62:50002", .hostname = "media-router-fra04.discord.media", .pattern = .steady, .base_down = 42 * KB, .base_up = 38 * KB, .phase = 0.7 },
    .{ .proto = .tcp, .endpoint = "162.159.136.234:443", .hostname = "gateway.discord.gg", .pattern = .trickle, .base_down = 9 * KB, .base_up = 3 * KB, .phase = 3.3 },
};

var flows_wuauserv = [_]Flow{
    .{ .proto = .tcp, .endpoint = "13.107.4.52:80", .hostname = "dl.delivery.mp.microsoft.com", .pattern = .bursty, .base_down = 12.5 * MB, .base_up = 90 * KB, .phase = 4.6 },
    .{ .proto = .tcp, .endpoint = "20.54.24.169:443", .hostname = "sls.update.microsoft.com", .pattern = .trickle, .base_down = 40 * KB, .base_up = 12 * KB, .phase = 0.2 },
};

var flows_dnscache = [_]Flow{
    .{ .proto = .udp, .endpoint = "192.168.1.1:53", .hostname = "fritz.box", .reverse_fallback = true, .pattern = .trickle, .base_down = 4 * KB, .base_up = 2 * KB, .phase = 1.8 },
};

var flows_dosvc = [_]Flow{
    .{ .proto = .tcp, .endpoint = "192.168.1.34:7680", .hostname = "DESKTOP-9GK2H4B.lan", .reverse_fallback = true, .pattern = .wave, .base_down = 20 * KB, .base_up = 2.8 * MB, .phase = 2.0 },
};

var flows_onedrive = [_]Flow{
    .{ .proto = .tcp, .endpoint = "13.104.140.140:443", .hostname = "sat02pap002.storage.live.com", .pattern = .steady, .base_down = 60 * KB, .base_up = 2.4 * MB, .phase = 0.9 },
    .{ .proto = .tcp, .endpoint = "13.107.42.13:443", .hostname = "onedrive.live.com", .pattern = .trickle, .base_down = 12 * KB, .base_up = 30 * KB, .phase = 5.1 },
};

var flows_spotify = [_]Flow{
    .{ .proto = .tcp, .endpoint = "35.186.224.47:443", .hostname = "audio-fa.scdn.co", .pattern = .wave, .base_down = 350 * KB, .base_up = 8 * KB, .phase = 3.9 },
    .{ .proto = .tcp, .endpoint = "104.199.65.124:4070", .hostname = "ap-gew4.spotify.com", .pattern = .trickle, .base_down = 6 * KB, .base_up = 4 * KB, .phase = 2.2 },
};

var flows_edge = [_]Flow{
    .{ .proto = .tcp, .endpoint = "204.79.197.239:443", .hostname = "edge.microsoft.com", .pattern = .trickle, .base_down = 80 * KB, .base_up = 20 * KB, .phase = 1.4 },
    .{ .proto = .udp, .endpoint = "52.113.194.132:3478", .hostname = "worldaz.tr.teams.microsoft.com", .pattern = .steady, .base_down = 24 * KB, .base_up = 26 * KB, .phase = 0.3 },
};

var flows_ssh = [_]Flow{
    .{ .proto = .tcp, .endpoint = "100.89.14.7:22", .hostname = null, .pattern = .trickle, .base_down = 14 * KB, .base_up = 5 * KB, .phase = 2.7 },
};

var flows_system = [_]Flow{
    .{ .proto = .tcp, .endpoint = "192.168.1.20:445", .hostname = "nas.lan", .reverse_fallback = true, .pattern = .wave, .base_down = 24 * MB, .base_up = 400 * KB, .phase = 5.8 },
};

var flows_ping = [_]Flow{
    .{ .proto = .icmp, .endpoint = "1.1.1.1", .hostname = "one.one.one.one", .pattern = .steady, .base_down = 1.0, .base_up = 1.0, .phase = 0.0 },
};

var flows_search = [_]Flow{
    .{ .proto = .tcp, .endpoint = "204.79.197.200:443", .hostname = "www.bing.com", .pattern = .idle, .base_down = 0, .base_up = 0, .phase = 0 },
};

var flows_nv = [_]Flow{
    .{ .proto = .tcp, .endpoint = "152.199.4.33:443", .hostname = "gfwsl.geforce.com", .pattern = .idle, .base_down = 0, .base_up = 0, .phase = 0 },
};

var procs_storage = [_]ProcRow{
    .{ .name = "steam.exe", .pid = 3412, .color = .{ 0x2b, 0x6f, 0xb5 }, .flows = &flows_steam },
    .{ .name = "chrome.exe", .pid = 8244, .color = .{ 0xdb, 0x44, 0x37 }, .flows = &flows_chrome },
    .{ .name = "svchost.exe", .service = "Windows Update (wuauserv)", .pid = 2260, .color = .{ 0x0a, 0x84, 0x67 }, .flows = &flows_wuauserv },
    .{ .name = "System", .pid = 4, .color = .{ 0x64, 0x64, 0x6e }, .flows = &flows_system },
    .{ .name = "OneDrive.exe", .pid = 7788, .color = .{ 0x0f, 0x6c, 0xbd }, .flows = &flows_onedrive },
    .{ .name = "svchost.exe", .service = "Delivery Optimization (DoSvc)", .pid = 5960, .color = .{ 0x0a, 0x84, 0x67 }, .flows = &flows_dosvc },
    .{ .name = "Spotify.exe", .pid = 5532, .color = .{ 0x1d, 0xb9, 0x54 }, .flows = &flows_spotify },
    .{ .name = "Discord.exe", .pid = 9120, .color = .{ 0x58, 0x65, 0xf2 }, .flows = &flows_discord },
    .{ .name = "msedge.exe", .pid = 10204, .color = .{ 0x0c, 0x8a, 0x5d }, .flows = &flows_edge },
    .{ .name = "svchost.exe", .service = "DNS Client (Dnscache)", .pid = 1608, .color = .{ 0x0a, 0x84, 0x67 }, .flows = &flows_dnscache },
    .{ .name = "ssh.exe", .pid = 13340, .color = .{ 0x8a, 0x63, 0xd2 }, .flows = &flows_ssh },
    .{ .name = "PING.EXE", .pid = 15112, .color = .{ 0xc2, 0x71, 0x0a }, .flows = &flows_ping },
    .{ .name = "SearchHost.exe", .pid = 6120, .color = .{ 0x64, 0x64, 0x6e }, .flows = &flows_search },
    .{ .name = "nvcontainer.exe", .pid = 4480, .color = .{ 0x76, 0xb9, 0x00 }, .flows = &flows_nv },
};

pub const procs: []ProcRow = &procs_storage;

pub var global_down_bps: f64 = 0;
pub var global_up_bps: f64 = 0;
pub var global_down_total: f64 = 0;
pub var global_up_total: f64 = 0;
pub var flow_count: usize = 0;

var prng = std.Random.DefaultPrng.init(0x5eed_1e55);

/// Give idle rows some pre-existing In-session Totals so "idle but was active" reads correctly.
pub fn init() void {
    flows_search[0].down_total = 18.4 * MB;
    flows_search[0].up_total = 1.2 * MB;
    flows_nv[0].down_total = 2.1 * MB;
    flows_nv[0].up_total = 240 * KB;
}

pub fn tick(dt: f64, t: f64) void {
    const rnd = prng.random();
    global_down_bps = 0;
    global_up_bps = 0;
    global_down_total = 0;
    global_up_total = 0;
    flow_count = 0;

    for (procs) |*p| {
        p.down_bps = 0;
        p.up_bps = 0;
        p.down_total = 0;
        p.up_total = 0;
        for (p.flows) |*f| {
            const jitter = 0.85 + 0.3 * rnd.float(f64);
            var target_down: f64 = 0;
            var target_up: f64 = 0;
            switch (f.pattern) {
                .steady => {
                    target_down = f.base_down * jitter;
                    target_up = f.base_up * jitter;
                },
                .wave => {
                    const s = 0.5 + 0.5 * @sin(t * 0.45 + f.phase);
                    target_down = f.base_down * s * jitter;
                    target_up = f.base_up * s * jitter;
                },
                .bursty => {
                    const active = @sin(t * 0.22 + f.phase) > 0.1;
                    target_down = if (active) f.base_down * jitter else f.base_down * 0.005;
                    target_up = if (active) f.base_up * jitter else f.base_up * 0.01;
                },
                .trickle => {
                    if (rnd.float(f64) < dt * 0.6) {
                        target_down = f.base_down * (1.0 + 3.0 * rnd.float(f64));
                        target_up = f.base_up * (1.0 + 3.0 * rnd.float(f64));
                    } else {
                        target_down = 0;
                        target_up = 0;
                    }
                },
                .idle => {},
            }
            const alpha = @min(1.0, dt * 2.5);
            f.down_bps += (target_down - f.down_bps) * alpha;
            f.up_bps += (target_up - f.up_bps) * alpha;
            if (f.proto != .icmp) {
                if (f.down_bps < 1) f.down_bps = 0;
                if (f.up_bps < 1) f.up_bps = 0;
            }
            f.down_total += f.down_bps * dt;
            f.up_total += f.up_bps * dt;

            p.down_bps += f.down_bps;
            p.up_bps += f.up_bps;
            p.down_total += f.down_total;
            p.up_total += f.up_total;
            if (f.down_bps > 0 or f.up_bps > 0) flow_count += 1;
        }
        if (!p.isIcmp()) {
            global_down_bps += p.down_bps;
            global_up_bps += p.up_bps;
            global_down_total += p.down_total;
            global_up_total += p.up_total;
        }
    }
}
