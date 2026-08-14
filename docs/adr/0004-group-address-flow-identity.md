# A Group Address never occupies a Flow's local endpoint

When a UDP datagram is addressed to a **Group Address** — a multicast group, the limited
broadcast address, or a subnet-directed broadcast — that address is vacated from the receiving
Flow's local endpoint and carried as an attribute instead. The local port is unchanged. The
local *address* becomes the receiving interface's unicast address where that is derivable, and
the unspecified address otherwise.

This resolves the tension [#41](https://github.com/cyljacky02/zpulsar/issues/41) opened against
[#36](https://github.com/cyljacky02/zpulsar/issues/36). #36 established by controlled live trace
(`docs/research/etw-tcp-udp-pipeline.md` §2.5) that a UDP receive is packet-oriented: ids 43/59
describe the arriving datagram, so `daddr`/`dport` is the local side. That is correct for
unicast. For a datagram addressed to a group the datagram's destination *is the group*, so the
Flow's local endpoint came out as `192.168.88.255:57621` or `224.0.0.252:5355` — not an address
any socket could have bound, contradicting #36's own acceptance criterion, which was ticked
unqualified and is, read literally, false.

## The rule

A Group Address is recognised by class, and each class yields a different local address because
each carries a different amount of information:

| class | example | local address becomes |
|---|---|---|
| multicast (`224.0.0.0/4`, `ff00::/8`) | `224.0.0.251:5353` | unspecified — no subnet is encoded |
| limited broadcast (`255.255.255.255`) | `255.255.255.255:67` | unspecified — no subnet is encoded |
| subnet-directed broadcast | `192.168.88.255:57621` | `192.168.88.254` — the interface's own address |

A directed broadcast address encodes its subnet, so the receiving interface is *derivable*: join
the datagram's destination with the OS's own prefix table and exactly one local interface
produces `192.168.88.255`. That is not a guess. It is the join of two facts Windows reports, and
it is refused whenever it would become one — **resolution requires exactly one matching prefix.**
Two interfaces sharing a prefix leave the address a broadcast with the local side unspecified;
*no* matching prefix means the address is somebody else's directed broadcast, indistinguishable
from a host from here, and it is left alone entirely as an ordinary unicast destination. A /31,
/32 or /0 has no broadcast address to match against and never participates.

§2.5 previously recorded that "there is no better answer available" because "the payload carries
no field for the receiving interface's unicast address." The payload still doesn't. The engine
now knows its own prefixes, which is where the answer was.

Flow identity keeps one Flow per peer — the sender remains the remote endpoint, so Hostname
Attribution is untouched. `ConnKey` gains `group_kind`, so a group-addressed conversation and a
unicast one with the same peer on the same ports stay distinct. The **send** path is unchanged:
there the group already sits correctly in the remote endpoint, which is what a send is addressed
to.

## Where the rule lives

Engine-side, at the `core.applyEvent` → `flows.flowKey` boundary — not in `parser.zig`, which
continues to report exactly what the wire says. Two constraints force this and neither is a
matter of taste:

- `NetEvent` is 56 bytes against a `@sizeOf <= 64` assert (`src/engine/event.zig`). A `[16]u8`
  group address takes it to 72 and breaks the assert, so the group cannot ride on the event.
- [ADR-0002](./0002-engine-architecture-and-threading.md) makes the consumer thread parse-only
  with no locks on the ETW callback path, while the prefix table is Engine-owned state. Reading
  it from the parser would be a data race or a new cross-thread mechanism.

Keeping the parser a faithful decoder also means the TDH fallback inherits the behaviour for
free, exactly as it inherits orientation today, so the two parse paths cannot disagree.

## Considered options

- **Accept the group in the local slot and document it** — the cheapest option, and #41's
  first. Rejected because the display then makes a claim the data does not support: a reader of
  `224.0.0.251:5353 -> 192.168.1.7:5353` concludes the process is bound to a multicast address.
  Weakening the promise to cover only the port was the alternative framing and was rejected for
  the same reason.
- **Key the Flow on the group, ICMP-style, with the peer display-only** ([ADR-0003](./0003-icmp-flow-identity.md)) —
  one Flow per group instead of one per peer, which would also have collapsed the send/receive
  pair and fixed the `udp_flows` over-count. Rejected: ADR-0003 made the peer display-only
  because the send path genuinely carries *no address*. Here the sender is present in `saddr`,
  correct, and already driving Hostname Attribution. Discarding a field we have, in imitation of
  a decision made because a field was missing, is the wrong lesson. It also contradicts the
  standing rule that one socket talking to N remotes is N Flows.
- **Infer local addresses from the owner tables already fetched every 10 s** — would have avoided
  new Windows surface entirely. Rejected because it fails exactly where it is needed: a
  `0.0.0.0`-bound socket never reveals an interface address, and a wildcard bind is precisely the
  case in #41's repro.
- **Use the unspecified address uniformly, for directed broadcast too** — one rule instead of
  two, and it lines up with the bind in the common case. Rejected because it leaves the local
  endpoint less precise than the available facts permit, and abandons the one case where a
  specifically-bound socket's Service Attribution can be fixed. The interface table is required
  for *classification* regardless, so this saves no Windows surface.
- **Put the full `group_addr` in `ConnKey`** — would eliminate every merge rather than the
  realistic one. Rejected: it widens the hash key for every Flow, TCP included, to separate a
  case needing one peer to send to two different groups from one source port to one destination
  port. mDNS, LLMNR and SSDP all use distinct ports.
- **`NotifyIpInterfaceChange` for immediate invalidation** — rejected for v1: a new waitable and
  a callback landing off the Engine thread, for a table that changes perhaps twice a day. The
  10 s sweep already does this shape of work. Recorded as the upgrade path if staleness ever
  bites.

## Consequences

- **Multicast on a specifically-bound socket still matches no owner-table row.**
  `owner_module.localMatches` rescues a group-addressed Flow only through its wildcard fallback,
  which keys on the *row* being `0.0.0.0`-bound. This is pre-existing and unchanged — zeroing the
  local address is neutral, not curative — and is now written down. Directed broadcast on such a
  socket *is* fixed, because resolution supplies the address the row actually holds.
- **A specifically-bound socket receiving group traffic shows one extra row.** `presenceTuple`
  always zeroes a group Flow's local address, so `reconcile` sees such a socket's table row as
  uncovered and seeds it as a zero-remote placeholder alongside the group Flow. This is a
  deliberate under-claim: the extra row is a real bound socket, whereas claiming coverage of an
  endpoint the Flow may not own could mask a socket nothing else is monitoring.
- **Two Groups of the same kind, same ports, same peer, merge**, and the displayed address is
  whichever arrived last. `group_kind` separates group traffic from unicast, not one group from
  another.
- **Up to 10 s of staleness.** A newly added subnet's directed broadcasts classify as unicast
  until the next sweep, reading exactly as they did before this decision. A failed table query
  keeps the last good table and retries, mirroring how a failed owner-table query is already
  handled; it degrades to prior behaviour, never to a wrong answer.
- **A process that broadcasts and hears itself still shows two Flows**, and the receive now reads
  as a self-loop (`192.168.88.254:57621 -> 192.168.88.254:57621`). That is honest — it is hearing
  its own datagram — but it makes the `[bcast …]` badge load-bearing rather than decorative:
  without it the row is inexplicable.
- **`udp_socks` is renamed `udp_flows`**, matching `icmp_flows` beside it. It counts live Flows
  per protocol and always has; the old name promised a socket count the engine never computed,
  which broadcasting made conspicuous but did not cause.
- **Hostname Attribution is unaffected.** It keys on `remote_addr`, which is the true sender in
  every case above.
