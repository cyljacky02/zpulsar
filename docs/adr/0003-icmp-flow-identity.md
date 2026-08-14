# ICMP Flow identity is (protocol, family, owning PID)

An ICMP Flow is identified by protocol, address family, and owning process — **not** by remote address, unlike every other Flow. The peer is learned from the replies the Flow correlates and carried for display only. A process pinging two hosts is therefore one Flow, showing whichever peer answered most recently.

This overrides the v1 spec ([issue #18](https://github.com/cyljacky02/zpulsar/issues/18), Data model: "ICMP: (protocol, remote address, PID)") and the correlation rule that depended on it ("match to the live ICMP Flow with the same remote address"). Both were written against `docs/research/icmp-visibility.md`, which established that TCPIP event 1422 carries `SourceAddress` and `DestAddress` — but only ever verified the fields the research capture printed: PID, direction, and ICMP type.

The reason is that those addresses are not there when it matters. Verified live during the build (elevated, Windows 11 build 26200, `logman` sessions on the TCPIP provider; see `docs/research/icmp-visibility.md` §Addendum). Under the keyword the spec selects, `ut:Global`, event 1422 logs **no addresses at all on the send path**:

```
ICMP: Sendmessage. Type = Echo Request, Code = 0, CompartmentId = 0, SourceAddress = , DestAddress =
    SourceAddressLength = 0     DestAddressLength = 0
```

The receive path carries both. Only the send path is attributable (its header PID is the real caller), and only the send path is address-less — precisely inverted from what the key needs.

Bisecting the provider's 64-bit keyword space found exactly one bit that makes the send path log its addresses: `ut:TcpipDiagnosis` (0x80). It is a per-packet keyword, and that is disqualifying:

| Session keywords | startup burst | events during a 20 MB download |
|---|---|---|
| `ut:Global` | 1155 | 300 |
| `ut:Global \| ut:TcpipDiagnosis` | 2144 | **12,433** |

Roughly 40× the steady-state event volume, on the consumer thread, to label a trickle of ping traffic. That trades the idle-CPU and Attribution-Latency budgets for a display field.

## Considered options

- **Enable `ut:TcpipDiagnosis` and keep the spec's key** — rejected on the volume above. The whole reason `ut:Global` was chosen is that it is a state-change keyword rather than a data path; this bit gives that back.
- **Correlate through a second send-path event that does carry the destination** — TCPIP 1370 (`ut:TcpipRoute`) and 1466 (`ut:AleRemoteEndpoint`) both fire in the pinging process's own context with the remote address, at affordable volume. Rejected for v1: neither is ICMP-specific, 1466's port field encodes something undocumented, and synthesizing one Flow from two correlated event streams is a large amount of undocumented-behavior surface for a display field. Recorded as the way back to per-host ICMP Flows if it ever matters.
- **Key on the remote address anyway, learned from the first reply** — rejected: an outbound message would have no Flow to belong to until a reply arrives, so a ping to an unreachable host would show nothing at all. Requests must be visible whether or not anything answers.

## Consequences

- Inbound correlation is by **(address family, ICMP type)** alone — no address is involved: a reply goes to the process that most recently sent the request its type pairs with (v4 echo 8→0 and timestamp 13→14; ICMPv6 renumbers echo to 128→129). Unmatched inbound ICMP is still dropped outright, so unsolicited ICMP creates no Flow and no Process Row.
- The heuristic is coarser than the spec's: with several processes pinging concurrently, replies resolve to the most recent requester rather than to the requester of that host. Verified live with two concurrent pingers to different hosts, where tight request→reply interleaving keeps it correct in practice.
- A Flow's `remote_addr` is all-zero until its first reply — an unanswered ping shows request counts against no peer, which is the honest reading.
- Nothing else about ICMP changes: still zero bytes in every total, still message counts, still a 30 s inactivity age-out, still invisible to the IP Helper reconciliation sweep.
- A `Flow`'s peer is taken from whichever message names one, request or reply, so a build that *does* log send-path addresses names it on the first request without any further change.
- ICMP the stack originates itself — errors, neighbor discovery, the echo replies it sends when something pings this machine — is logged in System's context and so appears as a PID-4 Flow, observed live as "1 sent / 0 recv" with no peer. That is a real outbound message and is shown as one. The rule that keeps System clean covers *inbound* messages, which carry no attribution at all and are dropped when unmatched.
- Event 1422 has only ever shipped at version 0. An unknown version **drops**, which would end ICMP visibility silently — there is no TDH fallback, because the payload's length-prefixed `win:Binary` addresses are exactly what `tdh.zig`'s flat offset derivation refuses to walk. Nothing surfaces this to the user; if a manifest revision ever lands, the symptom is ICMP Flows quietly ceasing to appear.
- The 1809 floor inherits a third verification item alongside the spec's two: whether 1809's TCPIP logs send-path addresses under `ut:Global`. If it does, the spec's original key becomes reachable there and this ADR is worth reopening.
