# P2P Testing Notes

P2P is the network layer. It owns TCP sockets, a thread pool, a peer
table, an address book, and a ban list. It carries consensus messages
between nodes but does not itself decide what they mean as that's the
consensus layer's job.

### Wire framing (`MessageTests.cpp`)

- `encodeMessage` produces the exact 10-byte header: 4-byte magic LE,
  2-byte type LE, 4-byte size LE, then payload.
- `MessageDecoder` handles partial headers, partial bodies, byte-by-byte
  delivery, multiple messages in one buffer.
- Corrupted magic and oversized messages are rejected.
- `reset()` clears the buffer.

This file pins the on-wire format for all non-consensus messages. A
byte-order mistake here would produce a broken network that works within
a version but fails across versions.

### Handshake and control messages (`VersionMessageTests.cpp`)

Round-trips for `VersionMessage`, `Peers`, `GetHeaders`, `Inv`,
`GetData`. Truncated input is rejected. Oversized inventory is rejected
(`InvRejectsOversize`).

### Consensus messages through P2P framing
(`WireFormatRoundTripTests.cpp`)

`encodeProposal` → `P2P::Message` → `encodeMessage` → `MessageDecoder`
→ `decodeProposal`. Every field verified. Same for `Vote`, including
the `is_nil` flag.

This file closes the gap between `Consensus/Tests/MessageTests.cpp`
(consensus structs in isolation) and `P2P/Tests/MessageTests.cpp`
(framing in isolation). Neither tested the composition; this file does.

### Address book (`AddressBookTests.cpp`)

- Add, size, idempotency, IP:port keying.
- `pickRandom` with and without exclusions.
- `markConnected` resets attempt counter.
- Persistence across reopen.
- Seeds survive purge.
- **Purge path itself is not exercised** — the tests acknowledge this
  in comments; testing it would require injecting a fake clock.

### Ban list (`BanListTests.cpp`)

- Initial empty state.
- Misbehavior score below and at threshold.
- Explicit ban, unban, idempotent ban.
- Multiple IPs.
- Persistence across reopen.
- **`purgeExpired` path is not exercised** — the tests acknowledge this
  in comments; the entry that would be purged has score equal to the
  threshold and survives.

### State enum helpers (`PeerStateTests.cpp`)

`peerStateName`, `isOperational`, `isTerminal`. `isOperational` returning
true only for `Established` is the important invariant — it's what
`broadcast` uses to decide whether to send.

### Thread pool (`WorkerPoolTests.cpp`)

- Thread count.
- Job execution.
- Multiple jobs.
- Exception in a job does not kill the worker.
- Pending job count.

### P2PManager under real sockets (`P2PManagerTests.cpp`)

The only tests that open TCP connections. Uses a `ManagerHarness` that
runs the manager's event loop on a background thread and exposes wait
helpers with timeouts.

- Listening on a port accepts raw socket connections.
- `stop()` returns cleanly and is idempotent.
- Two managers complete the version handshake and reach `Established`
  on both sides.
- Peer count reflects connections.
- Disconnect callback fires with a non-empty reason.
- The accept loop re-arms after a disconnect — a third manager can
  connect to the same listener.
- A broadcast after handshake reaches the peer via `onMessage`.
- A node that dials itself is detected by nonce comparison and closed.

`TwoManagersHandshake`, `PeerCountReflectsConnections`, and the
`waitForEstablished` checks are the tests that would catch a regression
of the earlier `buildVersionMessage` bug, in which the handshake
exchanged a default-constructed version and every peer rejected the
connection as "protocol too old".

## The boundaries this module has

P2P has more boundaries than any other module:

- **P2P ↔ Consensus.** Consensus messages are encoded by
  `ConsensusMessage.cpp` and framed by `Message.cpp`. The composition
  is what actually goes on the wire; `WireFormatRoundTripTests.cpp`
  tests it.
- **P2P ↔ Node.** Node installs callbacks (`onMessage`,
  `onPeerConnected`, `onPeerDisconnected`) and consumes them.
  `P2PManagerTests.cpp` tests the callbacks fire; the wiring to `Node`
  is tested in `NodeEndToEndTests.cpp` when P2P is enabled (which it
  currently isn't in the end-to-end fixture).
- **P2P ↔ file system.** Address book and ban list persist to disk.
  Tested for round-trip, but the purge-on-reload path is not.
- **P2P ↔ time.** Timeouts, retry backoff, and purge-by-age all
  depend on wall-clock time. Tests inject a real clock and can't
  reliably exercise the age-based paths.

When adding tests to P2P, prefer ones that exercise at least one
boundary. A test that verifies `AddressBook::pickRandom` returns the
expected number of entries is a unit test; a test that verifies a
manager with a low `targetOutbound` actually dials a peer from its
address book is an integration test that catches a different class of
bug.