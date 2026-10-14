# Network

How Clarity nodes find each other, establish encrypted sessions, and exchange blocks, transactions, and proofs.

This document is written for someone who needs to implement a peer, audit the protocol, or debug a connection. It describes the wire format, the handshake, the encryption, the message routing, and the rate-limiting policy as they exist in the code.

## Table of contents

- [Overview](#overview)
- [Transport](#transport)
  - [TCP](#tcp)
  - [Message framing](#message-framing)
  - [The magic number](#the-magic-number)
- [The handshake](#the-handshake)
  - [Phase 1: Version and Verack](#phase-1-version-and-verack)
  - [Phase 2: Auth](#phase-2-auth)
  - [Phase 3: AuthReady](#phase-3-authready)
  - [Establishment](#establishment)
  - [Self-connection prevention](#self-connection-prevention)
- [Authentication](#authentication)
  - [The challenge](#the-challenge)
  - [The identity key](#the-identity-key)
  - [Non-validator peers](#non-validator-peers)
  - [Failure handling](#failure-handling)
- [Session encryption](#session-encryption)
  - [Key agreement](#key-agreement)
  - [Directional keys](#directional-keys)
  - [Nonces and AAD](#nonces-and-aad)
  - [Per-direction cipher state](#per-direction-cipher-state)
- [Messages](#messages)
  - [Control messages](#control-messages)
  - [Sync messages](#sync-messages)
  - [Relay messages](#relay-messages)
  - [Proof messages](#proof-messages)
  - [Consensus messages](#consensus-messages)
- [Sync](#sync)
  - [The SyncManager state machine](#the-syncmanager-state-machine)
  - [Request bounds](#request-bounds)
  - [Timeouts](#timeouts)
  - [Idle refresh](#idle-refresh)
- [Relay](#relay)
  - [Block relay](#block-relay)
  - [Transaction relay](#transaction-relay)
  - [Relay loop breaking](#relay-loop-breaking)
- [Rate limiting](#rate-limiting)
  - [Per-peer buckets](#per-peer-buckets)
  - [The aggregate bucket](#the-aggregate-bucket)
  - [The two cost tables](#the-two-cost-tables)
  - [Failure responses](#failure-responses)
- [Peer management](#peer-management)
  - [The address book](#the-address-book)
  - [The ban list](#the-ban-list)
  - [Connection maintenance](#connection-maintenance)
  - [Peer deduplication](#peer-deduplication)
- [Threading](#threading)
- [What the network layer does not do](#what-the-network-layer-does-not-do)

## Overview

Clarity's P2P layer is a TCP-based, message-oriented protocol with an authenticated, encrypted session. Every peer connection goes through a four-phase handshake:

1. **Version and Verack** — exchange protocol version, network nonce, agent string, best height, listen port.
2. **Auth** — signed challenge-response binding both peers' identity keys and ephemeral keys to the session.
3. **AuthReady** — first encrypted message; confirms that both sides derived the same session key.
4. **Established** — application messages flow.

Once established, peers route messages by type: proposals, votes, transactions, block announcements, sync requests, proof requests, and peer addresses. Consensus messages (proposals and votes) are routed to the consensus engine. Relay and sync messages are routed to the node's handlers, which apply blocks, add transactions to the mempool, and answer proof requests.

The layer has three safety properties it maintains explicitly:

- **Peer identity is authenticated** before any application message is processed. A peer that fails the Auth exchange is closed immediately.
- **Application payloads are encrypted** with a per-session key derived from X25519 ephemeral exchange. The identity keys are not used for encryption; only for signing the Auth challenge.
- **Message processing is rate-limited** at two levels: per-peer (bounded by a token bucket per connection) and aggregate (bounded by a node-wide budget shared by all peers). Expensive messages are charged more, so a peer that floods expensive requests is cut off before it starves the node.

## Transport

### TCP

Every connection is a TCP socket. Both IPv4 and IPv6 are supported; the listener binds one or the other depending on the `listenOnIPv6` config flag.

The socket is non-blocking. Reads and writes are driven by `boost::asio` on a single `io_context`. All socket operations (accept, connect, read, write, close) run on the event loop thread. CPU-heavy work — deserializing a block, verifying a proof, applying state transitions — is offloaded to a small worker pool.

The maximum message size is `MAX_MESSAGE_SIZE = 16 MiB`. A peer that sends a header claiming a larger payload is disconnected before the payload is read.

### Message framing

Every message is framed with a 10-byte header:

```
[4] magic         (LE)
[2] type          (LE)
[4] payload_size  (LE)
```

The header is followed by exactly `payload_size` bytes of payload. There is no length footer, no checksum, no terminator. A reader that sees a header reads exactly `payload_size` bytes and treats the next 10 bytes as the next header.

The header is always plaintext. Once a session is established (both peers have sent and verified `AuthReady`), the payload is encrypted with XChaCha20-Poly1305; before that, the payload is plaintext.

### The magic number

Every network has its own magic:

| Network | Magic | ASCII |
| --- | --- | --- |
| Mainnet | `0x54524C43` | `CLRT` little-endian |
| Testnet | `0x54544C43` | `CLTT` little-endian |
| Regtest | `0x47524C43` | `CLRG` little-endian |

A peer that receives a header with the wrong magic closes the connection. The magic check is the first thing that happens on any received bytes; a peer that accidentally connects to a node on a different network is rejected before any parsing.

The magic is derived from the chain id but is not the chain id. Two networks could theoretically have the same chain id and different magic, but the current networks use distinct values for both.

## The handshake

The handshake runs in three phases over the TCP connection. Every phase exchanges exactly two messages (one in each direction), and each phase's completion depends on the other side's message having arrived.

### Phase 1: Version and Verack

After TCP connect, both peers send a `Version` message:

```
VersionMessage:
    protocolVersion  : u32 LE
    networkNonce     : u64 LE
    timestamp        : i64 LE
    listenPort       : u16 LE
    agentString      : u8 length || bytes   (max 255)
    bestHeight       : u64 LE
    peerNonce        : u64 LE              (unused; zero)
```

Each side then reads the other's `Version` and checks:

- The magic is correct (already checked at the framing level).
- The protocol version is compatible. The current protocol version is `CURRENT_PROTOCOL_VERSION`; a peer that advertises a version below the minimum is rejected as "protocol too old".
- The `networkNonce` is not our own. If it is, we've dialed ourselves; the connection is closed.

On successful verification, each side sends a `Verack` message (empty payload) and waits for the peer's `Verack`. The `Verack` exchange confirms that both sides have read and accepted each other's `Version`.

The `networkNonce` is a random 64-bit value generated once per node at startup. It is included in every `Version` message the node sends. It is used both for self-connection detection and, later, as part of the Auth challenge.

### Phase 2: Auth

After both sides have exchanged `Version` and `Verack`, the connection transitions to the `AuthPending` state. Each side sends an `Auth` message:

```
AuthMessage (fixed 128 bytes):
    identityPubkey   : 32 bytes (Ed25519 public key)
    ephemeralPubkey  : 32 bytes (X25519 public key)
    signature        : 64 bytes (Ed25519 over the challenge)
```

The `Auth` message is fixed-size and untyped — it does not carry a length prefix or a tag. A 96-byte `Auth` is the pre-encryption format and is rejected by the size check; a 128-byte message is this format.

The identity public key is the sender's long-term Ed25519 public key. It is used for signing the challenge and, after verification, for looking up the sender's validator record. A validator uses its consensus key as its identity; a non-validator uses a per-node key generated at first startup and stored at `<data_dir>/node_key`.

The ephemeral public key is a fresh X25519 public key, generated per session, never persisted. It is the input to the session key agreement (see [Session encryption](#session-encryption)).

The signature is over the challenge, which binds the two nonces, the identity key, and the ephemeral key. The construction is described in detail in [Authentication](#authentication).

Both `Auth` messages cross on the wire; neither side waits for the other's before sending its own.

### Phase 3: AuthReady

After sending `Auth` and receiving the peer's `Auth`, each side:

1. Verifies the peer's signature against the challenge.
2. Derives the session key from its own ephemeral secret and the peer's ephemeral public key.
3. Sends `AuthReady` — an empty message whose AEAD tag is the key confirmation.

The two sides send `AuthReady` independently, but the protocol requires that **neither side encrypts anything before sending its own `AuthReady`**, and **neither accepts anything encrypted before receiving the peer's `AuthReady`**.

The reason for the two-step is that the two `Auth` messages cross on the wire. A peer that finishes processing the peer's `Auth` may not yet have sent its own `Auth` — meaning it may not know whether the peer's signature is valid. If it started encrypting immediately, it would be encrypting under a key the peer might not derive (if the signature turns out to be invalid).

`AuthReady` synchronizes the transition. It is sent only after both sides have completed their respective `Auth` verifications. If the two sides derived the same key, the AEAD tag verifies; if they derived different keys, it doesn't, and the connection is closed.

### Establishment

After both sides have exchanged and verified `AuthReady`, the peer transitions to `Established`. This is the state in which application messages flow.

The manager maintains a per-pubkey map of established peers. When a peer transitions to `Established`, the manager checks whether another peer with the same identity pubkey is already established. If so, it applies the deduplication rule (see [Peer deduplication](#peer-deduplication)) and closes the loser.

The `onEstablished` callback fires once per successfully-established peer. The node uses it to instantiate a `SyncManager` for that peer.

### Self-connection prevention

Each node generates a random 64-bit `networkNonce` at startup. The nonce is sent in the `Version` message, and every node checks the received nonce against its own.

The check happens in `P2PManager::handlePeerMessage`, after the peer has been created but before any handshake messages are processed. If the received nonce matches the local nonce, the peer is closed with reason `"self-connection"`.

The check is placed there rather than in the peer's own `Version` handler because the manager sees the message first and can close the peer without the state machine needing to know about self-connections.

## Authentication

### The challenge

Every peer must complete the `Auth` exchange. The challenge is:

```
Blake2b(
    localNonce      8 bytes (LE)
  || remoteNonce     8 bytes (LE)
  || identityPubkey  32 bytes
  || ephemeralPubkey 32 bytes
)
```

`localNonce` is the sender's network nonce (the one it sent in its `Version`); `remoteNonce` is the peer's network nonce (the one it received). The two are ordered by direction — the initiator's nonce comes first — so both sides compute the same challenge.

Including both nonces binds the signature to the specific session: a signature captured from one session cannot be replayed in another, because the nonces differ.

Including both public keys binds the signature to the claimed identity and to the ephemeral key. A MITM that substitutes a different ephemeral key would produce a different challenge and invalidate the signature; a peer that claims a different identity would too.

The construction is documented in `AuthMessage.h` and implemented in `P2P::computeAuthChallenge`.

### The identity key

The identity public key is a 32-byte Ed25519 public key. It is used in two ways:

1. **To sign the challenge.** A valid `Auth` message must carry a signature over the challenge that verifies against the identity key.
2. **To look up the sender's validator record.** After verification, the manager looks up the validator whose consensus key matches the identity key. If found, the peer's `validator_id` is set to that validator's id; if not, the peer is authenticated but claims `validator_id = 0`.

The identity key is not used for encryption. Only the ephemeral X25519 key is used for the session key agreement. This gives forward secrecy: an attacker who compromises a validator's long-term identity key does not thereby compromise past session keys.

### Non-validator peers

A peer does not have to be a validator to connect. A non-validator node can authenticate with its own identity key (loaded from `<data_dir>/node_key`), and other nodes will accept it with `validator_id = 0`.

Non-validator peers can still participate in the P2P network: they can relay blocks and transactions, sync from other peers, and request proofs. They cannot sign proposals or votes, and their messages are not counted toward quorum.

The choice to accept non-validator peers is deliberate. It lets a user run a full node without being a validator, which is the standard model for block explorers, wallets, and indexers. The alternative — a permissioned network where only validators can connect — would require publishing the validator set and validating every connection against it, which the current design does not do.

### Failure handling

- **Invalid signature.** The peer is closed immediately and reported as misbehaving. A failed auth is a strong signal of a bad actor.
- **Missing or malformed Auth.** Same as an invalid signature. The peer is closed.
- **Key derivation failure.** If `deriveSessionKeys` fails for any reason (a missing `getOurIdentityPubkey` callback, a null ephemeral key, etc.), the peer is force-closed with `"encryption: key derivation failed"`. This is not treated as misbehavior; it's a configuration or protocol error, not an attack.
- **AuthReady mismatch.** If the peer's `AuthReady` fails to decrypt, the two sides derived different keys. The peer is closed **without** a ban. A session-key disagreement is not evidence of misbehavior; it could be a version mismatch, a bug, or a transient issue.

## Session encryption

### Key agreement

Once both `Auth` messages have been received and verified, each side has:

- Its own ephemeral X25519 secret.
- The peer's ephemeral X25519 public key.
- Both sides' identity Ed25519 public keys.
- Both network nonces.

The shared secret is:

```
sharedSecret = X25519(our_ephemeral_secret, their_ephemeral_pubkey)
```

This is a standard ephemeral-ephemeral X25519 agreement. The identity keys and nonces are folded into the key derivation function (see below) so that the derived keys are bound to the session context, not just the shared secret.

After the session keys are derived, the ephemeral secret is wiped (`Crypto::SecureZero`). It's never persisted, never logged, never leaves the `Peer` object.

### Directional keys

The session keys are two, not one. `deriveSessionKeys` produces:

- A **sending key** for the direction "this node → peer".
- A **receiving key** for the direction "peer → this node".

The two directions are distinguished by which side has the lower network nonce. The lower-nonce side uses key A for sending and key B for receiving; the higher-nonce side uses them the other way around. Both sides compute the same two keys and assign them by the same rule, so the sending key of one side is the receiving key of the other.

The two keys are derived from the shared secret via labelled Blake2b calls:

```
keyA = Blake2b("clrty-x25519-A" || sharedSecret
             || our_ephemeral_pubkey || their_ephemeral_pubkey
             || our_identity_pubkey  || their_identity_pubkey
             || localNonce || remoteNonce)
keyB = Blake2b("clrty-x25519-B" || sharedSecret
             || our_ephemeral_pubkey || their_ephemeral_pubkey
             || our_identity_pubkey  || their_identity_pubkey
             || localNonce || remoteNonce)
```

The full derivation is in `Crypto/SessionKey.h`. The important properties:

- The shared secret provides the entropy.
- The public keys and nonces are bound into the derivation, so two sessions with the same shared secret but different contexts have different keys.
- The labels ensure `keyA ≠ keyB` even if the input were somehow symmetric.

Two directional keys are not strictly necessary for confidentiality — a single shared key with a per-direction nonce counter would also be safe — but they remove the class of bug where the two directions accidentally share a nonce space.

### Nonces and AAD

Every encrypted message uses XChaCha20-Poly1305 with a 24-byte nonce. The nonce is constructed from an 8-byte counter:

```
nonce[0..8)  = counter (LE)
nonce[8..24) = zero
```

The counter starts at 0 for each direction. `AuthReady` uses counter 0; the first application message uses counter 1; and so on. The counter increments on each encrypted send (outbound) and on each successfully decrypted receive (inbound).

The counter never wraps. Each direction is bounded by 2^64 messages, which at one message per nanosecond is longer than the age of the universe. The `Peer` code checks the counter before incrementing and closes the connection if it would overflow.

The **AAD** on every message binds the message type and the direction:

```
AAD = [message_type (2 bytes LE)] || [direction_tag (1 byte)]
```

The `direction_tag` is 0 if this node is the lower-nonce side, 1 if it's the higher-nonce side. It is computed as `directionTag(asSender)` and used both when encrypting (sender perspective) and when decrypting (receiver perspective). The two tags are opposite for the same message on the two sides, so a frame sent by side A cannot be replayed back to side A under the same tag.

The AAD makes three attacks impossible:

1. **Reflection.** A message sent by A to B, if reflected back to A, has the wrong direction tag and fails authentication.
2. **Type confusion.** A message framed as a `Prevote` cannot be re-framed as a `Precommit` without invalidating the AEAD tag.
3. **Reordering across directions.** A message sent by A cannot be treated as a message received by A, because the directions use different keys and different AAD tags.

### Per-direction cipher state

The cipher state is tracked independently for the two directions:

```cpp
SessionCipherState outboundCipher_ = SessionCipherState::Plaintext;
SessionCipherState inboundCipher_ = SessionCipherState::Plaintext;
```

Each transitions from `Plaintext` to `Encrypted` at its own moment:

- **Outbound** flips to `Encrypted` the moment `AuthReady` is sent.
- **Inbound** flips to `Encrypted` the moment the peer's `AuthReady` is successfully decrypted.

The window between those two events — one side has sent `AuthReady`, the other hasn't yet — is **half-encrypted**: the sending side is encrypting outbound, but the receiving side hasn't yet transitioned inbound. This is normal and correct. The protocol requires that neither side sends an encrypted message before the peer is ready to receive it, which is guaranteed by the `AuthReady` synchronization: the peer's inbound cipher flips to `Encrypted` at exactly the moment it decrypts the first `AuthReady`.

A peer in `Established` but with either direction still `Plaintext` should never be observable. `Peer::sessionIsEncrypted()` returns true only when both directions are encrypted, and it exists for tests and RPC introspection.

## Messages

### Control messages

| Type | Value | Payload | Notes |
| --- | --- | --- | --- |
| `Version` | 0x0001 | `VersionMessage` | Handshake phase 1 |
| `Verack` | 0x0002 | empty | Handshake phase 1 ack |
| `Ping` | 0x0003 | empty | Keepalive |
| `Pong` | 0x0004 | empty | Keepalive reply |
| `GetPeers` | 0x0005 | empty | Request peer addresses |
| `Peers` | 0x0006 | `PeersMessage` | Peer address list |
| `Auth` | 0x0007 | `AuthMessage` | Handshake phase 2 |
| `AuthReady` | 0x0008 | empty (encrypted) | Handshake phase 3 |
| `Disconnect` | 0x00FF | optional reason | Graceful close |

`Ping` and `Pong` are the peer keepalive. A peer that hasn't sent anything for `pingIntervalSec` is pinged; a peer that hasn't responded to a ping within `pongTimeoutSec` is disconnected.

`GetPeers` and `Peers` implement peer discovery. A peer that receives a `GetPeers` replies with up to 100 addresses from its own address book. Received `Peers` messages are added to the local address book.

### Sync messages

| Type | Value | Payload | Notes |
| --- | --- | --- | --- |
| `GetHeaders` | 0x0010 | `GetHeadersMessage` | Request header range |
| `Headers` | 0x0011 | `HeadersMessage` | Header range |
| `GetBlocks` | 0x0012 | `GetBlocksMessage` | Request full blocks by hash |
| `Blocks` | 0x0013 | `BlocksMessage` | Full blocks |
| `GetProof` | 0x0014 | `GetProofMessage` | Request an SMT proof |
| `Proof` | 0x0015 | `ProofMessage` | The proof |

These are described in detail in the [Sync](#sync) section.

### Relay messages

| Type | Value | Payload | Notes |
| --- | --- | --- | --- |
| `Inv` | 0x0020 | list of `(type, hash)` | Announce inventory |
| `GetData` | 0x0021 | list of `(type, hash)` | Request inventory |
| `Tx` | 0x0022 | serialized transaction | Announce / relay a transaction |
| `Block` | 0x0023 | serialized block | Announce / relay a block |

`Inv` and `GetData` are the relay's notification protocol. A node that has a new block or transaction announces it via `Inv`; a peer that doesn't have it responds with `GetData`; the announcer sends the full object. This lets the network propagate inventory without sending full blocks to peers that already have them.

`Tx` and `Block` are the direct relay messages. In the current implementation, blocks and transactions are relayed directly via `Block` and `Tx` (see [Relay](#relay) below), without going through the `Inv`/`GetData` round trip. The `Inv`/`GetData` protocol is defined but not currently used for relay; it exists for future optimization.

### Proof messages

The `GetProof` and `Proof` messages are the light-client proof protocol. A client that holds a state root can request a proof for any key at any version; the server resolves the request to the SMT key, walks the tree from the requested version's root, and replies with the proof and the root it was proven against.

The request carries a typed descriptor rather than a raw SMT key. The descriptors are:

- `Account` — a 32-byte address.
- `TokenBalance` — a 32-byte address followed by a 4-byte LE token id.
- `Validator` — an 8-byte LE validator id.
- `Global` — a UTF-8 name (max 64 bytes).
- `AmmPool` — an 8-byte LE pool id.

The server resolves the descriptor to the same 32-byte SMT key the state layer uses and produces the proof. The reply's status field is one of:

- `Ok` — a proof was produced.
- `VersionUnavailable` — the requested version has no saved root.
- `KeyNotFound` — the version has a root, but the walk could not produce a proof.
- `Malformed` — the request's key descriptor didn't match its declared type.

### Consensus messages

| Type | Value | Payload | Notes |
| --- | --- | --- | --- |
| `Proposal` | 0x0040 | encoded `Proposal` | BFT proposal |
| `Prevote` | 0x0041 | encoded `Vote` | BFT prevote |
| `Precommit` | 0x0042 | encoded `Vote` | BFT precommit |

The consensus messages are routed to the consensus engine. They are not relayed — a proposal or vote is broadcast to every peer but not re-broadcast on receipt. This is different from the block and transaction relay paths, where re-broadcasting is what propagates the message through the network.

The consensus messages are charged against the consensus rate-limit bucket, which is separate from the general per-peer bucket. This bounds a validator that floods proposals or votes independently of the general message budget.

## Sync

### The SyncManager state machine

Each established peer has a `SyncManager` that drives the sync protocol. The manager is a small state machine with three states:

- **Idle.** The peer is caught up; no sync request is outstanding.
- **RequestingHeaders.** A `GetHeaders` was sent; waiting for `Headers`.
- **RequestingBlocks.** A `GetBlocks` was sent; waiting for `Blocks`.

The transitions are:

- **Idle → RequestingHeaders**: when the peer's advertised height is higher than the local height.
- **RequestingHeaders → RequestingBlocks**: when a `Headers` reply arrives with a non-empty range.
- **RequestingBlocks → Idle**: when a `Blocks` reply arrives with the requested blocks.
- **Any → Idle**: on timeout.

The `SyncManager` is driven by `tick()`, which is called periodically from the node's sync tick timer. Each tick checks for timeouts and drives the next step. This is what makes sync self-healing: a peer that doesn't respond within the timeout is retried or abandoned, and the next peer is tried.

### Request bounds

A single `GetHeaders` can request at most `MAX_HEADERS_PER_REQUEST = 2000` headers. A `Headers` reply with more entries is malformed and rejected.

A single `GetBlocks` can request at most `MAX_BLOCKS_PER_REQUEST = 128` full blocks. The actual bound is computed by `maxBlocksPerRequest(max_block_bytes)` so that a reply fits in one message:

```
maxBlocksPerRequest(max_block_bytes) =
    max(1, MAX_MESSAGE_SIZE / (max_block_bytes + overhead))
```

For a max block size of 256 KiB, that's about 60 blocks per request. For a smaller max block size, the bound is larger.

The `GetBlocks` request carries the hashes of the requested blocks. The peer responds with a `Blocks` message containing those blocks, in the same order. If the peer doesn't have one of the requested blocks, it omits it and sends the rest; the requester re-requests the missing ones on the next round.

### Timeouts

- **Headers timeout**: 30 seconds. If a `Headers` reply doesn't arrive within this window, the `SyncManager` times out, marks the peer as having failed the request, and returns to `Idle`.
- **Blocks timeout**: 60 seconds. Same handling.

A timed-out request is not a disconnect; the peer is not banned, not reported as misbehaving, and not closed. It's just a request that didn't complete. The next sync attempt may use a different peer.

### Idle refresh

A `SyncManager` that's in `Idle` and hasn't seen a block in `idleRefreshInterval` (default 30 seconds) re-issues a `GetHeaders` to the peer. This is what makes a node self-heal after briefly falling behind: if the peer committed new blocks while we were idle, the refresh discovers them without waiting for a `Block` relay message.

The refresh is bounded by a small interval so a busy node doesn't spam its peers with `GetHeaders`. In practice, the interval is longer than the block interval, so a caught-up node sends at most one refresh per block.

## Relay

### Block relay

When a validator commits a block, it broadcasts the full serialized block to every `Established` peer via a `Block` message. Each recipient:

1. Deserializes the block.
2. Checks that it's the next block after the current chain head.
3. If yes, applies it via `Node::applyCommittedBlock` (the same path consensus uses).
4. Re-broadcasts the block to every `Established` peer *except* the one it came from.

A node that already has the block (`chain_db_->hasBlock(block_hash)`) drops it silently. This is what breaks the propagation loop: without the "already have it, drop it" rule, a block would circulate forever.

A block that doesn't connect to the current head — the height is too high, or the parent hash doesn't match — is dropped without applying it. The `SyncManager` for the peer that sent it will eventually catch up via `GetHeaders` / `GetBlocks`.

### Transaction relay

When a node accepts a transaction into its mempool, it broadcasts the full serialized transaction to every `Established` peer via a `Tx` message. Each recipient:

1. Deserializes the transaction.
2. Checks that it's not already in the mempool (`mempool_->contains(txid)`).
3. If not, validates it and adds it to the mempool.
4. Re-broadcasts to every peer *except* the one it came from.

Same loop-breaking rule as block relay: a node that already has the transaction drops it silently.

The broadcast happens after the mempool accepts the transaction, so a transaction that fails validation is not relayed. The validation includes a signature check, a nonce check, a fee-rate check, and the type-specific preconditions.

### Relay loop breaking

Both block and transaction relay use the same loop-breaking rule: a node that already has the object drops the incoming message without re-broadcasting. This is what makes the network propagate a message exactly once (per node) rather than circulating forever.

The rule is enforced by:

- `chain_db_->hasBlock(block_hash)` for blocks.
- `mempool_->contains(txid)` for transactions.

A block that's already in the chain DB drops immediately. A transaction that's already in the mempool drops immediately. There is no separate "seen recently" cache, because the chain DB and mempool already serve that purpose.

## Rate limiting

### Per-peer buckets

Every peer has two token buckets:

- **General bucket.** Charged by `messageCost(type)` for every inbound message. Bounds the total message throughput from one peer.
- **Consensus bucket.** Charged by a fixed cost (typically 1) for consensus messages only. Bounds the proposal/vote throughput from one validator separately from the general bucket.

Both buckets use `Common::RateLimiter`, which is a simple token bucket with a burst and a refill rate. The bucket is refilled on each check based on the elapsed time since the last refill.

The general bucket's cost table reflects the asymmetry of work per message type. A control message costs 1; a `Tx` costs 5; a `GetHeaders` or `GetBlocks` costs 20; a `GetProof` costs 50. The high cost for proof requests reflects the server's work: a `GetProof` requires a tree walk from the requested root plus serialization of the proof.

### The aggregate bucket

Above the per-peer buckets is a **node-wide aggregate bucket**. It's shared across all peers, and it's charged at the same point the per-peer bucket is charged: on each inbound message, before the payload is read.

The aggregate bucket is what bounds the sum. Without it, a hundred peers each staying under their per-peer cap could still saturate the event loop thread's serving capacity. The aggregate bucket is the second line of defense: even if every peer is within its own budget, the total work is bounded.

### The two cost tables

The per-peer bucket and the aggregate bucket use **different cost tables**. This is deliberate.

The per-peer table's ratio reflects the per-message work:

```
GetProof      50
GetHeaders    20
GetBlocks     20
Block         10
Blocks        10
Tx             5
Proof          5
control        1
```

The aggregate table's ratio is compressed:

```
GetProof      10
GetHeaders     5
GetBlocks      5
Block          3
Blocks         3
Tx             3
Proof          3
consensus      3
control        1
```

The reason for the compression: at the aggregate level, the per-peer ratio is wrong. A single legitimate `GetProof` would consume 20% of a modest aggregate budget and starve header sync. The compressed ratio lets expensive work be shed first without letting a single legitimate request dominate. `GetProof` still costs more than a control message, just not 50× more.

The two tables live in separate translation units (`MessageTypes.cpp` and `AggregateLimiter.cpp`), so a future edit to one cannot silently change the other.

The consensus types are charged at the aggregate level even though they bypass the per-peer general bucket. A crowd of non-validators sending junk proposals is a real flood vector; the per-peer cap on each of them doesn't help if there are enough of them.

### Failure responses

- **Per-peer bucket trip.** The peer is reported as misbehaving. If the cumulative misbehavior score crosses the ban threshold, the peer is banned (see below). The message is dropped.
- **Aggregate bucket trip.** The connection is closed **without** reporting misbehavior. The peer is not banned. The reason for the difference: a peer behind a shared NAT can trip the aggregate budget through no fault of its own, and banning its IP would punish every peer behind the same NAT. The correct response is to shed the message and close the connection, not to blacklist.

Both buckets are disabled by setting burst and refill to zero. In that case, no message is ever rate-limited.

## Peer management

### The address book

The address book is a persistent list of `(ip, port)` pairs, stored at `<data_dir>/p2p_addresses.txt`. It's populated from:

- The seed list at startup.
- `Peers` messages received from other nodes.

The book is saved periodically (every 30 seconds via the maintenance timer) and on shutdown. It's purged of entries that haven't been seen in 7 days.

When the manager needs to dial new peers, it picks a random selection from the address book, avoiding entries that are banned or already connected. The selection is over-fetched (2× the needed count) to account for candidates that fail the ban or already-connected check.

### The ban list

The ban list is a persistent record of misbehaving peers, stored at `<data_dir>/p2p_bans.txt`. It's populated when a peer's cumulative misbehavior score crosses `banThreshold`.

The ban duration is `banDurationSec` (default 24 hours). Expired entries are purged periodically. Banned IPs are rejected at inbound accept time and skipped during outbound dialing.

The misbehavior score is incremented by `reportMisbehavior(score, reason)`. Typical values:

- **50** for sending a malformed sync message.
- **50** for sending a block that doesn't connect to the current head when the peer should know better.
- **100** for a failed authentication.
- **Minor increments** for rate-limit trips on the per-peer bucket.

A peer that reaches the threshold is banned immediately and closed.

### Connection maintenance

The manager maintains a target number of outbound connections (`targetOutbound`). Every 30 seconds, the maintenance timer fires and:

- Counts the current outbound connections.
- If below target, dials new peers from the address book.
- Persists the address book and ban list.
- Purges stale entries from both.

The inbound side is bounded by `maxInbound`. If the current inbound count is at the maximum, new inbound connections are accepted at the TCP level and then immediately closed. This is a defensive measure: without it, an attacker could open thousands of sockets and exhaust the file descriptor limit.

### Peer deduplication

Two nodes can end up connected by two TCP sockets if they dial each other at the same time. The deduplication logic detects this and closes one of the two connections.

The rule is based on the network nonces of the two nodes. Let `our_nonce` and `their_nonce` be the two nonces. Then:

- **The connection dialed by the lower-nonce node is kept.**
- **The other connection is closed.**

The rule is symmetric: both sides compute the same answer for the same pair of nonces and the same connection directions. If the two sides disagreed, they'd keep different connections and be unable to talk to each other.

The `shouldKeepConnection` function implements the rule. It takes a candidate peer and the local nonce, and returns true if the calling side should keep the candidate.

When a duplicate is detected:

1. The losing peer is closed with reason `"duplicate-peer"`.
2. The `established_by_pubkey_` map is updated to point at the winning peer.
3. The winner's `onEstablished` callback proceeds normally.

The losing peer's `handlePeerDisconnected` will run and clean up its own map entry, but only if the map entry still points at it (i.e., the winner hasn't already replaced it). This is what the map-entry check in `handlePeerDisconnected` protects against.

## Threading

The P2P layer has a single-threaded event loop and a small worker pool for CPU-heavy work.

- **The event loop thread** runs `io_context::run()`, which services socket reads and writes, timers, and completion handlers. All peer state (the peer table, the cipher state, the WAL) lives on this thread and is only mutated from it.
- **The worker pool** runs CPU-heavy work: deserializing large blocks, verifying proofs, computing state transitions. The worker pool's results are posted back to the event loop for further processing.
- **RPC workers** run on a separate thread pool and interact with the P2P layer only through `snapshot()` (which reads atomics) and `peerList()` (which posts to the event loop and waits).

The constraint "only the event loop touches peer state" is what makes the layer thread-safe without locks in the hot path. `snapshot()` reads atomic counters that mirror the peer table's state; `peerList()` posts a request to the event loop and waits for the reply.

The aggregate limiter is owned by the manager and shared by every peer. It's touched only from the event loop thread, which is why it has no lock. If the event loop ever ran on more than one thread, the limiter would need a mutex.

## What the network layer does not do

- **No UDP.** Every connection is TCP. Discovery is via the address book and `Peers` messages, not via UDP beacons.
- **No NAT traversal.** A peer behind a NAT cannot accept inbound connections unless the NAT is configured to forward its port. The address book doesn't do hole-punching or STUN.
- **No peer scoring beyond the ban threshold.** A peer's misbehavior score accumulates toward a ban, but there's no quality metric that influences which peers to prefer for sync or relay. The address book is picked at random.
- **No message authentication at the framing layer.** A message's magic, type, and length are plaintext and unauthenticated. The payload is encrypted and authenticated, but the framing is not. A peer that tampers with the framing gets a decode error or the wrong message type, but the protocol doesn't try to detect the tampering.
- **No persistent peer state.** A peer that disconnects is forgotten (except for the ban list). The address book persists, but the specific peer's stats, misbehavior history, and last-seen height do not.
- **No DHT.** Peer discovery is via the seed list and the `Peers` message. A peer that joins the network needs at least one seed to bootstrap; once connected, it learns other peers from the `Peers` exchange.
- **No relay prioritization.** Blocks and transactions are relayed in the order they're received, with no priority given to fees or to specific peers. All Established peers receive the same messages.