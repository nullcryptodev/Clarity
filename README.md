<img src='https://github.com/nullcryptodev/docs/blob/main/clarity/clarity-wide.png?raw=true'>

# Clarity - Authority rotates, the chain doesn't.

![Known Tests](https://img.shields.io/badge/Known_Tests-1%2C853-blue) ![Stage](https://img.shields.io/badge/Stage-Development-orange) ![Net](https://img.shields.io/badge/Network-REGTEST-blue) <a href="https://discord.gg/gGjnyvxwFp" target="_blank">![Discord](https://img.shields.io/badge/Discord-Join-purple)</a>

#### Documents

- [Economics of Clarity](https://github.com/nullcryptodev/Clarity/blob/main/ECONOMICS.md)
- [Setup Clarity REGTEST](https://github.com/nullcryptodev/Clarity/blob/main/SETUP-REGTEST.md)
- [Clarity Metrics Reference](https://github.com/nullcryptodev/Clarity/blob/main/METRICS.md)

#### Table of Contents

- [What it is](#what-it-is)
- [The architecture](#the-architecture)
- [Build](#build)
- [Tests](#tests)
- [**Consensus**: how blocks are produced](#consensus-how-blocks-are-produced)
  - [Protocol](#protocol)
  - [Proposer selection](#proposer-selection)
  - [Rounds](#rounds)
  - [Locking](#locking)
  - [Finality](#finality)
  - [Validator Set](#validator-set)
  - [Seed Validators](#seed-validators)
  - [Dry-run vs. finalized validation](#dry-run-vs-finalized-validation)
- [**State**: how the chain is stored](#state-how-the-chain-is-stored)
  - [Storage](#storage)
  - [State Commitment](#state-commitment)
  - [State Access](#state-access)
  - [Proofs](#proofs)
  - [Versioning](#versioning)
- [**Transactions**: what users can do](#transactions-what-users-can-do)
  - [Native Transfers](#native-transfers)
  - [Token Operations](#token-operations)
  - [Staking](#staking)
  - [Validator Operations](#validator-operations)
  - [AMM Operations](#amm-operations)
  - [Limit Orders](#limit-orders)
  - [Claim Rewards](#claim-rewards)
  - [System Transactions](#system-transactions)
- [**Validator identity**: two keys, two roles](#validator-identity-two-keys-two-roles)
  - [Consensus Key](#consensus-key)
  - [Reward Address](#reward-address)
  - [Tooling](#tooling)
- [**Network**: how nodes talk](#network-how-nodes-talk)
  - [Message Framing](#message-framing)
  - [Handshake](#handshake)
  - [Authentication](#authentication)
  - [Session encryption](#session-encryption)
  - [Sync](#sync)
  - [Idle Refresh](#idle-refresh)
  - [Block Relay](#block-relay)
  - [Transaction Relay](#transaction-relay)
  - [Proof Serving](#proof-serving)
  - [Rate Limiting](#rate-limiting)
  - [Peer Management](#peer-management)
  - [Self-connection prevention](#self-connection-prevention)
- [**Metrics**: how operators watch the node](#metrics-how-operators-watch-the-node)
- [**RPC**: how clients talk](#rpc-how-clients-talk)
- [**Wallet**: how keys are managed](#wallet-how-keys-are-managed)
  - [Signing](#signing)
  - [Address Codec](#address-codec)
  - [Fingerprint](#fingerprint)
  - [CLI wallet client](#cli-wallet-client)
  - [Startup Wizard](#startup-wizard)
  - [Address book pattern](#address-book-pattern)
- [What's notably absent](#whats-notably-absent)
- [Design choices worth noting](#design-choices-worth-noting)

## What it is

Clarity is a **single-chain, Byzantine-fault-tolerant proof-of-stake network** with a native currency ($CLRTY), a general-purpose token system, an automated market maker, a limit-order book, validator rewards with a pot mechanism, and a growing feature set around staking, validator rotation, and on-chain governance of validator sets.

It's not a direct fork of anything. The block format, consensus protocol, state model, and reward math are original. It uses well-known primitives (Ed25519, X25519, Blake2b, SHA-512, XChaCha20-Poly1305) from Monocypher, the Argon2 reference implementation for keystore KDF, the BLAKE2 reference code, and a project-internal Keccak implementation verified against the official Keccak test vectors.

The project is at the code-complete, pre-launch stage. The daemon builds, the full test suite passes, and the end-to-end path (from transaction submission through consensus through block application through state persistence through restart) has been exercised on a live two-validator regtest network. The RPC surface is complete and tested. The wallet layer (keystores, HD derivation, signing, address encoding) is complete and tested, and there is an interactive CLI wallet client. The P2P layer has authentication, session encryption, sync, block relay, transaction relay, proof serving, per-peer and node-wide rate limiting, and periodic refresh. A Prometheus-compatible metrics endpoint exposes node, P2P, mempool, storage, reward, and consensus state. It has not been deployed to a public network.

## The architecture

Ten main modules, from bottom to top:

```
Crypto           hashes, signatures, AEAD, key exchange, key types
Common           encodings (Base58, Base64, hex), CRC32, JSON, varint, rate limiter, wire codec
Serialization    binary, KV-binary, JSON serializers
State            MDBX storage, sparse Merkle tree, state access, proofs, historical reads
Core             blocks, transactions, execution, block processing, rewards, equivocation proofs
Consensus        BFT state machine, proposer selection, message encoding
P2P              TCP transport, peer management, message framing, auth, session encryption,
                 sync, relay, proof serving, rate limiting
Node             assembles everything into a running daemon
RPC              JSON-RPC 2.0 server, dispatcher, method handlers, encoders, metrics endpoint
Wallet           keystores, HD derivation (BIP39/SLIP10), signing, addresses
```

Companion binaries:

```
clarityd            the daemon
clarity_wallet      client wallet
address             keystore utility: create, import, inspect
                      (derives both the reward key and the consensus key
                      from one mnemonic, prints any network's encoding)
genesis_hash        computes and verifies the pinned genesis hash per network
transaction_signer  offline wallet transaction signer
```

## Build

```bash
# Clone repo
git clone https://github.com/nullcryptodev/Clarity

# Enter cloned dir
cd Clarity

# Remove bugged external
rm -rf external/json

# Re-add bugged external
git clone --branch v3.11.3 --depth 1 https://github.com/nlohmann/json.git external/json

# Make new dir
mkdir build

# Enter build dir
cd build

# Run cmake command
cmake ..

# Run make command
make

# Enter built apps dir
cd src/Apps
```

## Tests

You can launch `clairty_tests` with the gtest filter: `./clarity_tests --gtest_filter='Consensus*'` to run tests on individual modules.

```bash
# Follow steps from Build, until cmake command

# Run cmake command
cmake -DBUILD_TESTS=ON ..

# Run make command
make

# Enter tests dir
cd src/Tests

# Run test program
./clarity_tests
```

## Consensus: how blocks are produced

#### Protocol
A variant of BFT with three phases per round -- propose, prevote, precommit. When a quorum of precommits forms on a block, it commits. The protocol tolerates `f = (n - 1) / 3` Byzantine validators, with a quorum of `(2n / 3) + 1` (integer division, i.e. the floor). So four validators tolerate one fault (quorum 3); seven tolerate two (quorum 5); twenty-one tolerate six (quorum 15).

| Validators (N) | Quorum |
| ----- | ----- |
| 1	| 1 |
| 2	| 2 |
| 3	| 3 |
| 4	| 3 |
| 5	| 4 |
| 6	| 5 |
| 7	| 5 |
| 11 | 8 |
| 21 | 15 |

#### Proposer selection
`proposer = active_set[(height + round) mod active_set_size]`. Deterministic, rotates with every height and every round. The proposer builds a block, broadcasts it, and the other validators vote.

#### Rounds
If a round fails to reach quorum (proposer offline, network partition, timed-out proposal), the round number increments and a new proposer takes over. Timeouts scale exponentially with the round number, capped at a maximum. A proposal for a future round is queued and delivered when the local round advances, so a validator that's briefly behind doesn't drop the round's only proposal.

#### Locking
A validator locks on a block when it **precommits to that block after seeing a prevote quorum (polka) for it**. The lock is set at precommit time, not prevote time, so a validator that prevoted X but never saw a polka for X is not committed to X and will prevote Y in the next round if Y is proposed. This is a **variant** of the standard Tendermint locking rule (which locks at prevote). The variant is safe -- a validator that precommits X and later precommits Y requires a higher-round polka for Y, and the safety proof holds -- but its liveness properties differ: a validator that saw a polka for X after entering precommit does *not* record it, and so doesn't prevote X in the next round. That's a rare case that delays round-crossing recovery but does not break safety.

Once locked, at prevote time the validator prevotes the locked block unless a *newer* polka (from a round strictly greater than the lock round) supersedes the lock. At precommit time it precommits the block with a polka this round, or the locked block if no new polka has formed. The lock survives round transitions within a height and is cleared only on a height change.

#### Finality
One block per round. Each committed block is final -- no fork choice, no longest-chain rule, no reorgs. A block that reaches precommit quorum is the canonical block at that height.

#### Validator set
Bounded between 11 and 100. Rotates at epoch boundaries (every 60 blocks, `ROTATION_INTERVAL`). The rotation is sized to `min(ceil(n / 21), n - bftQuorum(n))`, a small enough fraction that rotation can never break quorum. At n=100 this gives 5, not 33 -- the safety cap is `n - bftQuorum(n)` and `bftQuorum(100) = 67`, so the safety bound is 33; the epoch-proportional bound is `ceil(100/21) = 5`, and the smaller of the two wins.

#### Seed validators
Two seed validators are declared in every network's genesis (mainnet, testnet, regtest). Each seed is derived from a single BIP-39 mnemonic, which produces two independent keys:

- **Reward address**, at `m/44'/9000'/0'/0'/0'`, a bech32m address. Encoded per network (`clrty1...`, `tclrty1...`, `rclrty1...`), same underlying pubkey for all three.
- **Consensus key**, at `m/44'/9000'/0'/2'/0'`, a raw 32-byte Ed25519 key. Same value on every network -- it carries no HRP.

The two keys are independent. Rotating one does not affect the other. Both are recoverable from the same mnemonic, so backing up the words backs up both.

Seeds are never removed from the active set by normal rotation, offline removal, or unhealthy-culling. This is the trust anchor for bootstrap -- the seeds are expected to be operated by the project itself. The mainnet and testnet genesis configs are defined and pinned but the networks are not live.

#### Dry-run vs. finalized validation
The block processor distinguishes between *simulating* a block (the proposer needs to know what state root a candidate block would produce, but the block's state root and quorum signatures aren't populated yet) and *applying* a finalized block. `BlockContext::dry_run` skips structural header checks, quorum verification, and the state-root comparison; the non-dry path runs them all. This split is load-bearing -- the consensus proposer relies on it, and the test suite exercises both paths.

## State: how the chain is stored

#### Storage
MDBX, a memory-mapped key-value store. Twenty-one tables: SMT nodes, SMT leaves, meta, accounts, token balances, tokens, validators, orders, three index tables (stakers, validators, order expiry), receipts, tx index, blocks by hash, blocks by height, the persistent mempool, the consensus WAL, and four historical SMT tables (nodes-history, leaves-history, nodes-by-version, leaves-by-version).

For v1, all of these live in a single MDBX database file at `<data_dir>/state`. Chain data — block indices, block bodies, receipts, the transaction index — shares the same file as state data. There is no separate chain DB directory. This is a storage-layout decision, not a consensus-relevant one: the atomic commit discipline that writes state, block index, and head together in one transaction relies on the two being in the same MDBX instance.

#### State commitment
A **sparse Merkle tree** of depth 256. Each key is a 32-byte hash (derived from an account address, token balance key, validator ID, or global state name). Each leaf commits to a value. The tree root is the state root, which is written into every block header. Any two nodes with the same state produce the same root.

#### State access
A `StateAccess` object wraps the DB and provides typed getters and setters for accounts, token balances, token metadata, validators, orders, AMM pools, AMM positions, receipts, and global state. Reads and writes go through the SMT so every change updates the root.

#### Proofs
Inclusion and non-inclusion proofs can be generated for any key. A proof is a list of sibling hashes down to the leaf; verification recomputes the root from the proof and compares. Proofs are a pure-function construction: `verifyProof(expected_root, proof)` performs no DB access and no signature checks, so a caller that holds only a state root can verify a proof without trusting the server that produced it. Proof generation is exposed over P2P via the `GetProof`/`Proof` message pair (see [Proof Serving](#proof-serving)), over RPC via `clrty_getProof`, and in-process by tests and diagnostic tooling.

`proveAtRoot(tree, root, key)` produces a proof against an explicit root, which is what lets a node serve proofs against *historical* state, not just the current head. A proof's value and its sibling list must come from a single walk from a single root -- reading the leaf separately from the current tree would produce a proof whose value and siblings disagree whenever the requested root is historical.

#### Versioning
The SMT saves its root at every version number, and stores a historical row for each SMT node and leaf it writes at a non-zero version. `rootAtVersion(n)` retrieves a historical root, and `SparseMerkleTree::getAtVersion(key, n)` retrieves a *key's value* as it was at version `n`. Typed historical reads are exposed on `StateAccess` as `getAccountAtVersion`, `getValidatorAtVersion`, and `getGlobalAtVersion`; the raw primitive is `getRawAtVersion`, which takes the same SMT keys the current-version getters use.

Version 0 is the bootstrap version -- the state before any block has been applied -- and is not stored historically. The chain's genesis state is applied at version 0 and never queried historically, so skipping it keeps the historical tables from accumulating rows that nothing reads.

Historical storage is content-addressed and deduplicated: a node whose subtree did not change between two versions is stored once, at the version where it first appeared, and remains reachable from every later version's root. In practice this means the historical tables grow with *state changes*, not with block count or write count.

`pruneHistory(keepFrom)` deletes every historical row whose version is strictly less than `keepFrom`, from both the historical tables and their by-version indexes. Pruning is not wired into the node's normal operation -- it's available for an operator to call from a startup pass or a periodic maintenance routine, and the retention policy is a local choice (two nodes with different pruning policies still agree on consensus, because pruning only affects local historical queries).

## Transactions: what users can do

Every transaction is signed with Ed25519 by the sender, has a nonce for replay protection, a chain ID, a fee, and a type-specific payload. There are roughly fifteen transaction types:

#### Native transfers
Send CLRTY from one address to another. The `from` balance decreases by amount + fee; `to` increases by amount. Nonce bumps on success, stays on failure.

#### Token operations
Create a token with a name, symbol, decimals, max supply, optional royalty, and optional fingerprint (for bridged tokens). Mint tokens up to the max supply (creator only). Burn tokens (reduces the tracked supply). Transfer tokens. Update token metadata (creator only -- changes name/symbol/royalty but not max supply).

#### Staking
Opt-in and opt-out of auto-staking. The auto-stake threshold determines when a balance becomes staked. Staked accounts are eligible for staking rewards at epoch boundaries.

#### Validator operations
Register as a validator (requires a minimum stake). **Unregister** -- starts an unbonding countdown: the validator is removed from the active set immediately, but its record, address index, and stake persist for `UNBONDING_PERIOD` (120 blocks, two rotation intervals) before being released to the owner. The validator cannot re-register while a pending unbond is in flight, and its record remains slashable for the entire window. Unregistration is forbidden for seeds, forbidden if the *active-set* removal would drop the set below the minimum, and rejected if a pending unbond is already in progress. **Update reward address** -- changes the address where block rewards are paid, with no effect on consensus participation. Registration writes a validator-by-address index entry that maps the reward address to the validator ID.

#### AMM operations
Create a pool for a pair of tokens (or a token and native CLRTY). Add liquidity (mints LP position). Remove liquidity (burns the position and returns the reserves) -- **removing the last LP's full share closes the pool**: the record is deleted from state, and the pool no longer exists for swaps or further liquidity additions. Swap through the pool with a constant-product formula and a fee.

#### Limit orders
Create an order that locks funds, specifying which token to buy, how much of it, and a minimum acceptable amount. Orders expire at a specified height. Cancel an order returns the locked funds. There is also an expiry index that tracks which orders expire at which heights.

#### Claim rewards
Move an account's pending rewards into its balance. Recomputes staked amount after the transfer.

#### System transactions
`BlockReward`, `OrderExpired`, `Slash` -- used internally by the block processor to record events. Users cannot submit these.

## Validator identity: two keys, two roles

Every validator has two keys with independent lifecycles:

#### Consensus key
Signs proposals, prevotes, precommits, and timeout attestations. It is the validator's identity for BFT purposes and for the equivocation-proof and timeout-certificate machinery. **Immutable after registration** -- rotating it requires unregistering and re-registering, which forfeits uptime history. Held as a raw hex secret read by the daemon at startup (`--consensus-key <hex>`).

#### Reward address
The address where the validator's block rewards are paid. It is a user-facing key, normally backed by a mnemonic keystore. **Freely changeable** via the `UpdateRewardAddress` transaction, with no effect on consensus participation. The daemon never touches it.

Both keys are 32-byte Ed25519 public keys. They can be the same value -- a validator registered with a single key uses it for both roles, which is the default for the seed validators. They don't have to be, and the whole point of the split is that they don't.

The daemon resolves the signing key through `ValidatorInfo::effectiveConsensusKey()`, which returns `consensus_key` when set and falls back to `reward_address` otherwise. The fallback keeps every pre-split validator record verifiable: a validator whose `consensus_key` is null signs and verifies with its reward address, exactly as before the split. New registrations set `consensus_key = reward_address` explicitly, and the first `UpdateRewardAddress` on a legacy validator pins the current effective key so the reward address can move without rotating the signing key.

#### Tooling
A single `address` binary handles all key management for validators and users:

- `address --new -o <path>` creates a fresh keystore from a new BIP-39 mnemonic. It derives and prints both keys for all three networks in one run.
- `address --import -o <path>` creates a keystore from an existing mnemonic.
- `address --show <path>` prints every key in an existing keystore.
- `address --show --show-secret` additionally prints the raw hex secrets. This is the command to run when you need the consensus secret for the daemon's `--consensus-key` flag.
- `address --from-mnemonic "<words>"` derives and prints keys without writing a keystore.

## Network: how nodes talk

**TCP transport** over IPv4 and IPv6. Each peer connection goes through a handshake: exchange version messages, verify protocol compatibility, exchange a signed challenge-response, complete a session-key confirmation, exchange addresses. Once established, peers route messages by type -- proposals, votes, transactions, block announcements, sync requests, proof requests, and peer address requests -- over an encrypted channel.

#### Message framing
10-byte header (4-byte magic, 2-byte type, 4-byte length) followed by an opaque payload. Magic is chain-ID-based, so peers on different networks don't connect. Max message size is 16 MiB. The header is always plaintext; the payload is encrypted once the session is established (see [Session encryption](#session-encryption)).

#### Handshake
After TCP connect, the two peers exchange `Version` messages (protocol version, network nonce, agent string, best chain height, listen port). They then exchange `Verack` acknowledgements. Then they exchange `Auth` messages -- a signed challenge-response carrying both the peer's identity public key and an X25519 ephemeral public key. Finally they exchange `AuthReady` messages, which confirm that both sides derived the same session key. Only after `AuthReady` is a peer considered `Established`.

#### Authentication
Every peer must complete the `Auth` exchange before reaching `Established`. The challenge is `Blake2b(initiator_nonce || responder_nonce || identity_pubkey || ephemeral_pubkey)`, so a signature captured from one session can't be replayed in another, and a MITM cannot substitute the ephemeral key without invalidating the signature. The identity pubkey is bound to the peer's validator ID by looking up the validator whose consensus key matches -- a non-validator peer is still authenticated but claims `validator_id = 0`. Failed auth is an immediate ban.

The `Auth` message also carries an X25519 ephemeral public key, which the signature covers. This key is the input to the session-key agreement (see [Session encryption](#session-encryption)). It is generated fresh per peer connection and never persisted.

On a validator node, the daemon uses the validator's consensus key as its node identity. On a non-validator, it loads or generates a per-node key at `<data_dir>/node_key`.

#### Session encryption
After `Auth` completes, the two peers exchange an `AuthReady` message. This is the synchronization point for the encrypted session: each side sends `AuthReady` only after it has both sent and verified the peer's `Auth`, so neither side ever encrypts before the other can decrypt.

The session key is derived from `X25519(our_ephemeral_secret, their_ephemeral_public)` combined with both ephemeral public keys, both identity public keys, and both network nonces, all hashed through Blake2b with a domain separator. The result is split into two directional keys via labelled Blake2b calls -- the lower-nonce side sends under one key and receives under the other, and the roles flip on the higher-nonce side. The AAD on every AEAD frame binds the message type and the direction, so a frame cannot be replayed in the reverse direction or reframed as a different type.

`AuthReady` itself is the first encrypted message; its AEAD tag is the key-confirmation. If the two sides derive different keys (a bug, a version mismatch, or an active attacker), the tag fails to verify, and the peer is closed without a ban -- a session-key disagreement is not evidence of misbehavior.

Every message after `AuthReady` is encrypted with XChaCha20-Poly1305. Each direction has its own 8-byte counter, zero-padded to the 24-byte extended nonce, and no nonce is ever reused. The identity keys are not used for key agreement -- an ephemeral X25519 keypair per session gives forward secrecy, which a static-static exchange on the identity key would not.

#### Sync
A peer that falls behind catches up via `GetHeaders` / `Headers` / `GetBlocks` / `Blocks`. The `SyncManager` per peer drives a small state machine -- request headers, receive them, request blocks, apply them, repeat -- bounded by `MAX_HEADERS_PER_REQUEST = 2000` and a computed `MAX_BLOCKS_PER_REQUEST` that fits in one message. Blocks are applied through `Node::applyCommittedBlock`, the same path consensus uses, so sync and consensus stay consistent. Requests time out (30 s for headers, 60 s for blocks); timeouts score the peer but don't disconnect.

#### Idle refresh
A `SyncManager` that's caught up periodically re-issues `GetHeaders` (default every 30 s) so that a peer that commits new blocks while we're Idle is discovered without needing a relay message. This is what makes a node self-heal after briefly falling behind.

#### Block relay
After a validator commits a block, it broadcasts the full serialized block to every `Established` peer. Recipients apply it if it's the next block, then re-broadcast. A node that already has the block drops it silently -- this is what breaks the propagation loop. A block that doesn't connect to the current head is dropped; sync fills the gap.

#### Transaction relay
A node that accepts a transaction into its mempool broadcasts it. Recipients add it and re-broadcast. A node that already has the tx (`mempool_->contains(txid)`) drops it silently -- same loop-breaking discipline as block relay. This is what lets a non-validator node submit a transaction to the network.

#### Proof serving
A client that holds a state root can request a proof for any key at any version via `GetProof` / `Proof`. The request carries a typed descriptor -- an account address, a `(address, token id)` pair, a validator id, a global state name, or an AMM pool id -- rather than a raw SMT key, so the client never has to know how keys are derived. The server resolves the descriptor to the same 32-byte SMT key the state layer uses, walks the tree from the requested version's root, and replies with the proof *and* the root it was proven against.

The root travels with the proof because the client's verification must be self-contained: `verifyProof(expected_root, proof)` recomputes the root from the proof and compares. The client does not need to trust that the server picked the right root, because if it picked a wrong one, verification fails. This is what makes a light client possible without syncing the chain.

Proofs can be requested against the current head (a sentinel version) or against any historical version that hasn't been pruned. Non-inclusion proofs (the account is empty at that version) and inclusion proofs use the same message; the client distinguishes them by inspecting the proof's `value` field. A reply carries a status field: `Ok` when a proof was produced, `VersionUnavailable` when the requested version has no saved root, `KeyNotFound` for a server that cannot serve the key (a pruned or inconsistent DB), and `Malformed` when the request's descriptor didn't match its declared type.

Serving a proof is expensive -- a 256-level tree walk plus a ~9 KB response -- so `GetProof` carries a higher rate-limit cost than a header request, and `Proof` carries a non-trivial cost because the receiving peer still has to deserialize and re-verify the proof.

#### Rate limiting
Each peer has a token bucket for its message stream, plus a stricter separate bucket for consensus messages. The cost per message reflects the asymmetry of work -- `GetHeaders` and `GetBlocks` cost 20 tokens, `GetProof` costs 50, `Tx` costs 5, `Proof` costs 5, control messages cost 1, consensus messages use the separate bucket. A peer that floods expensive-to-serve messages is cut off and disconnected.

Above the per-peer buckets is a **node-wide aggregate bucket**. The per-peer bucket bounds what any one peer can do; it does not bound the sum: many peers each staying under their own cap can still saturate the io_context thread's serving capacity. The aggregate bucket is charged by message type at the same point the per-peer bucket is, using a separate and deliberately compressed cost table -- `GetProof` costs 10 at the aggregate level, not 50, because a single legitimate proof request should not consume an eighth of the budget. Consensus types are charged at the aggregate level even though they bypass the per-peer general bucket; a crowd of non-validators sending junk proposals is a real flood vector. A trip on the aggregate bucket closes the offending connection **without** reporting misbehavior or banning -- a peer behind a shared NAT can trip the aggregate budget through no fault of its own. Both buckets use `Common::RateLimiter`; both are disabled by setting their burst and refill to zero.

The RPC layer has its own per-source-IP token bucket with the same `Common::RateLimiter`.

#### Peer management
An address book stores known peers, persisted to disk. A ban list records misbehaving peers, with a threshold at which they're banned. Outbound connection maintenance dials enough peers to maintain a target. The manager also handles inbound connections up to a maximum.

#### Self-connection prevention
Each node generates a random 64-bit network nonce at startup. The nonce is exchanged during the Version handshake. If a node receives a Version message with its own nonce, it closes the connection -- it has dialed itself. The check is done after the Version exchange and before `Verack`, so both sides observe the nonce before either transitions to the auth phase.

## Metrics: how operators watch the node

Clarity exposes a **Prometheus-compatible metrics endpoint** on a separate port from the RPC endpoint. It is enabled by default, bound to `127.0.0.1:9100`, and speaks the Prometheus text exposition format (`text/plain; version=0.0.4`).

The endpoint lives on its own HTTP server, independent of the RPC server: a separate port, a separate worker pool, a separate rate limiter, and a separate handler. This is deliberate. RPC endpoints are frequently exposed to the public internet, and metrics endpoints frequently are not — the operator should be able to make that choice for each independently. The two also have different audiences: RPC is for application clients, metrics is for scrapers, and combining them would force both to share a policy.

**Defaults.**

```
--metrics               enable the endpoint (default: on)
--no-metrics            disable the endpoint entirely
--metrics-bind <addr>   bind address (default: 127.0.0.1)
--metrics-port <port>   listen port (default: 9100)
--metrics-include-validators
                        include per-validator metrics (default: off)
```

The per-validator block adds six time series per active validator. On a 100-validator chain that's 600 series per node, fine for a monitoring stack but wasteful for an operator who just wants to watch their own node. Off by default.

**Scraping.**

```
curl -s http://127.0.0.1:9100/metrics
```

On a two-validator regtest network with the defaults, the endpoint returns roughly 50 fixed series plus the per-validator block if it's enabled. The metric families are:

| Group | What it reports |
|---|---|
| `clrty_height`, `clrty_running`, `clrty_chain_id`, `clrty_uptime_seconds` | Node identity and liveness |
| `clrty_p2p_*` | Peer counts by direction and state, ban list size, address book size, aggregate rate-limiter config |
| `clrty_mempool_*` | Pending transaction count, byte size, fee-tier split, fee-rate min/max/avg, and cumulative accept/reject counters with a `reason` label |
| `clrty_storage_*` | On-disk database size, block count, SMT node and leaf counts |
| `clrty_pot`, `clrty_total_supply`, `clrty_total_staked`, `clrty_staker_count`, `clrty_last_effective_apy_bps`, `clrty_current_epoch`, `clrty_blocks_until_epoch` | Reward pool and staking state |
| `clrty_consensus_*`, `clrty_active_set_size` | Consensus height, round, step ordinal, proposer flag, vote counts, consecutive timeouts, emergency rotation state, active set size and quorum threshold |
| `clrty_validator_*` (opt-in) | Per-validator stake, uptime EMA, reward multiplier, cumulative rewards and blocks produced, pending unbond height |

**Failure modes.** A path other than `/metrics` returns `404`. A method other than `GET` returns `405`. If a subsystem accessor throws during rendering, the whole scrape returns `500` rather than emitting a partial body — a partial scrape would leave some metrics at their last values while others errored, and Prometheus would silently carry the stale values forward. A clean failure is the honest signal.

**Concurrency.** The scrape runs on the metrics server's worker thread, never on the P2P event loop. Every value comes from one of four sources: `Node::Status` (a value struct returned by `Node::status()`), the memory-mapped database through `StateAccess`, lock-free atomic counters on `P2PManager` (read via `snapshot()`), or value-returning accessors on `Mempool` and `BftConsensus` that take their own short-lived mutexes. None of them requires posting a request to the event loop and waiting for a reply. A scrape never blocks on the event loop, and the event loop never blocks on a scrape.

**Port collisions.** Running two daemons on one host requires each to have a distinct metrics port. The second daemon binds `9101`, the third `9102`, and so on — the same as with any other network service. The [Setup Clarity REGTEST](https://github.com/nullcryptodev/Clarity/blob/main/SETUP-REGTEST.md) guide shows this pattern for the two-validator devnet.

## RPC: how clients talk

**JSON-RPC 2.0** over HTTP. The dispatcher accepts single requests and batches, handles notifications, and routes by method name. Every method is registered with a handler that receives `(Node&, RpcConfig&, JsonRpcRequest&)` and returns a `Json` result or throws an `RpcMethodError`.

**Encoders** produce the wire format. Numbers on the wire are `"0x"`-prefixed hex strings to avoid JS precision loss above 2^53. Addresses are Bech32m (`clrty1...`, `tclrty1...`, `rclrty1...`) for the same reason every user-facing surface in the codebase uses Bech32m. Hashes and signatures are `"0x"`-prefixed hex. Raw hex addresses are accepted on input for tooling.

Validator objects returned by the consensus methods expose both `reward_address` (bech32m) and `consensus_key` (0x-prefixed hex), in addition to the existing fields.

**Methods** cover chain (`chainId`, `blockNumber`, `getBlockByNumber`, `getBlockByHash`, `getBlockHeaderByNumber`, `getStateRoot`, `methods`), state (`getBalance`, `getAccount`, `getNonce`, `getTokenInfo`, `getTokenSupply`, `getProof`), transactions (`sendRawTransaction`, `getTransactionByHash`, `getTransactionReceipt`, `simulateTransaction`), mempool (`getMempoolStats`, `getMempoolTx`), consensus (`getValidators`, `getValidator`, `getActiveSet`, `getConsensusState`), AMM (`getPool`, `getPosition`, `getPositionByOwner`), orders (`getOrder`, `getOrdersExpiringAt`), node (`ping`, `status`, `health`, `getPeers`, `getConfig`), and admin (`shutdown`, `setLogLevel`).

**Ethereum-style shims:** `web3_clientVersion`, `net_version`, `net_peerCount`, `net_listening` are implemented for tooling that probes these before deciding whether the endpoint is a chain.

**Error responses** use JSON-RPC standard codes for `InvalidRequest`, `MethodNotFound`, `InvalidParams`, `InternalError`, plus a project-specific range (`BlockNotFound`, `TransactionNotFound`, `ReceiptNotFound`, `PoolNotFound`, `OrderNotFound`, `ValidatorNotFound`, `TokenNotFound`, `TxMalformed`, `ChainReadInternal`, `StateReadInternal`, `Unauthorized`, `ProofVersionUnavailable`, `ProofNotAvailable`, etc.). The `InternalError` catch path in the dispatcher swallows exception text -- a deliberate v1 choice documented in the code.

**Admin methods** require a bearer token in the `Authorization` header. The token is threaded through a thread-local set by `HttpConnection` before dispatch, since `JsonRpcRequest` doesn't carry transport-level data. An empty `admin_token` in the config means admin methods aren't registered at all.

**Rate limiting:** per-source-IP token bucket, applied at accept time before the request is dispatched to a worker. Configurable via `rate_limit_burst` and `rate_limit_per_second`; both zero disables. Oversize or malformed requests are rejected with 400; rate-limited requests get a 429.

## Wallet: how keys are managed

**Keystores** are encrypted JSON files. Each file contains an Argon2id or PBKDF2-derived key, a ChaCha20-Poly1305 ciphertext of the seed material, a MAC, a nonce, a salt, an optional user label, and the seed fingerprint. The format is versioned and validated on load; tampered ciphertext, MAC, nonce, salt, or AAD is rejected at unlock.

**HD derivation** follows BIP39 for mnemonic-to-seed and SLIP-10 for the derivation path. Two chains are in use:

- `m/44'/9000'/account'/0'/index'` -- reward addresses (the "receive" branch).
- `m/44'/9000'/account'/2'/index'` -- validator consensus keys.

All components are hardened, since SLIP-0010 for Ed25519 requires hardened-only derivation.

#### Signing
A `LocalSigner` wraps an unlocked keystore and registers derived keys by public key. `sign(hash)`, `signAtPath(path, hash)`, and `signBatch` produce Ed25519 signatures. All signing fails while the keystore is locked, and a derived key that hasn't been registered can't be signed with (the signer refuses rather than deriving on the fly).

#### Address codec
Bech32m with distinct HRPs per network (`clrty`, `tclrty`, `rclrty`). Decoding is strict: mixed case rejected, wrong network rejected, tampered checksum rejected. Addresses are 32-byte Ed25519 public keys with a one-byte witness version prefix.

#### Fingerprint
A stable, per-mnemonic identifier computed from the seed, used to detect when a keystore file's declared fingerprint doesn't match the one derived on unlock. This catches accidental keystore swaps or restores.

#### CLI wallet client
An interactive `clarity-wallet` binary opens a keystore, connects to a node's RPC endpoint, and provides a REPL for common operations:

```
balance [address] [--verify]    show the balance of an address
nonce [address]                 show the current nonce
info                            show the open keystore's metadata
status [txid]                   show a transaction receipt
send <to> <amount> <fee>        build, sign, submit a transfer
claim <fee>                     claim pending rewards
stake <opt-in|opt-out> <fee>    toggle staking
validator info                  show the validator record for this account
validator register ...
validator update-reward ...
validator unregister ...
connect <host:port>             set the RPC endpoint
connect-peer <host:port>        set a second RPC endpoint for proof verification
open / close                    session management
```

The wallet derives keys locally, signs with the reward key, and submits via `clrty_sendRawTransaction`. It does not manage consensus keys -- those are raw hex secrets the daemon reads directly.

`balance --verify` fetches the state root from the connected node, optionally requires a second endpoint (`connect-peer`) to agree on that root, and then requests an SMT proof for the account. The proof is verified locally with `State::verifyProof` before the balance is reported, so the value comes from a proof rather than the server's word. Without a peer endpoint configured, the wallet warns that it is trusting a single server for the root. With one, two independent servers must agree before either is trusted.

#### Startup wizard
If no `--keystore` is passed, the wallet runs an interactive setup: probe the RPC endpoint (with retry/offline options), discover keystores in the working directory, confirm the selected one, and unlock it. If `--keystore` is passed, the wizard skips discovery and goes straight to unlock.

#### Address book pattern
The wallet layer supports the operations you'd need for an address book -- multiple keystores, independent derivation paths, labels -- but the CLI does not yet expose those operations. Integrators drive the library directly.

## What's notably absent

**No divergence detection or repair.** With the atomic commit discipline (state writes, block index writes, and head update in one MDBX transaction), divergence shouldn't be possible. But if it happened -- from a bug, or from a partially-written restart -- the node has no detection or recovery path.

**No order matching engine.** Orders are stored, indexed by expiry, and can be cancelled -- but nothing *fills* them. There is no code that matches buys against sells, no partial-fill logic, no price-time priority queue. The order book exists in the state model but not in the execution model. This is the single largest feature gap.

**No RPC authentication beyond the admin token.** Read methods are unauthenticated. If the RPC endpoint is exposed to the public internet, anyone can query balances, blocks, and state roots. That's usually fine for a public node; it becomes a problem if the RPC endpoint is also used as a control plane. The metrics endpoint is bound to loopback by default for the same reason, but has no authentication at all -- the design assumes that a scrape endpoint on a private interface is not a secret.

**No consensus key rotation.** A validator's consensus key is set at registration and immutable. Rotating it means unregistering and re-registering, which forfeits uptime history. This is a deliberate choice -- mutable consensus keys would invalidate every prior signature by the same validator and complicate equivocation proofs -- but it means a validator with a compromised consensus key has no recovery path short of full re-registration.

**No wallet CLI for address-book operations.** The `clarity-wallet` client covers balance, transfer, staking, and validator operations, but not multi-account management, address labels, or key rotation from the CLI. Integrators still drive those through the library.

**Historical pruning is not wired into the node.** `pruneHistory` is implemented and callable, but no startup path or config flag invokes it. The retention policy -- how far back to keep history, whether to prune on startup or periodically -- is left to the operator. This is a deliberate choice: pruning affects local historical queries but not consensus, so two nodes with different retention policies still agree on the chain.

**AMM positions are not deleted when a pool closes.** When the last LP drains a pool, the pool record is deleted but the zeroed `AmmPosition` record persists. It is unreachable from any index (the position index was removed in the same operation), so it is invisible to any caller that doesn't already know its id -- but it costs 64 bytes per position ever created, and a `forEachPosition`-style scan would surface them. Cleaning them up would require either a `pool_id -> [position_ids]` index or a scan bounded by how many LPs the pool ever had. Neither is worth the code today; the historical SMT already preserves the fact that the position existed.

**The wallet uses RPC-proxied proofs, not the P2P protocol.** `balance --verify` requests a proof over the `clrty_getProof` RPC method and verifies it locally against a state root the wallet obtained from (optionally two) RPC endpoints. The proof itself is verified with the same `State::verifyProof` function a light client would use, so a server that lies about a balance produces a failing proof. But the *root* comes from the RPC endpoint, not from the chain -- a client that doesn't want to trust any RPC endpoint at all would need to fetch headers over P2P, follow the header chain, and obtain the current root independently. That's the `GetHeaders`/`Headers` P2P pair plus header-chain verification in the wallet, and it's the next step toward a full light client. The RPC path closes the "does anything use the proof protocol" gap; the P2P path would close the "is the root itself trusted" gap.

## Design choices worth noting

**Base58 is CryptoNote-style, not Bitcoin-style.** The test file explicitly notes this. Addresses produced by Clarity are not interoperable with external Base58 tools. This is a legacy surface -- the RPC and wallet layers emit Bech32m -- but any code that still uses the Base58 encoder would need to migrate before clients expect external interoperability.

**One block per round, immediate finality.** No fork choice, no probabilistic finality, no reorgs. Simpler than Bitcoin-style consensus and matches the BFT model, but the network can't make progress if fewer than `bftQuorum` validators are online.

**Reward distribution is epoch-based for stakers, block-based for validators.** Validators get paid every block. Stakers get paid every epoch (60 blocks). Keeps the per-block state transition cheap and defers the expensive iteration to the epoch boundary.

**Pot mechanism as a smoothing buffer.** The pot accumulates staker rewards when activity is low and releases them when activity is high. Decouples the staker payout from the current block's activity, giving a more stable APY. The pot is the destination for every unallocated reward: validator pool remainders when the active set contains unknown validator IDs, reward multiplier penalty differences, seed-only set shares, and slash proceeds.

**Validator rotation is bounded by BFT safety.** `computeRotationCount` never removes more validators than would keep the remaining set above quorum. A validator set of 4 can rotate at most 1 per epoch; the cap is `n - bftQuorum(n)`, which for n=100 is 33, but the epoch-proportional bound `ceil(n/21)` gives 5 for n=100. Both bounds are applied and the smaller one wins.

**State transitions are pure functions of the block and the state they run against.** Nothing inside `applyBlock` reads wall-clock time, local peer state, or hardware entropy. This is why the emergency rotation decision lives in the block header rather than a per-node timer: a node can look at its own clock to decide *whether* to stamp the flag, but only the *value* it stamped goes into the block, and only the block feeds the state.

**Wire codec is a codec, not a validator.** `BlockHeader::deserialize` round-trips bytes without applying consensus rules. `isWellFormed` is a separate, explicit step the acceptance path runs. This matters for three reasons: historical blocks remain readable if rules change, diagnostic tools can inspect malformed blocks without satisfying consensus rules, and test fixtures can construct blocks whose fields aren't all populated yet.

**Dry-run block application.** `BlockContext::dry_run` skips structural header checks, quorum verification, and the state-root comparison. The proposer relies on this to simulate a candidate block before populating the state root and collecting signatures. The non-dry path runs every check.

**Genesis timestamps are fixed constants.** `GENESIS_TIMESTAMP_MS = 1767225600000ULL` (2026-01-01T00:00:00Z) is written into every network's genesis. Block timestamps are proposer-set and validated against `now + 2 seconds`.

**Timer-driven poll loops.** Both the consensus poll and the sync tick use `boost::asio::steady_timer` rather than `sleep_for` inside a posted lambda. The io_context stays free between ticks, so incoming messages are serviced immediately instead of after the current sleep finishes.

**Proposals for future rounds are queued.** A proposal for round N+1 arriving at a validator in round N is stashed and delivered when the local round advances, rather than dropped. This is what makes the round-crossing case (a validator that timed out in round N while a proposer moved on to N+1) work on a real network with jitter. A precommit for the *locked* block is processed at any step at or after Prevote, not only at Precommit, so a validator that locked on X in round N and is still in Propose in round N+1 will record a precommit quorum for X and commit. This is the round-crossing lock case.

**Messages are weighted for rate limiting.** The per-peer token bucket charges by message type: cheap control messages cost 1, `Tx` costs 5, `GetHeaders` and `GetBlocks` cost 20, `GetProof` costs 50. This reflects the asymmetry of work -- a `GetHeaders` is 12 bytes on the wire but causes the server to do up to 2000 lookups, and a `GetProof` causes a 256-level tree walk. Consensus messages use a separate, stricter bucket.

**Slashing is automatic, not voted.** A proof of equivocation is a mathematical fact -- two valid signatures over conflicting values at the same `(height, round)`. It isn't subject to a vote, because a Byzantine majority could vote to slash an honest validator but cannot forge a signature. Automatic application means the safety argument of BFT is economically enforced: a validator that equivocates loses stake and earnings, regardless of what the other validators think about it.

**Evidence is erased on commit, by every node.** When a block containing a Slash tx commits, every node scans the block's transactions, decodes each Slash tx, and erases matching evidence from its own pending list. Not just the proposer -- every node. Only the proposer knows what it *tried* to include; a non-proposer only sees the block. Reading the block as the source of truth is what keeps all nodes in sync. Evidence is recorded only when both votes' signatures verify. A forged conflict is dropped rather than stored, because unverifiable evidence poisons the proposer's buffer and blocks it from proposing.

**Policy rejection is not a block-level error.** A system transaction whose target is ineligible for the operation -- a Slash tx against a seed, an unregistered validator, or a validator with nothing left to slash -- is a no-op at the transaction level, not a block rejection. The distinction is load-bearing: if ineligibility rejected the block, a proposer could halt the chain by including one such transaction in every block it produced. Validity of the *evidence* is enforced upstream (`verifyEquivocationProof`); the executor only applies policy. The same principle applies to every future system-tx type.

**AMM pools auto-close on full drain.** When the last LP withdraws and both reserves reach zero, the pool record is deleted rather than left in a zero-reserve state. A pool in that state is functionally inert -- `Swap` divides by a zero reserve, `AddLiquidity` rejects it -- and leaving the record behind would make callers special-case a state they can never usefully act on. Removing the record is what makes "remove all liquidity" mean "the pool no longer exists." Historical reads are unaffected: `getAtVersion` on a closed pool's key still returns the pool at any version where it existed, so a block explorer can ask "what did pool 7 look like at block 1000?" after the pool has been closed.

**Proof serving is a pure additive protocol.** A `GetProof` request carries a typed descriptor rather than a raw SMT key -- a wallet knows an address, not a `Blake2b("acct" || address)` digest -- so the server does the key derivation. The reply carries the proof *and* the root it was proven against, so the client's `verifyProof(expected_root, proof)` call is self-contained: no DB access, no signature checks, no trust in the server's choice of root beyond what the proof itself establishes. A wrong root produces a failing verification, not a false acceptance.

Proofs can be requested against historical versions because the SMT keeps historical node rows (see [Versioning](#versioning)). A proof against a version older than the pruning horizon returns `VersionUnavailable`, which the client can distinguish from `KeyNotFound` and `Malformed`. The two-call shape -- request, then verify locally -- is what makes the protocol light-client-safe: a client that doesn't want to trust the server can send the same request to two servers and accept the result only if both produce proofs that verify against the same root.

**A proof's value and siblings come from one walk.** `proveAtRoot` walks the SMT once, from the given root, and captures both the leaf value and the sibling hashes during that walk. An earlier implementation read the leaf via `tree.get()`, which walks from the tree's *current* root -- the two walks could disagree, producing a proof whose value and siblings were inconsistent whenever the requested root was historical. The failing case is subtle and worth recording: for a single-leaf tree, the two versions' siblings happen to be identical (both `defaultHash` at every level), so only the leaf hash distinguishes them. `verifyProof(root_v1, proof)` failed while `verifyProof(root_v2, proof)` passed -- a proof that was correct in one sense and wrong in another. The fix is to produce the value and the siblings from a single walk from a single root; the invariant is now documented on `proveFromRoot`.

**Seed rewards are stipend-based, not fee-based.** When the active set contains only seeds, the producer bonus is split evenly across seeds and the set share is routed to the pot. The producing seed earns no more than any other seed -- seeds are a single operational entity, and the distinction between producing and signing is bookkeeping noise. This keeps a young chain's rewards flowing into the pot (where they eventually pay stakers) rather than concentrating in the seed operators' balances, and it preserves the incentive for new validators to register: the moment a non-seed joins the active set, normal distribution resumes.

**Consensus key and reward address are separate, and derived from one mnemonic.** A validator's signing identity and its payout destination are two different things with two different lifecycles. Both are derived from the same BIP-39 mnemonic at distinct paths -- `m/44'/9000'/0'/0'/0'` for the reward address, `m/44'/9000'/0'/2'/0'` for the consensus key -- so one backup covers both, and one restore regenerates both. The signing key is set at registration and immutable; the reward address is mutable and can be changed without touching consensus. This split is what makes `UpdateRewardAddress` safe -- before it, changing the reward address silently rotated the consensus key, which is a live-key hazard.

**Unbonding delay for departing validators.** Unregistering no longer deletes a validator's record or refunds its stake immediately. Instead, the validator leaves the active set, and its record, address index, and stake persist for `UNBONDING_PERIOD` (120 blocks, two rotation intervals) before the stake is returned. The delay serves two purposes: it makes a validator that equivocates and immediately unregisters still *slashable* for the full window in which a proof can be observed and included in a block, and it prevents a departing validator from being re-promoted into the active set while its exit is in flight. `canBeActive()` requires `pending_unbond_height == 0`, so rotation and offline removal both skip a pending-unbond validator automatically.

**Historical state is content-addressed and deduplicated.** The SMT stores a historical row for every (node-hash, version) pair that was *written* -- that is, for every node whose subtree actually changed at that version. A subtree that did not change is stored once, at the version where it first appeared, and remains reachable from every later version's root because its hash is the same. This is what makes historical reads cheap enough to enable: the tables grow with state changes, not with write volume or block count. Version 0 is the bootstrap version and is not stored -- it's the state before any block has been applied, and nothing queries it.

**Persistent mempool.** The mempool writes through to a dedicated MDBX table (`TBL_MEMPOOL`) on every mutation -- add, remove, removeIncluded, purgeExpired, clear. On startup, `Node::initMempool` rebuilds the pool by re-adding each persisted entry through the normal validation path; entries that fail (nonce too low, insufficient funds, expired, already on chain) are dropped and their rows deleted. This means a transaction submitted before a restart is still in the pool after the node comes back -- important for the case where a user submits a tx and the operator restarts their validator before the next block commits it. The persisted entry carries the full `Entry` (tx, tier, fee rate, sequence, add time), not just the transaction, so priority status and eviction ordering survive a restart.

**Command-line consensus key.** The daemon reads the validator's consensus key from `--consensus-key <hex>`. This is a development convenience for the regtest devnet, where spinning up a two-validator network from a shell script should take a few commands and no persistent state. For a production validator, a file-based flag (`--consensus-key-file`) with restrictive permissions is the recommended path and will be added before launch. The command-line form is documented in `--help` as dev-only.

**`AuthReady` is the synchronization point for encryption.** The two `Auth` messages cross on the wire, so a peer that finishes processing `Auth` may not yet have received the peer's `Auth` -- meaning it may not yet know the peer's ephemeral key, and therefore cannot yet derive the session key. The fix is a fourth handshake message, `AuthReady`, sent only after both `Auth` messages have been sent and verified. Neither side encrypts anything before sending `AuthReady`, and neither accepts anything encrypted before receiving the peer's. The message itself is empty; its AEAD tag is the confirmation that the two sides derived the same key from the same inputs. A wrong key produces a failing AEAD, not a false acceptance, so key disagreement is detected at the earliest possible point and before any application data flows.

**Directional session keys, not a shared one.** The session key agreement produces two keys, not one. The lower-nonce side sends under one and receives under the other; the higher-nonce side does the reverse. This is not strictly necessary for confidentiality -- a single shared key with a per-direction nonce counter is also safe -- but it removes the class of bug where the two directions accidentally share a nonce space. The AAD additionally binds a direction tag, so a frame reflected back to its sender fails authentication even if the nonce and key happened to collide. The cost is one extra Blake2b call per session, which is free in any accounting that matters.

**The aggregate rate-limiter cost table is deliberately not `messageCost`.** The per-peer bucket assigns `GetProof` a cost of 50 because serving one proof is roughly 50× a control message. At the aggregate level that ratio is wrong: a single legitimate proof request would consume 20% of a modest aggregate budget and starve header sync. The aggregate table compresses the ratio -- `GetProof` is 10, `GetHeaders`/`GetBlocks` are 5, relay and consensus types are 3, control is 1 -- so expensive work is shed first without letting one legitimate request dominate. The two tables are in separate translation units (`MessageTypes.cpp` and `AggregateLimiter.cpp`) so a future edit to one cannot silently change the other.

**Metrics is a pull, not a push.** The node never sends metrics anywhere. A Prometheus-compatible scraper asks for them, and the node answers. That means the metrics endpoint is bounded by what a scraper can request, not by what the node chooses to send — an unreachable monitoring system causes zero work at the node. The alternative, push-based metrics, adds failure modes (what happens when the push target is down? buffer? drop? back off?) that a scrape-driven endpoint simply doesn't have. This is not a novel design; it's the same reason Prometheus exists, and Bitcoin Core, geth, and Erigon all follow it.

**The scrape path reads through `Node::status()`, not from the event loop.** Every metric the handler emits comes from one of four sources: `Node::Status` (a value struct), the memory-mapped database (through `StateAccess`), lock-free atomics on `P2PManager`, or value-returning accessors on `Mempool` and `BftConsensus` that take their own short-lived mutexes. None of them requires posting a request to the P2P event loop and waiting for a reply. That's the property that keeps a metrics scrape from ever blocking on message handling, and it's why `P2PManager::snapshot()` exists — it reads atomic counters rather than iterating the peer table, which is only safe from the event loop. `P2PManager::peerList()`, which does post to the event loop, is deliberately **not** called by the metrics handler.

**Each handler owns its own method contract.** The HTTP transport layer (`HttpConnection`) validates only what's universal: the HTTP version, the method is one the server speaks at all (`GET` or `POST`), and the request size is under the global limit. Everything else — which method is valid for which path, whether a body is required, what content type is acceptable — is the handler's job. This split is what makes `POST /metrics` return `405 use GET for metrics` from the metrics handler rather than `400 Content-Length is required` from the transport. The first is the correct diagnosis; the second is a true statement about a request whose real problem is that it targeted the wrong handler. `JsonRpcDispatcher` and `MetricsHandler` both implement `IHttpHandler`, both check their own method contract, and both return their own error responses for violations.

**`clrty_` is a namespace, not decoration.** Every metric name carries the `clrty_` prefix. Prometheus treats metric names as a flat global namespace across every exporter the server scrapes — `node_`, `postgres_`, `nginx_`, `ethereum_`, and so on all live in the same bag. A metric named `height` would collide with `height` from any of a dozen other exporters, and the operator would have to disambiguate every query with `{job="clarity"}`. The prefix costs a few bytes per scrape (compressed on the wire by Prometheus's default gzip) and saves the operator from writing longer queries forever. This is the same reason every well-behaved Prometheus exporter in existence prefixes its metrics.