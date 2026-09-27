![Known Tests](https://img.shields.io/badge/Passing_Tests-1%2C500%20%28100%25%29-blue)

## Build

```bash
git clone https://github.com/nullcryptodev/Clarity
cd Clarity

# remove and read bugged external
rm -rf external/json
git clone --branch v3.11.3 --depth 1 https://github.com/nlohmann/json.git external/json

mkdir build

# Build Tests
# cmake -DBUILD_TESTS=ON ..
# OR just the main modules
cmake ..

make
```

Refer to [TESTING.md](https://github.com/nullcryptodev/Clarity/blob/main/TESTING.md)

## What it is

Clarity is a **single-chain, Byzantine-fault-tolerant proof-of-stake network** with a native currency ($CLRTY), a general-purpose token system, an automated market maker, a limit-order book, validator rewards with a pot mechanism, and a growing feature set around staking, validator rotation, and on-chain governance of validator sets.

It's not a fork of anything. The block format, consensus protocol, state model, and reward math are original. It uses well-known primitives (Ed25519, Blake2b, SHA-512, Keccak, ChaCha20-Poly1305) from Monocypher and standard cryptographic references.

The project is at the code-complete, pre-launch stage. The daemon builds, the full test suite passes, and the end-to-end path (from transaction submission through consensus through block application through state persistence through restart) has been exercised in development sessions. The RPC surface is complete and tested. The wallet layer (keystores, HD derivation, signing, address encoding) is complete and tested. The P2P layer has authentication, sync, block relay, transaction relay, per-peer rate limiting, and periodic refresh. It has not been deployed to a public network.

## The architecture

Ten main modules, from bottom to top:

```
Crypto           hashes, signatures, AEAD, key types
Common           encodings (Base58, Base64, hex), CRC32, JSON, varint, rate limiter
Serialization    binary, KV-binary, JSON serializers
State            MDBX storage, sparse Merkle tree, state access, proofs
Core             blocks, transactions, execution, block processing, rewards
Consensus        BFT state machine, proposer selection, message encoding
P2P              TCP transport, peer management, message framing, auth, sync, relay
Node             assembles everything into a running daemon
RPC              JSON-RPC 2.0 server, dispatcher, method handlers, encoders
Wallet           keystores, HD derivation (BIP39/SLIP10), signing, addresses
```

## Consensus: how blocks are produced

**Protocol:** A variant of BFT with three phases per round — propose, prevote, precommit. When a quorum of precommits forms on a block, it commits. The protocol tolerates `f = (n - 1) / 3` Byzantine validators, with a quorum of `n - f`. So four validators tolerate one fault (quorum 3); seven tolerate two (quorum 5); twenty-one tolerate six (quorum 15).

**Proposer selection:** `proposer = active_set[(height + round) mod active_set_size]`. Deterministic, rotates with every height and every round. The proposer builds a block, broadcasts it, and the other validators vote.

**Rounds:** If a round fails to reach quorum (proposer offline, network partition, timed-out proposal), the round number increments and a new proposer takes over. Timeouts scale exponentially with the round number, capped at a maximum. A proposal for a future round is queued and delivered when the local round advances, so a validator that's briefly behind doesn't drop the round's only proposal.

**Locking:** A validator locks on the first block it prevotes for in a round. Once locked, it can only precommit for that block or for a block at a later round that has a valid prevote quorum. This is the standard BFT safety mechanism that prevents two blocks from committing at the same height.

**Finality:** One block per round. Each committed block is final — no fork choice, no longest-chain rule, no reorgs. A block that reaches precommit quorum is the canonical block at that height.

**Validator set:** Bounded between 11 and 100. Rotates at epoch boundaries (every 60 blocks, `ROTATION_INTERVAL`). The rotation is sized to `min(ceil(n / 21), n - bftQuorum(n))` — a small enough fraction that rotation can never break quorum.

**Seed validators:** Two seed validators are defined in the regtest genesis and presumably in mainnet genesis. They are never removed from the active set regardless of uptime, stake, or liveness. This is the trust anchor for bootstrap — the seeds are expected to be operated by the project itself.

**Dry-run vs. finalized validation:** The block processor distinguishes between *simulating* a block (the proposer needs to know what state root a candidate block would produce, but the block's state root and quorum signatures aren't populated yet) and *applying* a finalized block. `BlockContext::dry_run` skips structural header checks, quorum verification, and the state-root comparison; the non-dry path runs them all. This split is load-bearing — the consensus proposer relies on it, and the test suite exercises both paths.

## State: how the chain is stored

**Storage:** MDBX, a memory-mapped key-value store. Fifteen tables: SMT nodes, SMT leaves, meta, accounts, token balances, tokens, validators, orders, three index tables (stakers, validators, order expiry), receipts, tx index, blocks by hash, blocks by height.

**State commitment:** A **sparse Merkle tree** of depth 256. Each key is a 32-byte hash (derived from an account address, token balance key, validator ID, or global state name). Each leaf commits to a value. The tree root is the state root, which is written into every block header. Any two nodes with the same state produce the same root.

**State access:** A `StateAccess` object wraps the DB and provides typed getters and setters for accounts, token balances, token metadata, validators, orders, AMM pools, AMM positions, receipts, and global state. Reads and writes go through the SMT so every change updates the root.

**Proofs:** Inclusion and non-inclusion proofs can be generated for any key. A proof is a list of sibling hashes down to the leaf; verification recomputes the root from the proof and compares. This is what a light client would need to verify that an account exists with a given balance at a given state root.

**Versioning:** The SMT can save its root at a specific version number. `rootAtVersion(n)` retrieves a historical root. What's not yet implemented: retrieving a *key's value* as it was at version `n`, and pruning historical roots.

## Transactions: what users can do

Every transaction is signed with Ed25519 by the sender, has a nonce for replay protection, a chain ID, a fee, and a type-specific payload. There are roughly fifteen transaction types:

**Native transfers.** Send CLRTY from one address to another. The `from` balance decreases by amount + fee; `to` increases by amount. Nonce bumps on success, stays on failure.

**Token operations.** Create a token with a name, symbol, decimals, max supply, optional royalty, and optional fingerprint (for bridged tokens). Mint tokens up to the max supply (creator only). Burn tokens (reduces the tracked supply). Transfer tokens. Update token metadata (creator only — changes name/symbol/royalty but not max supply).

**Staking.** Opt-in and opt-out of auto-staking. The auto-stake threshold determines when a balance becomes staked. Staked accounts are eligible for staking rewards at epoch boundaries.

**Validator operations.** Register as a validator (requires a minimum stake). Unregister (returns the stake, forbidden for seeds, forbidden if it would drop the active set below the minimum). Update reward address. Validator registration writes an index entry that maps the reward address back to the validator ID.

**AMM operations.** Create a pool for a pair of tokens (or a token and native CLRTY). Add liquidity (mints LP position). Remove liquidity (burns the position and returns the reserves). Swap through the pool with a constant-product formula and a fee.

**Limit orders.** Create an order that locks funds, specifying which token to buy, how much of it, and a minimum acceptable amount. Orders expire at a specified height. Cancel an order returns the locked funds. There is also an expiry index that tracks which orders expire at which heights.

**Claim rewards.** Move an account's pending rewards into its balance. Recomputes staked amount after the transfer.

**System transactions.** `BlockReward`, `OrderExpired`, `Slash` — used internally by the block processor to record events. Users cannot submit these.

## Economics: how value flows

**Block reward:** Each block issues a fixed reward in CLRTY. The reward splits into a validator pool (60%), a staker pool (the remaining 40%), and a producer bonus (20% of the validator pool, paid to the block's proposer).

**Validator rewards:** The validator pool is split across active validators, weighted by their `reward_multiplier`. A validator that has been penalized for infractions has a reduced multiplier. Any validator ID in the active set with no corresponding validator record has its share routed to the pot.

**Staker rewards:** The staker pool accumulates in a "pot" on a per-block basis. At each epoch boundary (every 60 blocks), the pot is drained to pay stakers a target APY. Stakers are weighted by their staked balance, with a bonus for large balances (`BALANCE_BONUS_THRESHOLD`, `BALANCE_BONUS_BPS`), and time-weighted by how long they've been staked during the epoch.

**APY mechanism:** The target APY is `base + activity + pot_bonus`. Base is a fixed 5% (`APY_BASE_BPS = 500`). Activity scales with transaction throughput, up to a cap. Pot bonus scales with how full the pot is, up to a cap. The effective APY is capped at some maximum (`APY_ACTIVITY_MAX_BPS + APY_POT_BONUS_MAX_BPS + base`, all uint16).

**Pot mechanics:** The pot accumulates 40% of each block reward as it's issued. At the epoch boundary, the protocol tries to pay stakers the target APY. If the pot doesn't have enough, it pays what it has and drains. If the pool (this epoch's 40% contribution) doesn't cover the target, the pot fills in the gap. If the pot exceeds a maximum, the excess is burned.

**Total supply:** Increases by the block reward each block. Genesis has an initial supply of 100M CLRTY on mainnet (10M on testnet, 1M on regtest). Genesis distributes to a community fund (60M), development (20M), treasury (10M), and two seed validators (5M each). Total supply grows without a cap, but the growth rate is bounded by the block reward.

**Uptime and slashing:** Each validator has an uptime score, an EMA updated based on how many pings they respond to. Below a threshold, they're removed from the active set. Infractions (proven misbehavior) reduce the validator's `reward_multiplier`, with a floor of 20%. No automatic recovery.

## Network: how nodes talk

**TCP transport** over IPv4 and IPv6. Each peer connection goes through a handshake: exchange version messages, verify protocol compatibility, exchange a signed challenge, exchange addresses. Once established, peers route messages by type — proposals, votes, transactions, block announcements, sync requests, and peer address requests.

**Message framing:** 10-byte header (4-byte magic, 2-byte type, 4-byte length) followed by an opaque payload. Magic is chain-ID-based, so peers on different networks don't connect. Max message size is 16 MiB.

### P2P layer

**Handshake.** After TCP connect, the two peers exchange `Version` messages (protocol version, network nonce, agent string, best chain height, listen port). They then exchange `Verack` acknowledgements. Finally, they exchange `Auth` messages — a signed challenge-response that proves possession of the public key declared in the message.

**Authentication.** Every peer must complete the `Auth` exchange before reaching `Established`. The challenge is `Blake2b(initiator_nonce || responder_nonce || pubkey)`, so a signature captured from one session can't be replayed in another. The pubkey is bound to the peer's validator ID by looking up the validator whose `reward_address` matches — a non-validator peer is still authenticated but claims `validator_id = 0`. Failed auth is an immediate ban. Peers are not encrypted; a MITM can drop or substitute messages but cannot forge signatures.

**Sync.** A peer that falls behind catches up via `GetHeaders` / `Headers` / `GetBlocks` / `Blocks`. The `SyncManager` per peer drives a small state machine — request headers, receive them, request blocks, apply them, repeat — bounded by `MAX_HEADERS_PER_REQUEST = 2000` and a computed `MAX_BLOCKS_PER_REQUEST` that fits in one message. Blocks are applied through `Node::applyCommittedBlock`, the same path consensus uses, so sync and consensus stay consistent. Requests time out (30 s for headers, 60 s for blocks); timeouts score the peer but don't disconnect.

**Idle refresh.** A `SyncManager` that's caught up periodically re-issues `GetHeaders` (default every 30 s) so that a peer that commits new blocks while we're Idle is discovered without needing a relay message. This is what makes a node self-heal after briefly falling behind.

**Block relay.** After a validator commits a block, it broadcasts the full serialized block to every `Established` peer. Recipients apply it if it's the next block, then re-broadcast. A node that already has the block drops it silently — this is what breaks the propagation loop. A block that doesn't connect to the current head is dropped; sync fills the gap.

**Transaction relay.** A node that accepts a transaction into its mempool broadcasts it. Recipients add it and re-broadcast. A node that already has the tx (`mempool_->contains(txid)`) drops it silently — same loop-breaking discipline as block relay. This is what lets a non-validator node submit a transaction to the network.

**Rate limiting.** Each peer has a token bucket for its message stream, plus a stricter separate bucket for consensus messages. The cost per message reflects the asymmetry of work — `GetHeaders` costs 20 tokens, `Tx` costs 5, control messages cost 1, consensus messages use the separate bucket. A peer that floods expensive-to-serve messages is cut off and disconnected. The RPC layer has its own per-source-IP token bucket with the same `Common::RateLimiter`.

**Peer management:** An address book stores known peers, persisted to disk. A ban list records misbehaving peers, with a threshold at which they're banned. Outbound connection maintenance dials enough peers to maintain a target. The manager also handles inbound connections up to a maximum.

**Self-connection prevention:** Each node generates a random 64-bit network nonce at startup. The nonce is exchanged during handshake. If a node receives a version message with its own nonce, it closes the connection — it has dialed itself.

## RPC: how clients talk

**JSON-RPC 2.0** over HTTP. The dispatcher accepts single requests and batches, handles notifications, and routes by method name. Every method is registered with a handler that receives `(Node&, RpcConfig&, JsonRpcRequest&)` and returns a `Json` result or throws an `RpcMethodError`.

**Encoders** produce the wire format. Numbers on the wire are `"0x"`-prefixed hex strings to avoid JS precision loss above 2^53. Addresses are Bech32m (`clrty1...`, `tclrty1...`, `rclrty1...`) for the same reason every user-facing surface in the codebase uses Bech32m. Hashes and signatures are `"0x"`-prefixed hex. Raw hex addresses are accepted on input for tooling.

**Methods** cover chain (`clrty_chainId`, `clrty_blockNumber`, `clrty_getBlockByNumber`, `clrty_getBlockByHash`, `clrty_getBlockHeaderByNumber`, `clrty_getStateRoot`, `clrty_methods`), state (`clrty_getBalance`, `clrty_getAccount`, `clrty_getNonce`, `clrty_getTokenInfo`, `clrty_getTokenSupply`), transactions (`clrty_sendRawTransaction`, `clrty_getTransactionByHash`, `clrty_getTransactionReceipt`, `clrty_simulateTransaction`), mempool (`clrty_getMempoolStats`, `clrty_getMempoolTx`), consensus (`clrty_getValidators`, `clrty_getValidator`, `clrty_getActiveSet`, `clrty_getConsensusState`), AMM (`clrty_getPool`, `clrty_getPosition`, `clrty_getPositionByOwner`), orders (`clrty_getOrder`, `clrty_getOrdersExpiringAt`), node (`clrty_ping`, `clrty_status`, `clrty_health`, `clrty_getPeers`, `clrty_getConfig`), and admin (`clrty_shutdown`, `clrty_setLogLevel`).

**Ethereum-style shims:** `web3_clientVersion`, `net_version`, `net_peerCount`, `net_listening` are implemented for tooling that probes these before deciding whether the endpoint is a chain.

**Error responses** use JSON-RPC standard codes for `InvalidRequest`, `MethodNotFound`, `InvalidParams`, `InternalError`, plus a project-specific range (`BlockNotFound`, `TransactionNotFound`, `ReceiptNotFound`, `PoolNotFound`, `OrderNotFound`, `ValidatorNotFound`, `TokenNotFound`, `TxMalformed`, `ChainReadInternal`, `StateReadInternal`, `Unauthorized`, etc.). The `InternalError` catch path in the dispatcher swallows exception text — a deliberate v1 choice documented in the code.

**Admin methods** require a bearer token in the `Authorization` header. The token is threaded through a thread-local set by `HttpConnection` before dispatch, since `JsonRpcRequest` doesn't carry transport-level data. An empty `admin_token` in the config means admin methods aren't registered at all.

**Rate limiting:** per-source-IP token bucket, applied at accept time before the request is dispatched to a worker. Configurable via `rate_limit_burst` and `rate_limit_per_second`; both zero disables. Oversize or malformed requests are rejected with 400; rate-limited requests get a 429.

## Wallet: how keys are managed

**Keystores** are encrypted JSON files. Each file contains an Argon2id or PBKDF2-derived key, a ChaCha20-Poly1305 ciphertext of the seed material, a MAC, a nonce, a salt, an optional user label, and the seed fingerprint. The format is versioned and validated on load; tampered ciphertext, MAC, nonce, salt, or AAD is rejected at unlock.

**HD derivation** follows BIP39 for mnemonic-to-seed and SLIP-10 for the derivation path. Default path is `m/44'/coin_type'/account'/change/index`, with coin type derived from the network. The derived key is an Ed25519 keypair used for signing transactions and for the corresponding Bech32m address.

**Signing:** A `LocalSigner` wraps an unlocked keystore and registers derived keys by public key. `sign(hash)`, `signAtPath(path, hash)`, and `signBatch` produce Ed25519 signatures. All signing fails while the keystore is locked, and a derived key that hasn't been registered can't be signed with (the signer refuses rather than deriving on the fly).

**Address codec:** Bech32m with distinct HRPs per network (`clrty`, `tclrty`, `rclrty`). Decoding is strict: mixed case rejected, wrong network rejected, tampered checksum rejected. Addresses are 32-byte Ed25519 public keys with a one-byte witness version prefix.

**Fingerprint:** A stable, per-mnemonic identifier computed from the seed, used to detect when a keystore file's declared fingerprint doesn't match the one derived on unlock. This catches accidental keystore swaps or restores.

**Node identity:** Every node has a *node key* used to sign the P2P auth exchange. On a validator node, this is the validator's signing key. On a non-validator, it's a per-node key that's generated on first startup and persisted at `<data_dir>/node_key` with restrictive permissions. The key is stable across restarts, so the ban list and per-peer reputation have something to bind to.

**Address book pattern:** The wallet layer supports the operations you'd need for an address book — multiple keystores, independent derivation paths, labels — but the CLI is not part of this repository. Integrators use the library.

## What's notably absent

**No persistent mempool.** Pending transactions are lost on restart. Peers re-broadcast their pending transactions on reconnect, so the network recovers the important ones — but a transaction submitted immediately before a restart may be gone until someone re-submits it.

**No versioned state *queries*.** `rootAtVersion(n)` retrieves a historical root, but you cannot retrieve a *key's value* at version `n`. This makes it impossible to answer "what was this account's balance at block 1000?" against the SMT alone. A block-explorer-style service would need to maintain its own historical index.

**No historical pruning.** Every state is retained. The DB grows unboundedly. Fine for a small network, not for a long-running one. The SMT has a `prune` hook that isn't wired up.

**No divergence detection or repair.** With the atomic commit discipline (state writes, block index writes, and head update in one MDBX transaction), divergence shouldn't be possible. But if it happened — from a bug, or from a partially-written restart — the node has no detection or recovery path.

**No light client mode.** Full nodes only. The SMT proof machinery exists and is exercised in tests, but there's no P2P message type for requesting or delivering proofs. Light-client support would need a `GetProof`/`Proof` message pair on top of the existing encoder.

**No order matching engine.** Orders are stored, indexed by expiry, and can be cancelled — but nothing *fills* them. There is no code that matches buys against sells, no partial-fill logic, no price-time priority queue. The order book exists in the state model but not in the execution model. This is the single largest feature gap.

**No AMM pool close.** Pools are permanent. There's no "remove all liquidity and close pool" operation. A creator who wants to stop market-making can drain the pool to zero liquidity, but the pool record stays.

**No P2P encryption.** Authentication is done — every peer proves possession of its key. But the channel itself is plaintext. A MITM can drop messages or substitute them; they can't forge signatures, but they can cause liveness failures. An authenticated-encryption layer (Noise, or a simple ECDH + ChaCha20-Poly1305 wrap) would close this.

**No aggregate rate limiting at the P2P layer.** Each peer is limited individually, but 100 peers each at their per-peer cap can collectively saturate the io_context thread's serving capacity. An aggregate cap ("no more than N headers served per second across all peers") would close this.

**No RPC authentication beyond the admin token.** Read methods are unauthenticated. If the RPC endpoint is exposed to the public internet, anyone can query balances, blocks, and state roots. That's usually fine for a public node; it becomes a problem if the RPC endpoint is also used as a control plane.

**No metrics endpoint.** There's no Prometheus exporter, no `/metrics`, no structured healthcheck. Operators get logs.

**No automatic key rotation for validators.** A validator's signing key is its reward address, and neither changes during operation. Key compromise means the operator has to unregister, re-register with a new key, and re-earn their uptime score.

**No slashing for equivocation.** Infractions reduce `reward_multiplier`, but there's no stake-slashing mechanism. A validator that signs two blocks at the same height loses rewards but keeps their stake. This is a deliberate v1 trade-off; production BFT chains generally slash.

**No genesis-hash pinning.** Genesis is computed deterministically from `GenesisConfig`, but the resulting hash isn't hardcoded. A change to genesis construction (a field added, a field reordered) will produce a different genesis, and existing databases are rejected with "chain ID mismatch" rather than "genesis mismatch." Pinning the hash would catch this at build time.

**No wallet CLI.** The wallet layer is a library. There's no `clarity-wallet` binary, no interactive key management, no transaction signing UI, no address book management. Integrators drive the library directly.

## Design choices worth noting

**Base58 is CryptoNote-style, not Bitcoin-style.** The test file explicitly notes this. Addresses produced by Clarity are not interoperable with external Base58 tools. This is a legacy surface — the RPC and wallet layers emit Bech32m — but any code that still uses the Base58 encoder would need to migrate before clients expect external interoperability.

**Full nodes only.** The SMT proof machinery exists but isn't wired to a light-client protocol. Proofs are generated and verified in tests, but there's no P2P message type for requesting or delivering them.

**One block per round, immediate finality.** No fork choice, no probabilistic finality, no reorgs. Simpler than Bitcoin-style consensus and matches the BFT model, but the network can't make progress if fewer than `bftQuorum` validators are online.

**Reward distribution is epoch-based for stakers, block-based for validators.** Validators get paid every block. Stakers get paid every epoch (60 blocks). Keeps the per-block state transition cheap and defers the expensive iteration to the epoch boundary.

**Pot mechanism as a smoothing buffer.** The pot accumulates staker rewards when activity is low and releases them when activity is high. Decouples the staker payout from the current block's activity, giving a more stable APY.

**Validator rotation is bounded by BFT safety.** `computeRotationCount` never removes more validators than would keep the remaining set above quorum. A validator set of 4 can rotate at most 1 per epoch; a set of 100 can rotate up to 33. Rotation is gradual by design.

**Wire codec is a codec, not a validator.** `BlockHeader::deserialize` round-trips bytes without applying consensus rules. `isWellFormed` is a separate, explicit step the acceptance path runs. This matters for three reasons: historical blocks remain readable if rules change, diagnostic tools can inspect malformed blocks without satisfying consensus rules, and test fixtures can construct blocks whose fields aren't all populated yet.

**Dry-run block application.** `BlockContext::dry_run` skips structural header checks, quorum verification, and the state-root comparison. The proposer relies on this to simulate a candidate block before populating the state root and collecting signatures. The non-dry path runs every check.

**Genesis timestamps are fixed constants.** `GENESIS_TIMESTAMP_MS = 1767225600000ULL` (2026-01-01T00:00:00Z) is written into every network's genesis. Block timestamps are proposer-set and validated against `now + 2 seconds`.

**Timer-driven poll loops.** Both the consensus poll and the sync tick use `boost::asio::steady_timer` rather than `sleep_for` inside a posted lambda. The io_context stays free between ticks, so incoming messages are serviced immediately instead of after the current sleep finishes.

**Proposals for future rounds are queued.** A proposal for round N+1 arriving at a validator in round N is stashed and delivered when the local round advances, rather than dropped. This is what makes the round-crossing case (a validator that timed out in round N while a proposer moved on to N+1) work on a real network with jitter.

**Messages are weighted for rate limiting.** The per-peer token bucket charges by message type: cheap control messages cost 1, `Tx` costs 5, `GetHeaders` and `GetBlocks` cost 20. This reflects the asymmetry of work — a `GetHeaders` is 12 bytes on the wire but causes the server to do up to 2000 lookups. Consensus messages use a separate, stricter bucket.
