## What it is

Clarity is a **single-chain, Byzantine-fault-tolerant proof-of-stake network** with a native currency (CLRTY), a general-purpose token system, an automated market maker, a limit-order book, validator rewards with a pot mechanism, and a growing feature set around staking, validator rotation, and on-chain governance of validator sets.

It's not a fork of anything. The block format, consensus protocol, state model, and reward math are original. It uses well-known primitives (Ed25519, Blake2b, SHA-512, Keccak, ChaCha20-Poly1305) from Monocypher and standard cryptographic references.

The project is at the code-complete, pre-launch stage. The daemon builds, all ~970 tests pass, and the end-to-end path, from transaction submission through consensus through block application through state persistence through restart, has been exercised in development sessions. It has not been deployed to a public network.

## The architecture

Eight main modules, from bottom to top:

```
Crypto           hashes, signatures, AEAD, key types
Common           encodings (Base58, Base64, hex), CRC32, JSON, varint
Serialization    binary, KV-binary, JSON serializers
State            MDBX storage, sparse Merkle tree, state access, proofs
Core             blocks, transactions, execution, block processing, rewards
Consensus        BFT state machine, proposer selection, message encoding
P2P              TCP transport, peer management, message framing
Node             assembles everything into a running daemon
```

Dependencies flow downward. Crypto depends on nothing in the codebase. Node depends on everything. Every module has its own test suite and its own `TESTING.md`.

## Consensus: how blocks are produced

**Protocol:** A variant of BFT with three phases per round, propose, prevote, precommit. When a quorum of precommits forms on a block, it commits. The protocol tolerates `f = (n - 1) / 3` Byzantine validators, with a quorum of `n - f`. So four validators tolerate one fault (quorum 3); seven tolerate two (quorum 5); twenty-one tolerate six (quorum 15).

**Proposer selection:** `proposer = active_set[(height + round) mod active_set_size]`. Deterministic, rotates with every height and every round. The proposer builds a block, broadcasts it, and the other validators vote.

**Rounds:** If a round fails to reach quorum (proposer offline, network partition, timed-out proposal), the round number increments and a new proposer takes over. Timeouts scale exponentially with the round number, capped at a maximum.

**Locking:** A validator locks on the first block it prevotes for in a round. Once locked, it can only precommit for that block or for a block at a later round that has a valid prevote quorum. This is the standard BFT safety mechanism that prevents two blocks from committing at the same height.

**Finality:** One block per round. Each committed block is final, there's no fork choice, no longest-chain rule, no reorgs. A block that reaches precommit quorum is the canonical block at that height.

**Validator set:** Bounded between 11 and 100. Rotates at epoch boundaries (every 60 blocks, inferred from `ROTATION_INTERVAL`). The rotation is sized to `min(ceil(n / 21), n - bftQuorum(n))`, a small enough fraction that rotation can never break quorum.

**Seed validators:** Two seed validators are defined in the regtest genesis and presumably in mainnet genesis. They are never removed from the active set regardless of uptime, stake, or liveness. This is the trust anchor for bootstrap, the seeds are expected to be operated by the project itself.

## State: how the chain is stored

**Storage:** MDBX, a memory-mapped key-value store. Fifteen tables: SMT nodes, SMT leaves, meta, accounts, token balances, tokens, validators, orders, three index tables (stakers, validators, order expiry), receipts, tx index, blocks by hash, blocks by height.

**State commitment:** A **sparse Merkle tree** of depth 256. Each key is a 32-byte hash (derived from an account address, token balance key, validator ID, or global state name). Each leaf commits to a value. The tree root is the state root, which is written into every block header. Any two nodes with the same state produce the same root.

**State access:** A `StateAccess` object wraps the DB and provides typed getters and setters for accounts, token balances, token metadata, validators, orders, AMM pools, AMM positions, receipts, and global state. Reads and writes go through the SMT so every change updates the root.

**Proofs:** Inclusion and non-inclusion proofs can be generated for any key. A proof is a list of sibling hashes down to the leaf; verification recomputes the root from the proof and compares. This is what a light client would need to verify that an account exists with a given balance at a given state root.

**Versioning:** The SMT can save its root at a specific version number. `rootAtVersion(n)` retrieves a historical root. What's not yet implemented: retrieving a key as it was at version `n`, and pruning historical roots.

## Transactions: what users can do

Every transaction is signed with Ed25519 by the sender, has a nonce for replay protection, a chain ID, a fee, and a type-specific payload. There are roughly fifteen transaction types:

**Native transfers.** Send CLRTY from one address to another. The `from` balance decreases by amount + fee; `to` increases by amount. Nonce bumps on success, stays on failure.

**Token operations.** Create a token with a name, symbol, decimals, max supply, optional royalty, and optional fingerprint (for bridged tokens). Mint tokens up to the max supply (creator only). Burn tokens (reduces the tracked supply). Transfer tokens. Update token metadata (creator only, changes name/symbol/royalty but not max supply).

**Staking.** Opt-in and opt-out of auto-staking. The auto-stake threshold determines when a balance becomes staked. Staked accounts are eligible for staking rewards at epoch boundaries.

**Validator operations.** Register as a validator (requires a minimum stake). Unregister (returns the stake, forbidden for seeds, forbidden if it would drop the active set below the minimum). Update reward address. Validator registration writes an index entry that maps the reward address back to the validator ID.

**AMM operations.** Create a pool for a pair of tokens (or a token and native CLRTY). Add liquidity (mints LP position). Remove liquidity (burns the position and returns the reserves). Swap through the pool with a constant-product formula and a fee.

**Limit orders.** Create an order that locks funds, specifying which token to buy, how much of it, and a minimum acceptable amount. Orders expire at a specified height. Cancel an order returns the locked funds. There is also an expiry index that tracks which orders expire at which heights.

**Claim rewards.** Move an account's pending rewards into its balance. Recomputes staked amount after the transfer.

**System transactions.** `BlockReward`, `OrderExpired`, `Slash`, used internally by the block processor to record events. Users cannot submit these.

## Economics: how value flows

**Block reward:** Each block issues a fixed reward in CLRTY. The reward splits into a validator pool (60%), a staker pool (the remaining 40%), and a producer bonus (20% of the validator pool, paid to the block's proposer).

**Validator rewards:** The validator pool is split across active validators, weighted by their `reward_multiplier`. A validator that has been penalized for infractions has a reduced multiplier. Any validator ID in the active set with no corresponding validator record has its share routed to the pot.

**Staker rewards:** The staker pool accumulates in a "pot" on a per-block basis. At each epoch boundary (every 60 blocks), the pot is drained to pay stakers a target APY. Stakers are weighted by their staked balance, with a bonus for large balances (`BALANCE_BONUS_THRESHOLD`, `BALANCE_BONUS_BPS`), and time-weighted by how long they've been staked during the epoch.

**APY mechanism:** The target APY is `base + activity + pot_bonus`. Base is a fixed 5% (`APY_BASE_BPS = 500`). Activity scales with transaction throughput, up to a cap. Pot bonus scales with how full the pot is, up to a cap. The effective APY is capped at some maximum (`APY_ACTIVITY_MAX_BPS + APY_POT_BONUS_MAX_BPS + base`, all uint16).

**Pot mechanics:** The pot accumulates 40% of each block reward as it's issued. At the epoch boundary, the protocol tries to pay stakers the target APY. If the pot doesn't have enough, it pays what it has and drains. If the pool (this epoch's 40% contribution) doesn't cover the target, the pot fills in the gap. If the pot exceeds a maximum, the excess is burned.

**Total supply:** Increases by the block reward each block. The genesis has an initial supply of 100M CLRTY on mainnet (10M on testnet, 1M on regtest). Genesis distributes to a community fund (60M), development (20M), treasury (10M), and two seed validators (5M each). Total supply grows without a cap, but the growth rate is bounded by the block reward.

**Uptime and slashing:** Each validator has an uptime score, an EMA updated based on how many pings they respond to. Below a threshold, they're removed from the active set. Infractions (proven misbehavior) reduce the validator's `reward_multiplier`, with a floor of 20%. No automatic recovery.

## Network: how nodes talk

**TCP transport** over IPv4 and IPv6. Each peer connection goes through a handshake: exchange version messages, verify protocol compatibility, exchange addresses. Once established, peers route messages by type, proposals, votes, transactions, block announcements, and peer address requests.

**Message framing:** 10-byte header (4-byte magic, 2-byte type, 4-byte length) followed by an opaque payload. Magic is chain-ID-based, so peers on different networks don't connect. Max message size is a constant.

**Consensus messages**, proposals and votes, are encoded by `Consensus/ConsensusMessage.cpp` and wrapped in P2P messages by `Node::onConsensusProposal` and `Node::onConsensusVote`.

**Peer management:** An address book stores known peers, persisted to disk. A ban list records misbehaving peers, with a threshold at which they're banned. Outbound connection maintenance dials enough peers to maintain a target. The manager also handles inbound connections up to a maximum.

**Self-connection prevention:** Each node generates a random 64-bit network nonce at startup. The nonce is exchanged during handshake. If a node receives a version message with its own nonce, it closes the connection, it has dialed itself.

**No sync protocol yet.** This is one of the significant gaps. `GetHeaders` and `GetBlocks` message types exist, but the handlers on `Node` log and ignore them. A node that's behind cannot catch up from peers; it can only produce blocks with the validators it knows about. This is fine for a small network with all validators online, but it would need to be implemented before the network could tolerate a node that's offline for a while.

## What's notably absent

Things that a production blockchain would typically have but this one doesn't:

**No P2P block sync.** A node that falls behind cannot catch up. It has to already be at the correct height, or it has to be restarted from a fresh state.

**No persistent mempool.** Pending transactions are lost on restart. In production, peers re-broadcast their pending transactions on reconnect, so the loss is transient, but a transaction submitted immediately before a restart is gone until someone re-submits it.

**No versioned state queries.** You can look up the root at a past version, but not the value of a key at a past version. This makes it hard to answer questions like "what was this account's balance at block 1000?"

**No historical pruning.** Every state is retained. This makes the DB grow unboundedly. For a small network it's fine; for a long-running one it's not.

**No `getAtVersion`.** Same as above, you can't query historical state.

**No automatic recovery from state/chain divergence.** With the atomic commit fix, divergence between state and chain head shouldn't be possible. But if it happened, say, from a bug, the node would not detect or repair it.

**No light client mode.** Full nodes only.

**No RPC interface.** No JSON-RPC, no HTTP API.

**No wallet.** Keys are managed by whoever runs the node; the codebase has no key storage, transaction signing UI, or address book.

**No order matching engine.** Orders are stored and can be cancelled, but there's no code that actually fills them by matching buys against sells. The order book is currently one-sided in the sense that orders sit until they expire. This is a real gap: the order book feature exists in the state model but not in the execution model.

**No AMM pool close.** Pools are permanent. There is no "remove all liquidity and close pool" operation.

## Design choices worth noting

**Base58 is CryptoNote-style, not Bitcoin-style.** The test file explicitly notes this. Addresses produced by Clarity are not interoperable with external Base58 tools. If the project wants wallet interoperability, this is a decision that would need revisiting.

**Full nodes only, no light clients.** The SMT proof machinery exists but isn't wired to a light-client protocol. Proofs are generated and verified in tests, but there's no P2P message type for requesting or delivering them.

**One block per round, immediate finality.** No fork choice, no probabilistic finality, no reorgs. This is simpler than Bitcoin-style consensus and matches the BFT model, but it means the network can't make progress if fewer than `bftQuorum` validators are online.

**Reward distribution is epoch-based for stakers, block-based for validators.** Validators get paid every block. Stakers get paid every epoch (60 blocks). This keeps the per-block state transition cheap and defers the expensive iteration to the epoch boundary.

**Pot mechanism as a smoothing buffer.** The pot accumulates staker rewards when activity is low and releases them when activity is high. This decouples the staker payout from the current block's activity, giving a more stable APY.

**Validator rotation is bounded by BFT safety.** `computeRotationCount` never removes more validators than would keep the remaining set above quorum. This means a validator set of 4 can rotate at most 1 per epoch, and a set of 100 can rotate up to 33. The rotation is gradual by design.

**Genesis timestamps are fixed constants.** `GENESIS_TIMESTAMP_MS = 1767225600000ULL` (2026-01-01T00:00:00Z) is written into every network's genesis. Block timestamps are proposer-set and validated against `now + 2 seconds`.
