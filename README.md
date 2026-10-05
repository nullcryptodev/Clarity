<img src='https://github.com/nullcryptodev/docs/blob/main/clarity/clarity-wide.png?raw=true'>

# Clarity

![Known Tests](https://img.shields.io/badge/Known_Tests-1%2C768-blue) ![Stage](https://img.shields.io/badge/Stage-Development-orange) ![Net](https://img.shields.io/badge/Network-REGTEST-blue)

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
  - [Emergency Rotation](#emergency-rotation)
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
- [**Economics**: how value flows](#economics-how-value-flows)
  - [Block Reward](#block-reward)
  - [Validator Pool](#validator-pool)
  - [Validator Rewards](#validator-rewards)
  - [Seed-only reward policy](#seed-only-reward-policy)
  - [Staker Rewards](#staker-rewards)
  - [APY Mechanism](#apy-mechanism)
  - [Pot Mechanics](#pot-mechanics)
  - [Total Supply](#total-supply)
  - [Uptime and Penalties](#uptime-and-penalties)
  - [Stake slashing for equivocation](#stake-slashing-for-equivocation)
  - [How equivocation is detected and slashed](#how-equivocation-is-detected-and-slashed)
  - [Timeout certificate](#timeout-certificate)
- [**Network**: how nodes talk](#network-how-nodes-talk)
  - [Message Framing](#message-framing)
  - [Handshake](#handshake)
  - [Authentication](#authentication)
  - [Sync](#sync)
  - [Idle Refresh](#idle-refresh)
  - [Block Relay](#block-relay)
  - [Transaction Relay](#transaction-relay)
  - [Rate Limiting](#rate-limiting)
  - [Peer Management](#peer-management)
  - [Self-connection prevention](#self-connection-prevention)
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

It's not a direct fork of anything. The block format, consensus protocol, state model, and reward math are original. It uses well-known primitives (Ed25519, Blake2b, SHA-512, ChaCha20-Poly1305) from Monocypher, the Argon2 reference implementation for keystore KDF, the BLAKE2 reference code, and a project-internal Keccak implementation verified against the official Keccak test vectors.

The project is at the code-complete, pre-launch stage. The daemon builds, the full test suite passes, and the end-to-end path (from transaction submission through consensus through block application through state persistence through restart) has been exercised on a live two-validator regtest network. The RPC surface is complete and tested. The wallet layer (keystores, HD derivation, signing, address encoding) is complete and tested, and there is an interactive CLI wallet client. The P2P layer has authentication, sync, block relay, transaction relay, per-peer rate limiting, and periodic refresh. It has not been deployed to a public network.

## The architecture

Ten main modules, from bottom to top:

```
Crypto           hashes, signatures, AEAD, key types
Common           encodings (Base58, Base64, hex), CRC32, JSON, varint, rate limiter, wire codec
Serialization    binary, KV-binary, JSON serializers
State            MDBX storage, sparse Merkle tree, state access, proofs, historical reads
Core             blocks, transactions, execution, block processing, rewards, equivocation proofs
Consensus        BFT state machine, proposer selection, message encoding
P2P              TCP transport, peer management, message framing, auth, sync, relay
Node             assembles everything into a running daemon
RPC              JSON-RPC 2.0 server, dispatcher, method handlers, encoders
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
transaction_signer  offline wallet transaction signer and submit if rpc
                      is connected
```

## Build

```bash
git clone https://github.com/nullcryptodev/Clarity
cd Clarity

# remove and re-add bugged external
rm -rf external/json
git clone --branch v3.11.3 --depth 1 https://github.com/nlohmann/json.git external/json

mkdir build

cmake ..

make

cd src/Apps
```

## Tests

You can launch `clairty_tests` with the gtest filter: `./clarity_tests --gtest_filter='Consensus*'` to run tests on individual modules. Refer to [TESTING.md](https://github.com/nullcryptodev/Clarity/blob/main/TESTING.md)

```bash
cmake -DBUILD_TESTS=ON ..

make

cd src/Tests

./clarity_tests
```

## Consensus: how blocks are produced

#### Protocol
A variant of BFT with three phases per round — propose, prevote, precommit. When a quorum of precommits forms on a block, it commits. The protocol tolerates `f = (n - 1) / 3` Byzantine validators, with a quorum of `⌊2n/3⌋ + 1`. So four validators tolerate one fault (quorum 3); seven tolerate two (quorum 5); twenty-one tolerate six (quorum 15).

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
A validator locks on a block when it **precommits to that block after seeing a prevote quorum (polka) for it**. The lock is set at precommit time, not prevote time, so a validator that prevoted X but never saw a polka for X is not committed to X and will prevote Y in the next round if Y is proposed. This is a **variant** of the standard Tendermint locking rule (which locks at prevote). The variant is safe — a validator that precommits X and later precommits Y requires a higher-round polka for Y, and the safety proof holds — but its liveness properties differ: a validator that saw a polka for X after entering precommit does *not* record it, and so doesn't prevote X in the next round. That's a rare case that delays round-crossing recovery but does not break safety.

Once locked, at prevote time the validator prevotes the locked block unless a *newer* polka (from a round strictly greater than the lock round) supersedes the lock. At precommit time it precommits the block with a polka this round, or the locked block if no new polka has formed. The lock survives round transitions within a height and is cleared only on a height change.

#### Finality
One block per round. Each committed block is final — no fork choice, no longest-chain rule, no reorgs. A block that reaches precommit quorum is the canonical block at that height.

#### Validator set
Bounded between 11 and 100. Rotates at epoch boundaries (every 60 blocks, `ROTATION_INTERVAL`). The rotation is sized to `min(ceil(n / 21), n - bftQuorum(n))`, a small enough fraction that rotation can never break quorum. At n=100 this gives 5, not 33 — the safety cap is `n - bftQuorum(n)` and `bftQuorum(100) = 67`, so the safety bound is 33; the epoch-proportional bound is `ceil(100/21) = 5`, and the smaller of the two wins.

#### Seed validators
Two seed validators are declared in every network's genesis (mainnet, testnet, regtest). Each seed is derived from a single BIP-39 mnemonic, which produces two independent keys:

- **Reward address**, at `m/44'/9000'/0'/0'/0'`, a bech32m address. Encoded per network (`clrty1...`, `tclrty1...`, `rclrty1...`), same underlying pubkey for all three.
- **Consensus key**, at `m/44'/9000'/0'/2'/0'`, a raw 32-byte Ed25519 key. Same value on every network — it carries no HRP.

The two keys are independent. Rotating one does not affect the other. Both are recoverable from the same mnemonic, so backing up the words backs up both.

Seeds are never removed from the active set by normal rotation, offline removal, or unhealthy-culling. This is the trust anchor for bootstrap — the seeds are expected to be operated by the project itself. The mainnet and testnet genesis configs are defined and pinned but the networks are not live.

#### Emergency rotation
If the committed set can no longer form quorum, `BftConsensus` counts consecutive round timeouts. At `EMERGENCY_ROTATION_ROUNDS` (30) the proposer assembles a **timeout certificate** — f+1 signed `TimeoutVote` attestations at rounds ≥ 30 from the committed set — and stamps `block.header.emergency_rotation` (set to the round at which the emergency was declared) plus the certificate into the block header. Every verifier reads the flag from the block, verifies the certificate against the committed set, and derives the same emergency set from `(committed_set, registry, height)`. The certificate is what makes the flag non-arbitrary: without f+1 validators attesting to the same stall, the block is rejected by every honest node. Seeds are droppable here, unlike the normal paths. When the emergency block commits, the derived set becomes the committed set. `emergency_rotation` is part of the block hash. The timeout certificate is transmitted in the header but is deliberately **excluded** from the hash, the same treatment `commit_round` and `quorum_signatures` receive — the certificate is evidence attached to the block, not part of its identity.

**The active set is a function of the block, not the local counter.** `handleProposal`, `recordVote`, `quorumThreshold`, and `mySignerIndex` all resolve the emergency flag from the block being voted on. For a vote that references a block, the flag is read from that block's header; for nil votes, from the current round's proposal; for the proposer's own proposal attempt, from the local counter, which is the only case where it's consulted. This prevents two nodes whose counters differ by one from computing different proposers. A vote's `signer_index` resolves through `active_set[signer_index]` → validator record → signing key, matching `checkQuorum`. Votes for unknown blocks buffer until the block arrives; a second vote from a known signer is routed to `recordVote` regardless, so a conflict is detectable without the block.

#### Dry-run vs. finalized validation
The block processor distinguishes between *simulating* a block (the proposer needs to know what state root a candidate block would produce, but the block's state root and quorum signatures aren't populated yet) and *applying* a finalized block. `BlockContext::dry_run` skips structural header checks, quorum verification, and the state-root comparison; the non-dry path runs them all. This split is load-bearing — the consensus proposer relies on it, and the test suite exercises both paths.

## State: how the chain is stored

#### Storage
MDBX, a memory-mapped key-value store. Twenty-one tables: SMT nodes, SMT leaves, meta, accounts, token balances, tokens, validators, orders, three index tables (stakers, validators, order expiry), receipts, tx index, blocks by hash, blocks by height, the persistent mempool, the consensus WAL, and four historical SMT tables (nodes-history, leaves-history, nodes-by-version, leaves-by-version).

#### State commitment
A **sparse Merkle tree** of depth 256. Each key is a 32-byte hash (derived from an account address, token balance key, validator ID, or global state name). Each leaf commits to a value. The tree root is the state root, which is written into every block header. Any two nodes with the same state produce the same root.

#### State access
A `StateAccess` object wraps the DB and provides typed getters and setters for accounts, token balances, token metadata, validators, orders, AMM pools, AMM positions, receipts, and global state. Reads and writes go through the SMT so every change updates the root.

#### Proofs
Inclusion and non-inclusion proofs can be generated for any key. A proof is a list of sibling hashes down to the leaf; verification recomputes the root from the proof and compares. This is what a light client would need to verify that an account exists with a given balance at a given state root.

#### Versioning
The SMT saves its root at every version number, and stores a historical row for each SMT node and leaf it writes at a non-zero version. `rootAtVersion(n)` retrieves a historical root, and `SparseMerkleTree::getAtVersion(key, n)` retrieves a *key's value* as it was at version `n`. Typed historical reads are exposed on `StateAccess` as `getAccountAtVersion`, `getValidatorAtVersion`, and `getGlobalAtVersion`; the raw primitive is `getRawAtVersion`, which takes the same SMT keys the current-version getters use.

Version 0 is the bootstrap version — the state before any block has been applied — and is not stored historically. The chain's genesis state is applied at version 0 and never queried historically, so skipping it keeps the historical tables from accumulating rows that nothing reads.

Historical storage is content-addressed and deduplicated: a node whose subtree did not change between two versions is stored once, at the version where it first appeared, and remains reachable from every later version's root. In practice this means the historical tables grow with *state changes*, not with block count or write count.

`pruneHistory(keepFrom)` deletes every historical row whose version is strictly less than `keepFrom`, from both the historical tables and their by-version indexes. Pruning is not wired into the node's normal operation — it's available for an operator to call from a startup pass or a periodic maintenance routine, and the retention policy is a local choice (two nodes with different pruning policies still agree on consensus, because pruning only affects local historical queries).

## Transactions: what users can do

Every transaction is signed with Ed25519 by the sender, has a nonce for replay protection, a chain ID, a fee, and a type-specific payload. There are roughly fifteen transaction types:

#### Native transfers
Send CLRTY from one address to another. The `from` balance decreases by amount + fee; `to` increases by amount. Nonce bumps on success, stays on failure.

#### Token operations
Create a token with a name, symbol, decimals, max supply, optional royalty, and optional fingerprint (for bridged tokens). Mint tokens up to the max supply (creator only). Burn tokens (reduces the tracked supply). Transfer tokens. Update token metadata (creator only — changes name/symbol/royalty but not max supply).

#### Staking
Opt-in and opt-out of auto-staking. The auto-stake threshold determines when a balance becomes staked. Staked accounts are eligible for staking rewards at epoch boundaries.

#### Validator operations
Register as a validator (requires a minimum stake). **Unregister** — starts an unbonding countdown: the validator is removed from the active set immediately, but its record, address index, and stake persist for `UNBONDING_PERIOD` (120 blocks, two rotation intervals) before being released to the owner. The validator cannot re-register while a pending unbond is in flight, and its record remains slashable for the entire window. Unregistration is forbidden for seeds, forbidden if the *active-set* removal would drop the set below the minimum, and rejected if a pending unbond is already in progress. **Update reward address** — changes the address where block rewards are paid, with no effect on consensus participation. Registration writes a validator-by-address index entry that maps the reward address to the validator ID.

#### AMM operations
Create a pool for a pair of tokens (or a token and native CLRTY). Add liquidity (mints LP position). Remove liquidity (burns the position and returns the reserves) — **removing the last LP's full share closes the pool**: the record is deleted from state, and the pool no longer exists for swaps or further liquidity additions. Swap through the pool with a constant-product formula and a fee.

#### Limit orders
Create an order that locks funds, specifying which token to buy, how much of it, and a minimum acceptable amount. Orders expire at a specified height. Cancel an order returns the locked funds. There is also an expiry index that tracks which orders expire at which heights.

#### Claim rewards
Move an account's pending rewards into its balance. Recomputes staked amount after the transfer.

#### System transactions
`BlockReward`, `OrderExpired`, `Slash` — used internally by the block processor to record events. Users cannot submit these.

## Validator identity: two keys, two roles

Every validator has two keys with independent lifecycles:

#### Consensus key
Signs proposals, prevotes, precommits, and timeout attestations. It is the validator's identity for BFT purposes and for the equivocation-proof and timeout-certificate machinery. **Immutable after registration** — rotating it requires unregistering and re-registering, which forfeits uptime history. Held as a raw hex secret read by the daemon at startup (`--consensus-key <hex>`).

#### Reward address
The address where the validator's block rewards are paid. It is a user-facing key, normally backed by a mnemonic keystore. **Freely changeable** via the `UpdateRewardAddress` transaction, with no effect on consensus participation. The daemon never touches it.

Both keys are 32-byte Ed25519 public keys. They can be the same value — a validator registered with a single key uses it for both roles, which is the default for the seed validators. They don't have to be, and the whole point of the split is that they don't.

The daemon resolves the signing key through `ValidatorInfo::effectiveConsensusKey()`, which returns `consensus_key` when set and falls back to `reward_address` otherwise. The fallback keeps every pre-split validator record verifiable: a validator whose `consensus_key` is null signs and verifies with its reward address, exactly as before the split. New registrations set `consensus_key = reward_address` explicitly, and the first `UpdateRewardAddress` on a legacy validator pins the current effective key so the reward address can move without rotating the signing key.

#### Tooling
A single `address` binary handles all key management for validators and users:

- `address --new -o <path>` creates a fresh keystore from a new BIP-39 mnemonic. It derives and prints both keys for all three networks in one run.
- `address --import -o <path>` creates a keystore from an existing mnemonic.
- `address --show <path>` prints every key in an existing keystore.
- `address --show --show-secret` additionally prints the raw hex secrets. This is the command to run when you need the consensus secret for the daemon's `--consensus-key` flag.
- `address --from-mnemonic "<words>"` derives and prints keys without writing a keystore.

## Economics: how value flows

#### Block reward
Each block issues a fixed reward in CLRTY. The reward splits into a validator pool (60%) and a staker pool (40%).

#### Validator pool
The validator pool splits into a producer bonus (20% of the pool, paid to the block's proposer) and a set share (80% of the pool, split across the active set).

#### Validator rewards
Under the normal path, the producer bonus goes to the proposer and the set share is split evenly across active validators, weighted by their `reward_multiplier`. A validator that has been penalized for infractions has a reduced multiplier, and the difference is routed to the pot. Any validator ID in the active set with no corresponding validator record has its share routed to the pot. Rewards are paid to each validator's `reward_address`, not its consensus key — moving the reward address redirects future rewards without affecting the validator's ability to sign.

#### Seed-only reward policy
When every validator in the active set is a seed, the normal split is replaced. The producer bonus is distributed evenly across all seeds — the producing seed earns no more than any other seed, because seeds are operated as a single entity and the distinction between producing and signing is bookkeeping noise. The entire set share (80% of the validator pool) is routed to the pot, along with the staker pool.

This is deliberate: paying seeds the full validator pool on a chain with no other validators would concentrate wealth and provide no incentive for new validators to register. The policy fires only when *every* active validator is a seed — a single non-seed in the set resumes normal distribution, so a validator that joins a seed-heavy chain starts earning its share immediately.

The degenerate case is one seed: the seed earns the full producer bonus, and the set share plus staker pool go to the pot. The invariant `validator_earnings + pot_earnings == block_reward` holds in every case.

#### Staker rewards
The staker pool accumulates in a "pot" on a per-block basis. At each epoch boundary (every 60 blocks), the pot is drained to pay stakers a target APY. Stakers are weighted by their staked balance, with a bonus for large balances (`BALANCE_BONUS_THRESHOLD`, `BALANCE_BONUS_BPS`), and time-weighted by how long they've been staked during the epoch.

#### APY mechanism
The target APY is `base + activity + pot_bonus`. Base is a fixed 5% (`APY_BASE_BPS = 500`). Activity scales with transaction throughput, up to a cap of +5% (`APY_ACTIVITY_MAX_BPS = 500`). Pot bonus scales with how full the pot is, up to a cap of +3% (`APY_POT_BONUS_MAX_BPS = 300`). The effective APY is capped at 13%. The payout is computed deterministically from the state at the epoch boundary, so the exact number a staker receives is knowable in advance. The *target* is a policy parameter, not a promise; if the pot is low the actual distribution is lower.

#### Pot mechanics
The pot accumulates 40% of each block reward as it's issued, plus the set share during seed-only blocks, plus the difference from any validator's reward multiplier penalty, plus any slash proceeds. At the epoch boundary, the protocol tries to pay stakers the target APY. If the pot doesn't have enough, it pays what it has and drains. If the pool (this epoch's 40% contribution) doesn't cover the target, the pot fills in the gap. If the pot exceeds a maximum, the excess is burned.

#### Total supply
Increases by the block reward each block. Genesis has an initial supply of 100k CLRTY on mainnet (38k to treasury, 60k to community, 1k per seed). Total supply grows without a cap, but the growth rate is bounded by the block reward.

#### Uptime and penalties
Each validator has an uptime score, an EMA updated based on how many pings they respond to. Below a threshold, they're removed from the active set. Infractions reduce the validator's `reward_multiplier`, with a floor of 20%. No automatic recovery from a multiplier penalty.

#### Stake slashing for equivocation
A validator that signs two conflicting votes at the same `(height, round)` loses 5% of its stake (`SLASH_AMOUNT_BPS = 500`). The slashed stake is credited to the staker pot. The validator's reward multiplier is also reduced by the standard penalty (`REWARD_MULTIPLIER_PENALTY`), so the economic cost is both a one-time loss of principal and a persistent reduction in future earnings. Seed validators are exempt (`SEED_SLASH_EXEMPT`).

A validator whose post-slash stake falls below `VALIDATOR_MIN_STAKE` becomes ineligible for the active set via the existing `canBeActive` check, and rotation removes it on the next epoch boundary. A validator that has requested unregistration is *not* immediately immune: its record, address index, and stake persist for the full `UNBONDING_PERIOD`, and remain slashable throughout. A proof that lands during the window is applied as normal, and the stake return at expiry is the *post-slash* amount.

#### How equivocation is detected and slashed
Nodes detect conflicting votes during the prevote phase. Both votes' signatures are verified before the conflict is recorded as evidence. A forged conflict — a second vote from a known signer with a garbage signature — is rejected rather than stored, because an unverifiable conflict would otherwise poison the proposer's evidence buffer and prevent it from proposing. A conflict whose block is not yet known is dropped and re-delivered when the block arrives. Evidence survives round and height transitions, bounded by `MAX_EQUIVOCATION_EVIDENCE` (256 entries), and the proposer includes a `TxType::Slash` transaction carrying the proof in the next block it builds. Every node independently verifies the proof during block application. Verification checks framing, `(height, round, signer)` agreement, value disagreement, signer range, validator registration, and both Ed25519 signatures over the domain-separated vote hash. A block containing an invalid Slash proof is rejected. Once a Slash tx commits, every node erases matching evidence by scanning the committed block.

Signatures are verified against `ValidatorInfo::effectiveConsensusKey()`, so a validator that has split its reward address from its consensus key remains slashable for any vote signed under its consensus key.

A Slash tx whose target is ineligible — a seed, an unregistered validator, or a validator with nothing left to slash — is a no-op at the executor level: `executeSystemSlash` returns `Success` with a zero receipt, and the block is accepted. Ineligibility is a *policy* outcome, not evidence of a malformed block. Returning `Failure` here would let a proposer halt the chain by including a Slash tx against a seed in every block it produces, because `BlockProcessor` treats a failed Slash as a block-level error. The proof's *validity* is enforced upstream: `verifyEquivocationProof` rejects an invalid proof, and the block is rejected on that basis. The distinction matters: **policy rejection must not be a block-level error.**

#### Timeout certificate
Each round that times out is attested by a broadcast `TimeoutVote` — a signature over `(height, round)` with the attesting validator's index in the committed set. A node that has timed out 30 or more consecutive rounds and holds f+1 valid attestations at a round ≥ 30 can include them in an emergency block header. A node that has not yet accumulated f+1 attestations refuses to propose an emergency block; the round stalls rather than emitting a block every verifier will reject. The certificate is verified by every node's `validateProposal` and re-verified on-chain by `BlockProcessor::applyBlock` before the emergency set is honoured. The certificate's signers are drawn from the **committed** set, since that's the set that was trying to run when the stall began; the emergency set only exists once a certificate is honoured.

## Network: how nodes talk

**TCP transport** over IPv4 and IPv6. Each peer connection goes through a handshake: exchange version messages, verify protocol compatibility, exchange a signed challenge, exchange addresses. Once established, peers route messages by type — proposals, votes, transactions, block announcements, sync requests, and peer address requests.

#### Message framing
10-byte header (4-byte magic, 2-byte type, 4-byte length) followed by an opaque payload. Magic is chain-ID-based, so peers on different networks don't connect. Max message size is 16 MiB.

#### Handshake
After TCP connect, the two peers exchange `Version` messages (protocol version, network nonce, agent string, best chain height, listen port). They then exchange `Verack` acknowledgements. Finally, they exchange `Auth` messages — a signed challenge-response that proves possession of the public key declared in the message.

#### Authentication
Every peer must complete the `Auth` exchange before reaching `Established`. The challenge is `Blake2b(initiator_nonce || responder_nonce || pubkey)`, so a signature captured from one session can't be replayed in another. The pubkey is bound to the peer's validator ID by looking up the validator whose consensus key matches — a non-validator peer is still authenticated but claims `validator_id = 0`. Failed auth is an immediate ban. Peers are not encrypted; a MITM can drop or substitute messages but cannot forge signatures.

On a validator node, the daemon uses the validator's consensus key as its node identity. On a non-validator, it loads or generates a per-node key at `<data_dir>/node_key`.

#### Sync
A peer that falls behind catches up via `GetHeaders` / `Headers` / `GetBlocks` / `Blocks`. The `SyncManager` per peer drives a small state machine — request headers, receive them, request blocks, apply them, repeat — bounded by `MAX_HEADERS_PER_REQUEST = 2000` and a computed `MAX_BLOCKS_PER_REQUEST` that fits in one message. Blocks are applied through `Node::applyCommittedBlock`, the same path consensus uses, so sync and consensus stay consistent. Requests time out (30 s for headers, 60 s for blocks); timeouts score the peer but don't disconnect.

#### Idle refresh
A `SyncManager` that's caught up periodically re-issues `GetHeaders` (default every 30 s) so that a peer that commits new blocks while we're Idle is discovered without needing a relay message. This is what makes a node self-heal after briefly falling behind.

#### Block relay
After a validator commits a block, it broadcasts the full serialized block to every `Established` peer. Recipients apply it if it's the next block, then re-broadcast. A node that already has the block drops it silently — this is what breaks the propagation loop. A block that doesn't connect to the current head is dropped; sync fills the gap.

#### Transaction relay
A node that accepts a transaction into its mempool broadcasts it. Recipients add it and re-broadcast. A node that already has the tx (`mempool_->contains(txid)`) drops it silently — same loop-breaking discipline as block relay. This is what lets a non-validator node submit a transaction to the network.

#### Rate limiting
Each peer has a token bucket for its message stream, plus a stricter separate bucket for consensus messages. The cost per message reflects the asymmetry of work — `GetHeaders` costs 20 tokens, `Tx` costs 5, control messages cost 1, consensus messages use the separate bucket. A peer that floods expensive-to-serve messages is cut off and disconnected. The RPC layer has its own per-source-IP token bucket with the same `Common::RateLimiter`.

#### Peer management
An address book stores known peers, persisted to disk. A ban list records misbehaving peers, with a threshold at which they're banned. Outbound connection maintenance dials enough peers to maintain a target. The manager also handles inbound connections up to a maximum.

#### Self-connection prevention
Each node generates a random 64-bit network nonce at startup. The nonce is exchanged during handshake. If a node receives a version message with its own nonce, it closes the connection — it has dialed itself.

## RPC: how clients talk

**JSON-RPC 2.0** over HTTP. The dispatcher accepts single requests and batches, handles notifications, and routes by method name. Every method is registered with a handler that receives `(Node&, RpcConfig&, JsonRpcRequest&)` and returns a `Json` result or throws an `RpcMethodError`.

**Encoders** produce the wire format. Numbers on the wire are `"0x"`-prefixed hex strings to avoid JS precision loss above 2^53. Addresses are Bech32m (`clrty1...`, `tclrty1...`, `rclrty1...`) for the same reason every user-facing surface in the codebase uses Bech32m. Hashes and signatures are `"0x"`-prefixed hex. Raw hex addresses are accepted on input for tooling.

Validator objects returned by the consensus methods expose both `reward_address` (bech32m) and `consensus_key` (0x-prefixed hex), in addition to the existing fields.

**Methods** cover chain (`chainId`, `blockNumber`, `getBlockByNumber`, `getBlockByHash`, `getBlockHeaderByNumber`, `getStateRoot`, `methods`), state (`getBalance`, `getAccount`, `getNonce`, `getTokenInfo`, `getTokenSupply`), transactions (`sendRawTransaction`, `getTransactionByHash`, `getTransactionReceipt`, `simulateTransaction`), mempool (`getMempoolStats`, `getMempoolTx`), consensus (`getValidators`, `getValidator`, `getActiveSet`, `getConsensusState`), AMM (`getPool`, `getPosition`, `getPositionByOwner`), orders (`getOrder`, `getOrdersExpiringAt`), node (`ping`, `status`, `health`, `getPeers`, `getConfig`), and admin (`shutdown`, `setLogLevel`).

**Ethereum-style shims:** `web3_clientVersion`, `net_version`, `net_peerCount`, `net_listening` are implemented for tooling that probes these before deciding whether the endpoint is a chain.

**Error responses** use JSON-RPC standard codes for `InvalidRequest`, `MethodNotFound`, `InvalidParams`, `InternalError`, plus a project-specific range (`BlockNotFound`, `TransactionNotFound`, `ReceiptNotFound`, `PoolNotFound`, `OrderNotFound`, `ValidatorNotFound`, `TokenNotFound`, `TxMalformed`, `ChainReadInternal`, `StateReadInternal`, `Unauthorized`, etc.). The `InternalError` catch path in the dispatcher swallows exception text — a deliberate v1 choice documented in the code.

**Admin methods** require a bearer token in the `Authorization` header. The token is threaded through a thread-local set by `HttpConnection` before dispatch, since `JsonRpcRequest` doesn't carry transport-level data. An empty `admin_token` in the config means admin methods aren't registered at all.

**Rate limiting:** per-source-IP token bucket, applied at accept time before the request is dispatched to a worker. Configurable via `rate_limit_burst` and `rate_limit_per_second`; both zero disables. Oversize or malformed requests are rejected with 400; rate-limited requests get a 429.

## Wallet: how keys are managed

**Keystores** are encrypted JSON files. Each file contains an Argon2id or PBKDF2-derived key, a ChaCha20-Poly1305 ciphertext of the seed material, a MAC, a nonce, a salt, an optional user label, and the seed fingerprint. The format is versioned and validated on load; tampered ciphertext, MAC, nonce, salt, or AAD is rejected at unlock.

**HD derivation** follows BIP39 for mnemonic-to-seed and SLIP-10 for the derivation path. Two chains are in use:

- `m/44'/9000'/account'/0'/index'` — reward addresses (the "receive" branch).
- `m/44'/9000'/account'/2'/index'` — validator consensus keys.

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
balance [address]              show the balance of an address
nonce [address]                show the current nonce
info                           show the open keystore's metadata
status [txid]                  show a transaction receipt
send <to> <amount> <fee>       build, sign, submit a transfer
claim <fee>                    claim pending rewards
stake <opt-in|opt-out> <fee>   toggle staking
validator info                 show the validator record for this account
validator register ...
validator update-reward ...
validator unregister ...
open / close / connect         session management
```

The wallet derives keys locally, signs with the reward key, and submits via `clrty_sendRawTransaction`. It does not manage consensus keys — those are raw hex secrets the daemon reads directly.

#### Startup wizard
If no `--keystore` is passed, the wallet runs an interactive setup: probe the RPC endpoint (with retry/offline options), discover keystores in the working directory, confirm the selected one, and unlock it. If `--keystore` is passed, the wizard skips discovery and goes straight to unlock.

#### Address book pattern
The wallet layer supports the operations you'd need for an address book — multiple keystores, independent derivation paths, labels — but the CLI does not yet expose those operations. Integrators drive the library directly.

## What's notably absent

**No divergence detection or repair.** With the atomic commit discipline (state writes, block index writes, and head update in one MDBX transaction), divergence shouldn't be possible. But if it happened — from a bug, or from a partially-written restart — the node has no detection or recovery path.

**No light client mode.** Full nodes only. The SMT proof machinery exists and is exercised in tests, but there's no P2P message type for requesting or delivering proofs. Light-client support would need a `GetProof`/`Proof` message pair on top of the existing encoder.

**No order matching engine.** Orders are stored, indexed by expiry, and can be cancelled — but nothing *fills* them. There is no code that matches buys against sells, no partial-fill logic, no price-time priority queue. The order book exists in the state model but not in the execution model. This is the single largest feature gap.

**No P2P encryption.** Authentication is done — every peer proves possession of its key. But the channel itself is plaintext. A MITM can drop messages or substitute them; they can't forge signatures, but they can cause liveness failures. An authenticated-encryption layer (Noise, or a simple ECDH + ChaCha20-Poly1305 wrap) would close this.

**No aggregate rate limiting at the P2P layer.** Each peer is limited individually, but 100 peers each at their per-peer cap can collectively saturate the io_context thread's serving capacity. An aggregate cap ("no more than N headers served per second across all peers") would close this.

**No RPC authentication beyond the admin token.** Read methods are unauthenticated. If the RPC endpoint is exposed to the public internet, anyone can query balances, blocks, and state roots. That's usually fine for a public node; it becomes a problem if the RPC endpoint is also used as a control plane.

**No metrics endpoint.** There's no Prometheus exporter, no `/metrics`, no structured healthcheck. Operators get logs.

**No consensus key rotation.** A validator's consensus key is set at registration and immutable. Rotating it means unregistering and re-registering, which forfeits uptime history. This is a deliberate choice — mutable consensus keys would invalidate every prior signature by the same validator and complicate equivocation proofs — but it means a validator with a compromised consensus key has no recovery path short of full re-registration.

**Emergency rotation is tested in isolation but not end to end.** The derivation, the block path, the timeout counter, the certificate verifier, vote verification, and evidence lifetime all have unit tests. What is *not* tested is a live network driving through 30 rounds of genuine stall and asserting recovery — the `ConsensusNetwork` fixture does not model offline validators or pool promotion candidates. A randomized multi-node simulator with partition and offline-node injection would close this.

**No wallet CLI for address-book operations.** The `clarity-wallet` client covers balance, transfer, staking, and validator operations, but not multi-account management, address labels, or key rotation from the CLI. Integrators still drive those through the library.

**Historical pruning is not wired into the node.** `pruneHistory` is implemented and callable, but no startup path or config flag invokes it. The retention policy — how far back to keep history, whether to prune on startup or periodically — is left to the operator. This is a deliberate choice: pruning affects local historical queries but not consensus, so two nodes with different retention policies still agree on the chain.

**AMM positions are not deleted when a pool closes.** When the last LP drains a pool, the pool record is deleted but the zeroed `AmmPosition` record persists. It is unreachable from any index (the position index was removed in the same operation), so it is invisible to any caller that doesn't already know its id — but it costs 64 bytes per position ever created, and a `forEachPosition`-style scan would surface them. Cleaning them up would require either a `pool_id → [position_ids]` index or a scan bounded by how many LPs the pool ever had. Neither is worth the code today; the historical SMT already preserves the fact that the position existed.

## Design choices worth noting

**Base58 is CryptoNote-style, not Bitcoin-style.** The test file explicitly notes this. Addresses produced by Clarity are not interoperable with external Base58 tools. This is a legacy surface — the RPC and wallet layers emit Bech32m — but any code that still uses the Base58 encoder would need to migrate before clients expect external interoperability.

**Full nodes only.** The SMT proof machinery exists but isn't wired to a light-client protocol. Proofs are generated and verified in tests, but there's no P2P message type for requesting or delivering them.

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

**Messages are weighted for rate limiting.** The per-peer token bucket charges by message type: cheap control messages cost 1, `Tx` costs 5, `GetHeaders` and `GetBlocks` cost 20. This reflects the asymmetry of work — a `GetHeaders` is 12 bytes on the wire but causes the server to do up to 2000 lookups. Consensus messages use a separate, stricter bucket.

**Slashing is automatic, not voted.** A proof of equivocation is a mathematical fact — two valid signatures over conflicting values at the same `(height, round)`. It isn't subject to a vote, because a Byzantine majority could vote to slash an honest validator but cannot forge a signature. Automatic application means the safety argument of BFT is economically enforced: a validator that equivocates loses stake and earnings, regardless of what the other validators think about it.

**Evidence is erased on commit, by every node.** When a block containing a Slash tx commits, every node scans the block's transactions, decodes each Slash tx, and erases matching evidence from its own pending list. Not just the proposer — every node. Only the proposer knows what it *tried* to include; a non-proposer only sees the block. Reading the block as the source of truth is what keeps all nodes in sync. Evidence is recorded only when both votes' signatures verify. A forged conflict is dropped rather than stored, because unverifiable evidence poisons the proposer's buffer and blocks it from proposing.

**Policy rejection is not a block-level error.** A system transaction whose target is ineligible for the operation — a Slash tx against a seed, an unregistered validator, or a validator with nothing left to slash — is a no-op at the transaction level, not a block rejection. The distinction is load-bearing: if ineligibility rejected the block, a proposer could halt the chain by including one such transaction in every block it produced. Validity of the *evidence* is enforced upstream (`verifyEquivocationProof`); the executor only applies policy. The same principle applies to every future system-tx type.

**AMM pools auto-close on full drain.** When the last LP withdraws and both reserves reach zero, the pool record is deleted rather than left in a zero-reserve state. A pool in that state is functionally inert — `Swap` divides by a zero reserve, `AddLiquidity` rejects it — and leaving the record behind would make callers special-case a state they can never usefully act on. Removing the record is what makes "remove all liquidity" mean "the pool no longer exists." Historical reads are unaffected: `getAtVersion` on a closed pool's key still returns the pool at any version where it existed, so a block explorer can ask "what did pool 7 look like at block 1000?" after the pool has been closed.

**Seed rewards are stipend-based, not fee-based.** When the active set contains only seeds, the producer bonus is split evenly across seeds and the set share is routed to the pot. The producing seed earns no more than any other seed — seeds are a single operational entity, and the distinction between producing and signing is bookkeeping noise. This keeps a young chain's rewards flowing into the pot (where they eventually pay stakers) rather than concentrating in the seed operators' balances, and it preserves the incentive for new validators to register: the moment a non-seed joins the active set, normal distribution resumes.

**Consensus key and reward address are separate, and derived from one mnemonic.** A validator's signing identity and its payout destination are two different things with two different lifecycles. Both are derived from the same BIP-39 mnemonic at distinct paths — `m/44'/9000'/0'/0'/0'` for the reward address, `m/44'/9000'/0'/2'/0'` for the consensus key — so one backup covers both, and one restore regenerates both. The signing key is set at registration and immutable; the reward address is mutable and can be changed without touching consensus. This split is what makes `UpdateRewardAddress` safe — before it, changing the reward address silently rotated the consensus key, which is a live-key hazard.

**Unbonding delay for departing validators.** Unregistering no longer deletes a validator's record or refunds its stake immediately. Instead, the validator leaves the active set, and its record, address index, and stake persist for `UNBONDING_PERIOD` (120 blocks, two rotation intervals) before the stake is returned. The delay serves two purposes: it makes a validator that equivocates and immediately unregisters still *slashable* for the full window in which a proof can be observed and included in a block, and it prevents a departing validator from being re-promoted into the active set while its exit is in flight. `canBeActive()` requires `pending_unbond_height == 0`, so rotation and offline removal both skip a pending-unbond validator automatically.

**Historical state is content-addressed and deduplicated.** The SMT stores a historical row for every (node-hash, version) pair that was *written* — that is, for every node whose subtree actually changed at that version. A subtree that did not change is stored once, at the version where it first appeared, and remains reachable from every later version's root because its hash is the same. This is what makes historical reads cheap enough to enable: the tables grow with state changes, not with write volume or block count. Version 0 is the bootstrap version and is not stored — it's the state before any block has been applied, and nothing queries it.

**Persistent mempool.** The mempool writes through to a dedicated MDBX table (`TBL_MEMPOOL`) on every mutation — add, remove, removeIncluded, purgeExpired, clear. On startup, `Node::initMempool` rebuilds the pool by re-adding each persisted entry through the normal validation path; entries that fail (nonce too low, insufficient funds, expired, already on chain) are dropped and their rows deleted. This means a transaction submitted before a restart is still in the pool after the node comes back — important for the case where a user submits a tx and the operator restarts their validator before the next block commits it. The persisted entry carries the full `Entry` (tx, tier, fee rate, sequence, add time), not just the transaction, so priority status and eviction ordering survive a restart.

**Command-line consensus key.** The daemon reads the validator's consensus key from `--consensus-key <hex>`. This is a development convenience for the regtest devnet, where spinning up a two-validator network from a shell script should take a few commands and no persistent state. For a production validator, a file-based flag (`--consensus-key-file`) with restrictive permissions is the recommended path and will be added before launch. The command-line form is documented in `--help` as dev-only.