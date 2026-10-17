# Clarity: A Byzantine-Fault-Tolerant Proof-of-Stake Chain with Native Exchange Primitives

**A technical whitepaper**

---

## Abstract

Clarity is a single-chain, Byzantine-fault-tolerant proof-of-stake network with a native currency (CLRTY), a general-purpose token system, a constant-product automated market maker, a price-time-priority limit-order book with an in-process matching engine and AMM routing for Active orders, and a first-class non-fungible-token system with optional on-chain reward schedules. It is not a fork of any existing chain: the block format, the consensus protocol, the state model, the matching engine, the routing mechanism, the NFT model, the key-rotation machinery, and the reward mathematics are original. It uses well-known cryptographic primitives (Blake2b, Ed25519, X25519, XChaCha20-Poly1305, Argon2id) from audited reference implementations.

Clarity's contribution is not a new consensus algorithm — it is a disciplined *integration*. The chain commits its entire state to a single Merkle root per block, and every state transition is a pure function of the block and the state it runs against. This single commitment makes it possible to build a set of application primitives — a native AMM, a limit-order book, a full NFT system — that are not smart contracts but *first-class state objects*, subject to the same determinism, provability, and auditability as an account balance. The result is a chain where a block's validity is a mathematical fact that any node can verify, where two nodes with the same state always agree on the root, and where the exchange primitives compose with every other part of the state without a VM, a scripting language, or interface discovery.

The protocol specification below describes the consensus, state, transaction, and application layers as they exist in the reference implementation. The reference implementation currently runs on a two-validator regtest network; the mainnet and testnet parameters are pinned but the networks are not live. This document is written for protocol engineers and auditors.

---

## Table of contents

1. Introduction
2. Threat model and assumptions
3. Architecture and core principles
4. State: commitment, storage, and proofs
5. Transactions and execution
6. Consensus
7. The application layer: AMM, order book, NFTs
8. Economics
9. Network
10. Security considerations
11. Implementation status and open questions
- Appendix A: Protocol parameters
- Appendix B: State key domain tags
- Appendix C: Genesis configuration
- Appendix D: Claims to source

---

## 1. Introduction

### 1.1 The design bet

Clarity is built on a specific bet: that a curated set of native application primitives, implemented as pure state transitions over a single committed Merkle tree, produces a better chain for exchange activity than a general-purpose smart-contract platform. The bet is not that arbitrary computation is undesirable in principle; it is that the cost of a general VM — nondeterminism, interface discovery, unbounded execution, contract-level security bugs — is not worth paying for the specific applications Clarity targets: a native currency, a token system, a limit-order book, an AMM, and NFTs with on-chain rewards.

Every feature is a typed transaction with a fixed executor handler. There is no bytecode, no storage slot abstraction, no ABI, no interface discovery, no reentrancy surface. A token is a `TokenInfo` record at a well-known SMT key. An NFT is an `NftInfo` record plus a shadow token. An AMM pool is an `AmmPool` record. A limit order is an `Order` record. The executor knows these types directly, and the state layer treats them as opaque byte blobs at their domain-separated positions. Adding a feature requires adding a record type and a transaction type, not writing a contract; adding a behavior requires a hard fork.

### 1.2 Immediate finality

Clarity's consensus is Byzantine-fault-tolerant proof-of-stake with three phases per round and immediate finality. A block commits when `2f+1` validators precommit it, where `f = (n-1)/3` is the maximum number of Byzantine validators the protocol tolerates. Once committed, a block is final: no fork choice, no longest-chain rule, no probabilistic finality, no reorg. The chain is a linear sequence of committed blocks.

The trade-off is a liveness assumption Bitcoin does not have: the chain stalls if fewer than `2f+1` validators are online. For a chain whose purpose is exchange activity, immediate finality is worth the liveness cost — a trader never waits for N confirmations, and a block at height H is final in the same second it commits.

### 1.3 Deployment status

The reference implementation is code-complete and pre-launch. It builds, the full test suite passes, and the end-to-end path — transaction submission, consensus, block application, matching, Active-order routing, NFT mint/wrap/transfer/burn and reward accrual, state persistence, restart — has been exercised on a live two-validator regtest. The RPC surface, the wallet layer, the P2P layer with authentication and encryption, and a Prometheus-compatible metrics endpoint are complete and tested. The mainnet and testnet parameters (chain IDs, genesis hashes, seed addresses) are pinned in `GlobalConfig` but the networks are not deployed. This document specifies the protocol the code implements; the deployment status is stated so that a reader does not mistake a specification for a live network.

---

## 2. Threat model and assumptions

### 2.1 What the protocol defends against

**Byzantine validators.** The BFT consensus tolerates up to `f = (n-1)/3` Byzantine validators. A Byzantine validator can equivocate, censor transactions, refuse to participate, or send malformed messages. The protocol's safety — two honest validators never commit different blocks at the same height — holds against this adversary. Its liveness holds if `2f+1` validators are reachable and honest.

**Network adversaries.** An adversary that can eavesdrop, modify, drop, or delay messages cannot decrypt session traffic (it is encrypted with ephemeral X25519 + XChaCha20-Poly1305, giving forward secrecy), forge a peer's identity (the Auth challenge binds identity key, ephemeral key, and both session nonces), tamper with a block without changing its hash, tamper with a Merkle proof without detection, or inject a valid transaction without the sender's private key.

**Malicious peers.** A peer that sends malformed messages, floods the node, or tries to connect to itself is detected and disconnected. Peers that cross the misbehavior threshold are banned. Two rate-limiting layers — a per-peer token bucket and a node-wide aggregate bucket — bound both per-peer and total work.

**State corruption.** The state is committed by a Merkle tree whose root is in every block header. Any two nodes with the same state produce the same root; a node whose state diverges produces a different root and its blocks are rejected.

**Light-client impersonation.** A server that lies about a balance produces a proof that fails local verification against the client's expected root. The client does not need to trust the server, because `verifyProof(expected_root, proof)` recomputes the root from the proof and compares.

**Transaction replay.** Every transaction is signed over a chain ID, so a mainnet transaction cannot be replayed on testnet. Within a chain, a nonce prevents replay.

**Equivocation.** A validator that signs two conflicting votes at the same `(height, round)` produces a mathematical proof of misbehavior. The proof is included in a block as a `Slash` system transaction; the validator loses 5% of its stake and its reward multiplier is permanently reduced.

### 2.2 What the protocol does not defend against

**A supermajority of Byzantine validators.** If more than `f` validators are Byzantine, safety breaks. This is a fundamental limitation of BFT consensus. At `n = 100`, `f = 33`; the protocol is safe up to 33 Byzantine validators and unsafe above.

**A chain stall.** If fewer than `2f+1` validators are online and honest, the chain stalls. Emergency rotation can replace offline validators with pool candidates, but only if there are candidates. A chain whose entire active set is offline and whose pool is empty stays halted until validators return.

**Long-term network partitions.** A partition longer than the round timeout triggers round advancement; longer than `EMERGENCY_ROTATION_ROUNDS` triggers emergency rotation. A partition that lasts for days will eventually exhaust the pool and leave the chain with a small active set — a liveness limitation, not a safety one.

**Compromise of a validator's live consensus key.** An attacker who compromises a validator's consensus key can sign conflicting votes on its behalf, which will be detected and slashed, but the damage is done. The mitigation is rotation via `RotateConsensusKey`.

**Compromise of a wallet's private key.** An attacker who compromises a wallet's reward key can spend its funds, update its reward address, and unregister its validator. There is no protocol recovery mechanism. The mitigation is hardware isolation (supported today via the offline `transaction_signer`; hardware wallet support is not implemented).

**Malicious RPC endpoints.** A wallet that uses an RPC endpoint trusts that endpoint for the root it verifies proofs against. The mitigation is to configure two endpoints and require both to agree on the root.

**Quantum adversaries.** Every signature scheme is Ed25519 and every key agreement is X25519. Both are vulnerable to a sufficiently large quantum computer. There is no post-quantum fallback; a transition would be a hard fork.

### 2.3 What the protocol assumes

**Honest-majority of validators.** At most `f = (n-1)/3` validators are Byzantine.

**Quorum liveness.** At least `2f+1` validators are reachable and honest.

**Partial synchrony.** The network eventually delivers messages; a message sent by an honest validator eventually arrives.

**Cryptographic hardness.** Blake2b is collision- and preimage-resistant; Ed25519 signatures are unforgeable; X25519 provides forward secrecy; XChaCha20-Poly1305 is IND-CCA2 secure; Argon2id is memory-hard.

**Synchronized clocks within the round timeout.** The BFT protocol uses round timeouts to advance rounds. A validator whose clock is far off may see rounds advance too fast or too slow; there is no clock synchronization protocol.

**Trusted execution for validators.** A validator's signing key is held in the daemon's memory. The protocol assumes the daemon is not compromised; operational security is the operator's responsibility.

---

## 3. Architecture and core principles

### 3.1 The eleven modules

Clarity's code is organized into eleven modules, from bottom to top:

- **Crypto** — hashes (Blake2b, Keccak, SHA-2), signatures (Ed25519), key exchange (X25519), AEAD (XChaCha20-Poly1305), KDF (Argon2id), key types.
- **Common** — encodings (hex, base58, base64), CRC32, JSON, varint, rate limiter, wire codec.
- **Serialization** — binary, KV-binary, and JSON serializers.
- **State** — MDBX storage, the compressed radix Merkle trie, `StateAccess`, proofs, historical reads.
- **Core** — blocks, transactions, execution, block processing, rewards, the order book, the matching engine, the Active-order router, the key-rotation history, equivocation proofs, NFT records, collections, reward schedules.
- **Consensus** — the BFT state machine, proposer selection, message encoding.
- **P2P** — TCP transport, peer management, framing, Auth, session encryption, sync, relay, proof serving, rate limiting.
- **Node** — assembles everything into a running daemon.
- **RPC** — JSON-RPC 2.0 server, dispatcher, method handlers, encoders, metrics endpoint.
- **Wallet** — keystores, HD derivation (BIP39/SLIP10), signing, addresses, transaction builders.

### 3.2 Four core principles

**State is a Merkle tree, not a database of accounts.** The persistent state is a single compressed radix trie whose root is committed into every block header. Every account, token, balance, validator, order, pool, position, NFT, and global value has exactly one position. There is no side table that participates in consensus but isn't in the tree. Every read and write routes through the tree; the tree's root is the state root, full stop. The cost is that a state change of any kind walks O(log N) nodes and rewrites the path to the root. That cost buys proofs, light clients, and canonicity.

**Everything is a first-class state object.** An NFT is not a contract. A token is not a contract. An AMM pool is not a contract. An order is not a contract. They are records in the state tree, indistinguishable at the state layer from an account: each has a domain-separated key, a serialized value, and a position in the trie. There is no VM, no bytecode, no storage slots, no interface discovery, no ABI. Adding a feature means adding a record type and a transaction type. The cost is that Clarity cannot do arbitrary computation; the bet is that this trade-off produces a better chain for the specific things it does.

**State transitions are pure functions.** Every state change inside block application is a pure function of the block and the state it runs against. Nothing reads wall-clock time, local peer state, hardware entropy, or any other non-deterministic source. This is why the emergency-rotation decision lives in the block header — a validator can look at its own clock to decide *whether* to set the flag, but only the *value* goes into the block, and only the block feeds the state. The matching engine, the Active-order router, the key-history maintenance, and the NFT reward accrual are held to the same rule: they read nothing but their arguments. The consequence is that a proposer can simulate a block to compute its state root without committing anything, and any node that later applies the same block computes the same root.

**One block per round, final on commit.** There is no fork choice. A block that commits is the block at that height. The chain is linear and append-only. The cost is the liveness assumption described in §1.2.

### 3.3 The dry-run/apply split

Because a block's state root is only known after the block's transactions have been applied, the block processor distinguishes two paths:

- **Simulate (dry-run).** The proposer runs the block's state transition, computes the resulting root, and aborts the transaction. Nothing is committed.
- **Apply.** Every node that receives a committed block runs the same state transition and commits it.

For the proposer's block to be accepted by other nodes, the simulate root and the apply root must be identical, byte for byte. This requires that **every state change that touches the SMT happens on both paths.** Only writes to the meta table and to non-SMT index tables may be gated on `!ctx.dry_run`, because those do not contribute to the state root. If a change is gated, the two paths disagree on the root and the block is rejected.

The dry-run path additionally skips structural header checks and quorum signature verification — a proposer has no signatures to verify while it is building the block — and the three commitment checks (`state_root`, `receipts_root`, `epoch_fills_root`). It does *not* skip the timeout-certificate signature verification for an emergency block, because the certificate determines the emergency active set and therefore the state changes the dry-run must compute.

The invariant has been violated once, in the earliest version of the block processor, and the symptom was that blocks 1 and 2 were committed by consensus but rejected by every node that tried to apply them. The fix was to unify the write paths, and the `MatchingSimulateAndApplyProduceSameRoot`, `MatchingRootIdenticalAcrossFreshInstances`, and `NftReward_SimulateAndApplyProduceSameRoot` tests are the canaries that catch a future violation.

### 3.4 Single-file storage

All of the node's persistent data — chain data, state data, receipts, the transaction index, the mempool, and the consensus WAL — lives in a single MDBX file at `<data_dir>/state`. There is no separate chain database directory. This is a storage-layout decision, not a consensus-relevant one. Its motivation is atomicity: the block processor commits a block's transactions, the block's index entries, and the chain-head update in a single MDBX write transaction. If chain data and state data were in separate files, that atomicity would have to be simulated with a two-phase commit, and any crash between the two phases would leave the database in a state where the block was committed but the state wasn't (or vice versa). With one file, MDBX's own transaction gives the invariant for free. The trade-off is that MDBX's file-size accounting is per-environment, not per-table, so a naive read of the file size includes both chain and state. Per-table byte estimates are available through `mdbx_stat -a`.

---

## 4. State: commitment, storage, and proofs

### 4.1 The compressed radix Merkle trie

The state tree is a **compressed radix Merkle trie** over 256-bit keys. Keys are read one bit at a time, MSB first. A leaf sits at the end of a path; an internal node ("branch") sits at a point where two keys diverge. Path compression means that a chain of single-child internal nodes is collapsed into a single branch: the branch carries the shared prefix that all keys below it agree on, plus one branching bit, plus two children. There are no single-child internal nodes in a well-formed tree.

The result is that the tree's height is O(log N) in the number of leaves N. A tree with a thousand leaves is about ten levels deep; a tree with a million leaves is about twenty.

#### 4.1.1 Node kinds

There are exactly three kinds of node:

**Leaf.** A leaf is `(key, value_hash)`. Its hash preimage is:

```
Blake2b("leaf" || 0x00 || key(32) || value_hash(32))
```

The leaf's *value* is not part of the leaf; it is stored separately, keyed by the leaf's hash. This separation lets the leaf's hash commit to the value without the tree holding the value bytes — the tree stores 65-byte leaf preimages, and the value lives in a separate table.

**Branch.** A branch is `(prefix_len, prefix_bits, left_hash, right_hash)`. Its hash preimage is:

```
Blake2b("brch" || 0x01 || prefix_len(BE16) || prefix_bits_padded || left(32) || right(32))
```

The two children are distinguished by the bit immediately following the prefix: if that bit is 0, the walk descends into `left_hash`; if 1, into `right_hash`. The prefix bits and the branching bit together cover some number of key bits at the branch's position; the sum of these across a path from root to leaf equals the number of key bits consumed.

**Default.** The empty subtree at a given remaining depth, represented by a precomputed hash. The default-hash recursion is:

```
defaultHash(0)     = Blake2b("dflt" || 0x02 || 0x0000)
defaultHash(d + 1) = Blake2b("dflt" || 0x02 || BE16(d + 1) || defaultHash(d) || defaultHash(d))
```

This has an important property: `defaultHash(d)` is the hash of an internal node whose two children are both `defaultHash(d-1)`. This is what makes "a branch whose two children are both empty" *be* the empty subtree for the branch's depth, so the tree's sparse representation is exactly consistent with its hashing. There are 257 default hashes, computed once and cached.

The domain tags `"leaf"`, `"brch"`, `"dflt"` and the second-layer bytes `0x00`, `0x01`, `0x02` make cross-kind collisions impossible even if the payloads happened to align.

#### 4.1.2 Two invariants

The tree maintains two invariants that make it a canonical representation of a key set.

**Every branch consumes at least one bit.** A branch's prefix length plus one (the branching bit) is the number of key bits that branch consumes. Since prefix length is bounded by 256 and every descent consumes at least one bit, the height of a tree with N leaves is bounded by both 256 and the number of distinct keys.

**No branch has a default child.** When one of a branch's children becomes default — as a result of a delete — the branch is *collapsed*: it is replaced by the surviving child with its prefix extended by the branch's prefix plus the branching bit. Every branch in a well-formed tree has two non-default children.

Together these invariants make the tree canonical: two nodes with the same key set build the same tree regardless of insertion order.

#### 4.1.3 Insert, update, delete, and write cost

The tree is walked recursively from the root. Insertion into an empty subtree replaces the default with a new leaf. Insertion of a key matching an existing leaf replaces the leaf. Insertion of a key differing from an existing leaf finds the first differing bit and creates a branch. Insertion of a key whose path diverges from an existing branch's prefix splits the branch. Deletion replaces the leaf with the default and, on the way back up, collapses any branch whose child is now default.

For a tree with N leaves and uniformly distributed keys, the expected height is approximately `log2(N)`. Each insert or delete writes one row per level of the path it visits, so an update writes O(log N) rows. This is the fundamental cost property the tree was chosen for.

#### 4.1.4 Canonicity

The tree's root is a pure function of its key set. This is what makes consensus on a state root possible without a canonical-ordering pass, and what makes the dry-run/apply invariant hold: a dry-run produces the same root as an apply, because both walk the same key set with the same invariants. An earlier draft that split leaves without reference to the current depth violated this and produced order-dependent roots; the fix — computing the shared prefix relative to the current position, not from bit 0 — restores canonicity. The `ManyInsertsAreOrderIndependent` and `ApplyBatchMatchesSequential` tests cover it.

### 4.2 Key derivation

Every state object is keyed by `Blake2b(domain4 || payload)`, where `domain4` is a 4-byte ASCII tag identifying the object's kind, and `payload` is the identifier for the object. The 4-byte tag prevents two different object kinds from ever colliding: an account address and a validator ID could hash to the same 32 bytes in principle, but their domain tags differ, so the keys differ.

Once a domain tag is deployed, it must never change. Changing a tag moves every key in that namespace, orphaning the state it references. The tags are part of the chain's identity, the same as the block format and the consensus rules. The full list of 20 tags is in Appendix B.

The compressed tree reads keys the same way the uncompressed tree did — bit by bit from MSB to LSB — so the key space is unchanged. Only the node structure above the keys differs.

### 4.3 StateAccess

`StateAccess` is the typed façade the rest of the node uses. It sits over the MDBX environment and the tree and exposes methods for the entities the chain has: `getAccount`, `putAccount`, `getToken`, `putToken`, `getValidator`, `putValidator`, `getOrder`, `putOrder`, and so on. Every read that touches the tree goes through the tree's `get`, which walks from the current root down to the leaf. Every write goes through the tree's `update` or `remove`, which walks from the root down to the leaf and recomputes every hash on the way back up.

#### 4.3.1 Two modes

`StateAccess` exists in two modes.

**Txn-bound mode.** The `StateAccess` is constructed over an existing MDBX write transaction, and every read and write goes through it. The transaction is not owned by the `StateAccess`; the caller opened it and the caller commits or aborts it. This is the mode the block processor uses: it opens one write transaction per block, wraps it in a `StateAccess`, applies the block's transactions, and commits the transaction at the end. Every read sees the transaction's own uncommitted writes.

**Autocommit mode.** The `StateAccess` owns a single MDBX read transaction for its lifetime, and read methods route through it. Write methods release the read transaction first, open their own write transaction for the duration of the write, and the next read after the write transparently opens a fresh read transaction. Autocommit mode is what makes a tree walk cheap: a walk visits a dozen nodes, and holding one read transaction for the lifetime of the `StateAccess` means the entire walk is one reader slot, not a dozen.

#### 4.3.2 Read dispatch

A read dispatches in order: the bound write transaction (if any), the held read transaction (if any), then raw DB access with a per-thread fallback. The per-thread handle is checked before opening a transaction, so a nested read from inside a `forEach` visitor reuses the outer iteration's transaction rather than trying to open a second one. This is what makes the layer thread-safe without locks in the hot path.

#### 4.3.3 Write discipline

MDBX forbids opening a write transaction on a thread that already has a read transaction open. Every write method on `StateAccess` therefore calls `releaseReadTxnIfHeld()` before it does anything else. The next read after the write transparently acquires a fresh read transaction. The result is that a `StateAccess` in autocommit mode can interleave reads and writes freely.

A related rule: **every `putX` method is a pure write; it reads nothing before it writes.** This is not stylistic. A read inside a write path interleaves with the tree's content-addressed node update buffer in a way that can cause a subsequent update to be computed against a stale root and silently dropped. The exact mechanics are subtle: the tree's update recursion is stateful across a single call, and a read between writes can leave the recursion with a stale view of the subtree it is about to modify.

This was learned the hard way during NFT development. An early `putNft` read the old record first to unindex it, and the result was that a reward-pass update in a subsequent transaction was silently lost. The fix was to make `putNft` a pure write and move the read to the caller, which is where every other `putX` already had it. A caller that needs to clean up an old record's index rows reads the old record first, then calls a dedicated unindex method, then calls the new `putX`.

### 4.4 Proofs

A Merkle proof for a key is a list of sibling hashes from the deepest branch on the key's path up to the root, plus a description of what the walk terminated on. Verification recomputes the root from the proof and compares. `verifyProof(expected_root, proof)` performs no database access and no signature checks: a caller that holds only the state root can verify a proof without trusting the server that produced it.

#### 4.4.1 The four terminal kinds

A proof's walk terminates at one of four things:

**Inclusion.** The walk reached a leaf whose key matches the proven key. The proof carries the value at that leaf. Verification hashes `(key, value)` to get the leaf hash, then walks up.

**Default.** The walk reached an empty subtree at some remaining depth. The proof carries no value; the depth is derivable from the sibling list. Verification computes `defaultHash(depth)` and walks up.

**Different leaf.** The walk reached a leaf whose key is not the proven key. The proof carries the divergent leaf's key and value hash. This is a non-inclusion proof: the proven key is not in the tree, and the divergent leaf is the evidence.

**Divergent branch.** The walk reached a branch whose prefix the proven key does not share. The proof carries the branch's prefix and both children's hashes. This is also a non-inclusion proof.

The four kinds are necessary because the compressed tree's walk can stop at any of them, and each carries different identifying information. An earlier design with only "inclusion or non-inclusion" couldn't distinguish the two kinds of non-inclusion that carry different data, and produced proofs that failed verification for the divergent-branch case.

#### 4.4.2 Wire format

```
proof:
    key                    32 bytes
    terminal_kind           1 byte  (0=Inclusion, 1=Default, 2=DifferentLeaf, 3=DivergentBranch)
    terminal payload        (depends on kind)
    sibling_count           1 byte  (0..256)
    siblings                sibling_count * variable

sibling:
    prefix_len              2 bytes (big-endian)
    prefix_bits             ceil(prefix_len / 8) bytes
    sibling_hash            32 bytes
```

The wire format is self-describing and rejects trailing bytes. The sibling count is a `u8` capped at 256, so a hostile peer cannot cause an unbounded allocation with a fake count.

#### 4.4.3 Verification

The verifier computes the terminal hash from the terminal descriptor, walks the sibling list from deepest to shallowest combining the current accumulated hash with each sibling, and compares the final computed root to the expected root. The walk's direction is dictated by the key's bits: at each branch, the branching bit determines whether the current hash is the left or right child of the parent. The `prefix_start` at each level is derived from the sibling list itself — the sum of `(prefix_len + 1)` over the siblings above, subtracted from 256 — which is what lets the wire format omit an explicit depth per sibling.

#### 4.4.4 Generation and the single-walk invariant

`proveAtRoot(tree, root, key)` walks from an explicit root down to the key's terminal, collecting sibling hashes and the terminal's identifying information in a single recursion. The alternative — reading the leaf separately from the current tree — would produce a proof whose value and siblings disagreed whenever the requested root was historical. The single-walk invariant is documented on `proveFromRoot`, and it is the reason `proveAtRoot` takes an explicit root rather than being a thin wrapper over `tree.get`.

#### 4.4.5 Key descriptors

A client that wants a proof of "Alice's balance" doesn't know that the underlying key is `Blake2b("acct" || alice_address)`. So the proof protocol accepts a typed descriptor and lets the server resolve it to the right SMT key. The descriptors are `Account` (32-byte address), `TokenBalance` (32-byte address + 4-byte token id), `Validator` (8-byte validator id), `Global` (UTF-8 name up to 64 bytes), and `AmmPool` (8-byte pool id). The server resolves the descriptor via the same `Keys::*` functions the rest of the codebase uses.

### 4.5 Versioning and historical reads

A **version** is a block height. When the block processor commits a block at height H, it applies the block's transactions and calls the tree's `save(H)`, which writes the current root to the meta table and updates the current root. The tree also writes a historical row for every node and leaf it stores at version H, provided H is not 0. Version 0 is the bootstrap version — the state before any block has been applied — and is not stored historically.

`rootAtVersion(V)` retrieves the state root at version V. `getAtVersion(key, V)` retrieves a key's value as it was at version V: it reads the root at V, then walks the tree from that root using the *historical* tables instead of the live ones. Typed historical reads are exposed as `getAccountAtVersion`, `getValidatorAtVersion`, and `getGlobalAtVersion`; the raw primitive is `getRawAtVersion`.

Historical storage is content-addressed and deduplicated: a node whose subtree did not change between two versions is stored once, at the version where it first appeared, and remains reachable from every later version's root. This means the historical tables grow with state *changes* within the retention window, not with block count.

### 4.6 The retention window

`smt_history_blocks` is the size of the retention window. After block H commits, the historical tables contain versions from `H - N + 1` to `H` inclusive; older versions are pruned. The prune runs after every block commit, inside the same MDBX write transaction as the block commit. If the prune fails, the entire block commit aborts, the block is not committed, and the consensus engine's retry mechanism retries the block.

This is deliberate. A storage failure that prevents pruning is a real problem: if the prune failed silently, the historical tables would grow unbounded behind a warning, and an operator might not notice until the disk filled. By making the prune part of the commit, a prune failure halts the block processor and surfaces the problem.

The default windows are 2,048 blocks on mainnet, 512 on testnet, and 64 on regtest. The window is not consensus-relevant: two nodes on the same chain with different windows still agree on every block, on every state root, and on every consensus decision; they differ only in what historical queries they can answer.

### 4.7 What state storage costs

**Bounded components.** The live tree (`smt_nodes`, `smt_leaves`) holds one row per distinct subtree hash; for N live leaves it is O(N) rows. The historical tables hold rows for at most `smt_history_blocks` versions, bounded by `(writes per version) × smt_history_blocks`. The entity tables and index tables hold one row per live object. Block and transaction history grows linearly with chain length — this is the component that grows with the chain and is the reason a long-running node eventually needs more disk than a freshly synced one.

**Unbounded components.** The live tree's stale nodes: when the tree's shape changes, the old subtree hashes remain in the live tables even though they are no longer reachable. The tables grow with the total number of distinct subtrees the chain has ever produced. For a chain that grows its live state monotonically this leak is small; for a chain that churns heavily it can be significant. The leak is currently unmitigated; a mark-and-sweep pass that deletes rows unreachable from the current root would bound it, but it is not implemented in v1. Fill history (`TBL_FILL_HISTORY`) is also never pruned, and is a candidate for future bounding.

**Realistic sizes.** For a regtest running a few hundred blocks with modest churn, the total is under 20 MB. For a mainnet with a million accounts, a thousand tokens, a thousand pools, and ten thousand NFTs, the dominant component is block and transaction history (~5 GB at a million blocks), with the historical tables at ~400 MB and the live tree at ~50 MB.

---

## 5. Transactions and execution

### 5.1 The transaction envelope

Every transaction carries: `version` (u16), `chain_id` (u64), `tx_type` (u8), `nonce` (u64), `valid_until_height` (u64), `from` (32-byte address), `to` (32-byte address), `token_id` (u32), `amount` (u64), `fee` (u64), `payload` (variable), and `signature` (64-byte Ed25519).

The signing hash is `Blake2b(serializeForSigning())`, where `serializeForSigning` produces the same bytes as `serialize` except for the signature, which is omitted. **The signing hash equals the transaction id (txid).** A client can compute the txid from an unsigned transaction; it doesn't need the signature.

The wire format is a **codec, not a validator**. Deserializing produces a `Transaction` struct; it does not check that fields are semantically valid. `isWellFormed()` is a separate step that checks structural constraints. The mempool and the executor run both.

### 5.2 Transaction types

The `TxType` enum groups types by category:

- `0x00–0x0F` — Core (transfers).
- `0x10–0x1F` — Staking.
- `0x20–0x2F` — Validator.
- `0x30–0x3F` — AMM.
- `0x40–0x4F` — DEX / Orders / NFTs.
- `0x50–0x5F` — Token management.
- `0x60–0x6F` — Governance (reserved).
- `0x70–0x7F` — Cross-chain (reserved).
- `0xF0–0xFE` — System (implicit).
- `0xFF` — Invalid sentinel.

Values are never reused. The full type list with payload layouts is in §7 for the application-layer types and below for the core types.

#### 5.2.1 Native transfer (`Transfer = 0x00`)

Sends CLRTY or a custom token from `from` to `to`. Validation: `amount != 0`, `to` is not null, sender has enough balance. State changes: if native, sender balance decreases by `amount`, recipient balance increases; if custom, token balances are adjusted. The recipient's account is created if it did not exist.

#### 5.2.2 Staking (`OptInStaking = 0x10`, `OptOutStaking = 0x11`, `ClaimRewards = 0x12`)

Staking is liquid: no lockup, no withdrawal delay. The "staked" amount is bookkeeping — it determines reward eligibility, not spendability. Auto-stake rule: any account with balance ≥ `AUTO_STAKE_THRESHOLD` (1 CLRTY) is automatically enrolled unless opted out.

`OptInStaking` clears the opt-out flag and recomputes staked via `recalculateStaked()`, which sets it to `balance - AUTO_STAKE_THRESHOLD` if balance exceeds the threshold, else 0. If the sender became a staker (staked was 0, now > 0), it is added to the staker index and `staker_count` is incremented. `OptOutStaking` is the mirror. `ClaimRewards` moves `pending_rewards` into `balance`, resets `pending_rewards` to 0, and recomputes staked.

#### 5.2.3 Validator operations

`RegisterValidator = 0x20` — registers the sender as a validator. Payload is the 32-byte P2P node public key. Validation: sender balance ≥ `VALIDATOR_MIN_STAKE` (10 CLRTY), sender is not already registered. State changes: new `ValidatorInfo` with `id = next_validator_id`, `reward_address = from`, `owner = from`, `stake = balance`, `registered_at_height = current_height`, `uptime_score = 10000`, `is_active = false`, `consensus_key = payload`; the `next_validator_id` global is incremented; a validator-by-address index entry is written; a single-entry consensus-key history is initialized covering from `current_height` onward. The validator is placed in the pool, not the active set.

`UnregisterValidator = 0x21` — begins the validator's unbonding. The validator is removed from the active set immediately; its record, address index, key history, and stake persist for `UNBONDING_PERIOD` (120 blocks, two rotation intervals) before the stake is released. Validation: sender is registered, sender is not a seed, if active then removing it would not drop the set below `ACTIVE_SET_MIN`, and no pending unbond is in flight. After `UNBONDING_PERIOD`, `processUnbondExpiries` refunds the stake to the owner, deletes the validator record, deletes the address index, and deletes the key history.

`UpdateRewardAddress = 0x22` — changes the validator's reward address. Payload is the 32-byte new reward address. Validation: payload is exactly 32 bytes, sender is registered, new address is not null, new address is not already used. State changes: old address index is deleted, new is written, `reward_address` and `owner` are updated. If the validator's `consensus_key` was null (a pre-split validator), it is set to the current effective key before the update, so the reward address can move without affecting consensus.

`RotateConsensusKey = 0x23` — rotates the consensus signing key. Payload is the 32-byte new consensus public key. Validation: payload is exactly 32 bytes, sender is registered and is the owner, new key is not equal to the current effective key, no pending unbond. State changes: the key history is loaded (or synthesized for a pre-feature validator), the last entry's `valid_until_height` is set to the current height, a new entry is appended with the new key, and the record's cached `consensus_key` is updated. The rotation is immediate; the old key stops being valid for new signatures the moment the rotation commits.

#### 5.2.4 Token operations

`CreateToken = 0x50` — creates a fungible token. Payload carries decimals, backing, name, symbol, max supply (0 = unlimited), royalty bps, and an optional fingerprint. The `isValid()` check enforces name and symbol length, decimals ≤ 18, backing ≤ 1, and royalty bps ≤ 10000.

`MintToken = 0x51` — mints new units. Only the creator can mint. Validation: `amount != 0`, token is not native, token exists, sender is creator, and if `max_supply > 0` then `current_supply + amount <= max_supply`.

`BurnToken = 0x52` — burns units. Validation: `amount != 0`, token is not native, sender has at least `amount`.

`UpdateTokenMeta = 0x53` — changes name, symbol, and royalty. Only the creator. An empty field means "leave unchanged." `max_supply` and `decimals` cannot be changed.

### 5.3 The execution pipeline

Every transaction passes through the same pipeline in `TransactionExecutor::execute`:

1. **Structural validation.** `tx.isWellFormed()` checks that the fields have plausible types and sizes.
2. **Chain ID.** `tx.chain_id == ctx.chain_id`.
3. **Expiry.** If `valid_until_height != 0` and `current_height > valid_until_height`, reject.
4. **Signature.** The signing hash is recomputed and verified against `tx.from`.
5. **Nonce.** `account(from).nonce == tx.nonce`.
6. **Fee charge.** The sender's balance must cover `tx.fee`. If it doesn't, the transaction is rejected *before* the type-specific dispatch.
7. **Dispatch.** The type-specific handler runs. If it returns `Success`, the nonce is bumped. If it returns `Failure`, the nonce is **not** bumped (but the fee was already charged).

The order matters. The fee is charged before the dispatch, so a failed transaction still pays its fee. The nonce is bumped only on success, so a failed transaction can be retried with the same nonce. If any of the earlier stages fails, the fee is not charged.

### 5.4 Receipts and fills

Every transaction that succeeds or fails produces a receipt with `status` (u8), `fee_paid` (u64), and `fills` (a list of `Fill` records). The fill list is empty for every transaction type except `CreateOrder`, and even for `CreateOrder` it is empty unless the order crossed. A fill has a `source` (`Limit` for a book match, `Amm` for a pool route), a `maker_order_id` (zero for an AMM fill), a `taker_order_id`, a `pool_id` (zero for a limit fill), `qty_base` and `qty_quote` in canonical frame, `price` scaled by `BOOK_PRICE_SCALE`, and `base_token` and `quote_token` ids.

The receipt's bytes feed into `receipts_root`, so the fills on a receipt are consensus state: a block whose receipts commit to a different set of fills than the verifier computes produces a different `receipts_root` and is rejected. Fills produced at the epoch boundary by the Active-order router have no transaction to attach to; they are committed separately via the header's `epoch_fills_root` (see §7.2).

### 5.5 What a transaction cannot do

A transaction cannot specify an arbitrary recipient for the fee (fees are always in CLRTY, to the sender); cannot retry a failed transaction without re-signing (a failed nonce is not bumped, but the fee is charged); cannot exceed 64 KiB of payload or 1 MiB total; cannot target a different chain; cannot be replayed; cannot sign on behalf of someone else; cannot pay fees in a non-native token; cannot have a fee of zero; cannot use a nonce that hasn't been reached.

---

## 6. Consensus

### 6.1 Protocol overview

Clarity's consensus is a variant of Tendermint-style BFT proof-of-stake. Validators are selected from a bounded active set, rotate at epoch boundaries, and sign blocks in rounds. A block commits when `2f+1` validators precommit it, where `f = (n-1)/3` is the maximum number of Byzantine validators the protocol tolerates. Once a block commits, it is final.

The consensus engine is `BftConsensus`. It holds no persistent state of its own; every durable fact lives either in the block headers (for committed blocks) or in the write-ahead log (for the local validator's own votes and locks). A validator that crashes mid-round and restarts replays its WAL, reconstructs its position, and resumes from where it left off without ever signing a conflicting vote.

### 6.2 Rounds and steps

Consensus proceeds height by height. For each height there is a sequence of rounds; for each round there are three steps:

- **Propose.** The proposer for this round builds a block and broadcasts it.
- **Prevote.** Every validator casts a vote for the block it believes should be committed, or a nil vote if it has not seen a valid proposal.
- **Precommit.** Every validator casts a second vote, for the block that reached a prevote quorum (a "polka") in this round, or for its lock if no new polka formed.

When `2f+1` precommits land on the same block, the block commits and the engine advances to the next height. If a round fails to reach quorum — the proposer is offline, the network is partitioned, the proposal doesn't arrive in time — the round number increments and a new proposer takes over.

### 6.3 The three phases

**Propose.** The proposer for round R at height H builds a candidate block, simulates it to compute the state root and the epoch fills, fills in the header (including `epoch_fills_root`), signs the proposal, and broadcasts it. The other validators receive the proposal, verify its signature against the expected proposer, deserialize the block, run their own simulation to confirm the state root and the epoch fills, and hold it as the candidate for this round. A validator that has already voted in a previous round may re-propose its locked block.

**Prevote.** Once a validator has a candidate block for the round, it casts a prevote for that block. If it has no candidate — the proposal hasn't arrived, or arrived but failed verification — it casts a nil prevote. The prevote commits the validator to a specific block hash for this round; the validator cannot change its prevote within the round.

**Precommit.** When a validator observes a prevote quorum (a polka) for a block within a round, it casts a precommit for that block. If no polka formed, it casts a precommit for its lock if it has one, or nil otherwise. The precommit is the vote that commits.

The three phases exist because a two-phase protocol cannot guarantee that two honest validators don't commit different blocks in the same round. The prevote phase is where the network agrees on a single candidate; the precommit phase is where the network commits to it.

### 6.4 Quorum

The quorum threshold is `bftQuorum(n) = (n * 2) / 3 + 1`.

| Validators (N) | Quorum | Tolerated faults |
|---|---|---|
| 2 | 2 | 0 |
| 3 | 3 | 0 |
| 4 | 3 | 1 |
| 5 | 4 | 1 |
| 6 | 5 | 1 |
| 7 | 5 | 2 |
| 11 | 8 | 3 |
| 21 | 15 | 6 |
| 100 | 67 | 33 |

A quorum is a quorum on a *specific block hash*, not on "some block". Two quorums on different blocks in the same round cannot both exist unless the intersection of their validator sets contains a Byzantine validator who signed both. Since the intersection of two `(2n/3)+1` sets is at least `n/3 + 1`, and there are at most `(n-1)/3` Byzantine validators, the intersection always contains at least one honest validator. An honest validator cannot sign two different blocks at the same height and round, so two conflicting quorums are impossible.

Note that the minimum legal active set is **2**, not 11. At N=2, `bftQuorum(2) = 2`, so both validators must sign for a block to commit and zero faults are tolerated. This is the genesis configuration and the hard floor. The *default target* active set is 11; the active set grows toward that target as validators register, and a rotation that would drop the set below `ACTIVE_SET_DEFAULT` is sized to avoid doing so. The N=2 case is a bootstrap configuration, not a steady state.

### 6.5 Proposer selection

`proposer = active_set[(height + round) mod active_set_size]`.

The proposer rotates deterministically with every height and every round. If the proposer for round R is offline, round R+1 has a different proposer. The rotation is what makes a single offline validator delay the chain by one round rather than halt it indefinitely.

The proposer for a given round is identified by the validator's id, not by its index in the set. The index is a hint that ships in the proposal (for compactness when packing quorum signatures into a committing block), but the id is authoritative. A receiver that resolves the id and finds that the index disagrees rejects the proposal. This matters when the emergency active set differs from the committed set: index 5 in the committed set is a different validator than index 5 in the emergency set. The id is stable across the two; the index is not.

### 6.6 Locking and safety

#### 6.6.1 When a validator locks

A validator **locks** on a block when it precommits to that block after seeing a prevote quorum (a polka) for it. The lock is set at *precommit* time, not at prevote time.

This distinction is important. A validator that prevoted block X but never saw a polka for X is not locked on X. If a new round proposes block Y, the validator is free to prevote Y. Only after observing that a quorum of the active set also prevoted X does the validator commit itself to X.

Once locked, the validator's prevote in any subsequent round is for the locked block, *unless* a newer polka (from a round strictly greater than the lock round) supersedes the lock. The precommit is for the block that reached a polka this round, or for the locked block if no new polka formed. The lock survives round transitions within a height and is cleared only when the height changes.

#### 6.6.2 The valid-value state

Closely related to the lock is the **valid value**: the most recent block for which the validator has seen a polka. The validator records `(valid_hash, valid_round)` whenever it observes a polka, whether or not it then precommits. At prevote time, the selection rules are:

1. If the validator has a lock and the lock has not been superseded by a newer polka, prevote the locked block.
2. Otherwise, if the validator has a valid value, prevote that.
3. Otherwise, prevote the proposal for this round.
4. Otherwise, prevote nil.

The valid value and the lock are distinct. A validator can have a valid value without a lock (if it saw a polka but didn't precommit before the round advanced), and it can be locked on a block that isn't its most recent valid value (if it locked on X in round N and saw a polka for Y in round N+1 that it didn't have time to precommit before the round advanced again). The combination is what makes round-crossing recovery work.

#### 6.6.3 Round-crossing recovery

The subtle case is a validator that times out in round N, has not seen a polka, and sees a proposal for round N+1 before its own timer has fully settled. The validator has not locked on anything, has no valid value, and is free to accept the round-N+1 proposal.

The harder case is a validator that was on the edge of round N: it saw enough prevotes to form a polka for X but didn't have time to precommit before the round advanced to N+1. On entering N+1, it has a valid value (the polka for X) but no lock. It prevotes X in round N+1. The proposer for N+1 may be proposing Y. The prevote for X doesn't help Y commit, but it doesn't hurt either.

The mechanism that makes this work in practice is the proposal queue. A proposal for round N+1 that arrives while the validator is still in round N is stashed and delivered when the local round advances. Combined with the valid-value rule, a validator that was on the cusp of forming a polka in round N can still prevote the right block in N+1 without having to have completed the round.

A related mechanism: **votes are recorded whenever they arrive, regardless of the receiver's current step; only the transitions they trigger are step-gated.** This is what allows a late-arriving polka to fire `enterPrecommit` on the next step transition, even if the validator has already moved past the step where the polka would normally have been observed. The transitions are idempotent — `enterPrevote` and `enterPrecommit` return early if already in the target step — so recording a vote never re-fires a transition that already happened.

#### 6.6.4 Why these rules are safe

The safety claim is: **two honest validators never commit different blocks at the same height.**

Suppose validator A commits block X at height H round R, and validator B commits block Y at height H round S, with X ≠ Y. Both commits required a precommit quorum: `2f+1` precommits for X in round R, and `2f+1` precommits for Y in round S.

If R = S, the two quorums intersect in at least `n/3 + 1` validators, of which at least one is honest. That honest validator precommitted both X and Y at the same height and round, which contradicts the protocol — a validator precommits exactly once per round.

If R < S, the safety argument reduces to showing that a precommit quorum for X in round R implies that no honest validator will precommit Y in any later round. An honest validator that precommitted X is locked on X, and at round S it can only precommit Y if it saw a polka for Y in a round greater than R. But a polka for Y in a round greater than R requires `2f+1` prevotes for Y in that round; since the polka for X in round R had `2f+1` prevotes for X, the intersection of the two sets contains an honest validator. That validator prevoted X in round R (via the polka) and Y in a later round — but by the valid-value rule, it can only prevote Y in a later round if it saw a polka for Y in a round at least as new as its valid round. Since it had a valid value for X (from the round-R polka), it would need to have seen a polka for Y in a round strictly greater than R. This is possible in principle, but it requires the honest validator to have seen the polka for Y and then to have updated its valid value to Y. The full proof is the standard Tendermint safety proof and holds for the same reasons.

The pieces of the code that implement the safety argument are the step transition rules in `enterPrevote`, `enterPrecommit`, and `enterCommit`; the lock and valid-value updates in `enterPrecommit` and `checkPrevoteQuorum`; the prevote selection rule in `selectPrevoteHash`; the vote signature verification in `verifyVoteSignature`, which binds each vote to the signer's authoritative key at the vote's height; and the vote-recording path in `insertVote`, which detects equivocation and refuses to count a conflicting vote.

### 6.7 Timeouts and round advancement

Each round has a timeout that scales exponentially with the round number. Round 0 has the base timeout; each subsequent round doubles it, up to a maximum. The scaling makes the network resilient to jitter without liveness loss: a round that times out because a proposal was slow gets a second chance with a longer window.

The timer is driven by `pollTimers()`, which is called from the consensus loop. When the current round's timer expires:

- If in **Propose**, cast a timeout vote and move to **Prevote**.
- If in **Prevote**, cast a timeout vote and move to **Precommit**.
- If in **Precommit**, cast a timeout vote; if a precommit quorum for a block formed, commit; otherwise advance to the next round's **Propose**.

The timeout vote is only broadcast when the round is at or above the emergency rotation threshold (`EMERGENCY_ROTATION_ROUNDS = 30`), because a certificate composed of timeout votes from below that threshold is not useful for emergency rotation.

A validator that receives a valid vote for a round much higher than its current round can skip forward. Each vote carries its `(height, round)`, and a validator that observes `f+1` distinct validators at a round higher than its own advances its own round to match. The rule is: if `f+1` validators (of which at least one is honest) have signed votes at round R' > R, then the network is at least at round R', and a validator stuck at R can safely skip to R'. The skip is bounded: an attacker cannot induce a validator to skip to a very high round, because the votes must be signed by distinct validators in the committed set.

### 6.8 Block production: event-driven with a heartbeat floor

Clarity's block production is event-driven with a floor. The engine waits `MIN_BLOCK_INTERVAL_MS = 10,000` milliseconds after a commit before entering the next height — *unless* there is pending work, in which case it enters the next height immediately. The definition of "pending work" in the reference implementation is **the mempool is non-empty**.

This gives three regimes:

- **Busy chain.** The mempool is non-empty, so blocks are produced as fast as consensus can run — sub-second in the reference implementation — back to back.
- **Idle chain.** The mempool is empty, so the engine paces itself at one block per 10 seconds. This is the heartbeat. It keeps the chain producing blocks (and therefore rewards) even when there is no user activity, and it ensures that epoch boundaries, order-condition evaluations, and reward distributions run on a predictable schedule.
- **Stalled chain.** If 30 consecutive round timeouts occur, the emergency-set machinery engages (§6.10).

The 10-second floor is a **protocol-level norm, not a peer-enforced rule**. A proposer that runs faster than 10s on an idle chain is not rejected by its peers; the norm is a convention the reference implementation follows, not a consensus rule. This is the correct design for a chain where the block rate is an emergent property of activity: the consensus rules should not encode a block cadence, only a finality rule.

A scheduled epoch boundary or an order-condition evaluation does **not**, by itself, force a block. Those run when a block is produced for other reasons — a user transaction, or the heartbeat firing. The block-production trigger is "there is user work," and protocol-level housekeeping rides along.

### 6.9 Commit failure handling

When the precommit quorum forms for a block, the engine calls `on_block_committed(block)`. The callback returns a `bool` indicating whether the apply succeeded. If it returns `true`, the engine advances to the next height. If it returns `false`, the engine does **not** advance.

Instead, it retries the apply in place, with a linear backoff. `commit_attempts_` is incremented; `next_commit_attempt_ms_` is set to `now + backoff * commit_attempts_`; the engine returns to its normal poll loop. On the next `pollTimers()` past `next_commit_attempt_ms_`, it calls `tryApplyCommit()` again. The retry continues up to `max_commit_retries` (default 5).

The reason for retrying rather than advancing the round: the block already has `2f+1` precommits. It is the decided block at this height, and re-proposing it or a different block would violate the safety of the commit. Retrying the apply is the only correct response to a local apply failure. Advancing the round would also push a validator with a persistent apply failure toward emergency rotation, which is the worst possible response to a local disk problem.

If every retry fails, the engine calls `haltConsensus(reason)`: `running_` becomes false, `halted_` becomes true, the round timer is stopped, `on_consensus_halt(reason)` fires exactly once. `on_height_advanced` does not fire, the WAL is not truncated, and `pending_height_` is not set. The engine stays halted until the node calls `start()` again. The halt is deliberately loud: an operator who sees a node halt with the reason "committed block at height H could not be applied after N retries" knows the problem is local storage, not consensus. The node is not making progress, but it is also not corrupting state or losing the block — it is parked on the block it can't apply, waiting for the operator to fix the underlying issue.

The other way out of a commit retry loop is for the chain to advance externally. If a relay or sync path applies the block while consensus is retrying, the node calls `noteChainHead(applied_height)`. This is lock-free and safe to call from inside any callback: it stores `applied_height + 1` in an atomic. On the next `pollTimers()`, the engine observes that `external_next_height_` is greater than its own target and resets `commit_block_`, `commit_attempts_`, and `pending_height_`, clears the pacing timer, truncates the WAL to `external_next_height_ - 1`, and enters the new height directly. This is what makes a node recover gracefully from a stall caused by an external event (a sync that applied the block out-of-band) rather than requiring operator intervention. Operator intervention is only needed if *neither* consensus *nor* relay can apply the block — i.e., a genuinely local storage problem.

### 6.10 Emergency rotation

Emergency rotation triggers when a validator has observed `EMERGENCY_ROTATION_ROUNDS = 30` consecutive round timeouts at the current height. At a reference round timeout of ~5 seconds, this is roughly 2.5 minutes of stall — long enough that the stall is not a transient network issue, short enough that the chain doesn't wait indefinitely.

The threshold is observed by each validator independently. A validator that has been stalled for 30 rounds sets `consecutive_timeouts_ >= EMERGENCY_ROTATION_ROUNDS`, which makes `useEmergencySet()` return true. When the validator is the proposer, it proposes an emergency block; when it votes, it votes on the emergency set.

An emergency block carries a **timeout certificate**: a set of `f+1` signed timeout votes from the committed set at rounds greater than or equal to `EMERGENCY_ROTATION_ROUNDS`. The certificate proves to a verifier that at least `f+1` validators in the committed set observed the stall, which is the threshold for "the committed set is genuinely unable to produce a block". Since at most `f` validators are Byzantine, `f+1` signatures imply at least one honest validator observed the stall.

The certificate is included in the block header, hashed, and the hash is committed to via the `timeout_certificate_hash` field, which is part of the block hash. A relaying peer cannot strip or swap the certificate without changing the block hash and thus invalidating every signature.

The emergency active set is computed from the committed set and the validator registry, using the same predicate as offline removal:

```
emergency_set =
    (committed_set - validators_offline_at_current_height)
    + pool_promotions
```

A validator is "offline at current height" if its `last_seen_height` is more than `OFFLINE_KICK_BLOCKS` (20) blocks behind the current height. Pool promotions are chosen by the same uptime-based ordering as normal rotation. If the pool is empty, the set shrinks rather than the chain halting. Seeds are **not** protected in emergency rotation: a failed seed is exactly what emergency rotation is designed to replace, and the ordinary protections (which apply to normal rotation, offline removal, and unhealthy culling) are disabled here.

The emergency set is derived deterministically from the committed set, the validator registry, and the current height. Every honest node with the same inputs computes the same emergency set. This is what makes an emergency block verifiable by nodes that didn't propose it. The derivation is a single function, `resolveActiveSet(state, committed, height, force_rotation)`, called both by the proposer (to build the block) and by every verifier (to validate it), so the two cannot drift.

A verifier that receives an emergency block checks: the block's `emergency_rotation` field is ≥ `EMERGENCY_ROTATION_ROUNDS` and ≤ the proposal's round; the `timeout_certificate` is non-empty; `computeTimeoutCertificateHash(certificate)` matches `timeout_certificate_hash`; the certificate contains `f+1` signed timeout votes from the committed set, all at rounds equal to `emergency_rotation`; and the proposal's signature is valid against the emergency active set (which the verifier computes independently). If any check fails, the block is rejected.

One more rule makes the emergency path safe against displacing a decided block: **a node that has already observed a precommit quorum for a block will commit that block even if a peer sends an emergency proposal for a different block.** The node checks its own `heldQuorumBlock(height)` before processing an emergency proposal; if it holds a quorum for a different block, it applies and broadcasts its held block and ignores the emergency proposal. The emergency path is a fallback for nodes that don't have a quorum, not an override for nodes that do.

### 6.11 The write-ahead log

The consensus engine writes to a write-ahead log before it does anything that could cause a validator to sign a conflicting vote. The WAL holds two things:

- **Votes the validator has signed.** A `(height, round, is_precommit, block_hash, is_nil, signature)` entry, appended *after* signing and *before* the vote is recorded or broadcast.
- **Locks the validator has set.** A `(height, round, block_hash)` entry, appended *before* the lock is set. The locked block itself is written first (via `wal_append_locked_block`), because a block without a lock is harmless but a lock without its block is not.

On startup, `BftConsensus::start(height)` calls `replayWalForHeight(height)` before entering the propose step. The replay reads all WAL entries for the given height, adds each vote to `signed_votes_` keyed by `(height, round, is_precommit)` — `emplace` keeps the *first* entry for each key, so a validator that signed two different votes at the same key uses the first one, which is the binding one — restores `locked_`, `locked_hash_`, and `locked_round_` (the highest round wins if multiple locks are present), loads the locked block from the WAL and restores it in `proposals_by_hash_`, and **re-broadcasts every signed vote**. The vote is durable; a peer that never received it before the crash might receive it now. The replay returns the highest round seen in the WAL, so the engine resumes at that round rather than starting from round 0.

The re-broadcast is what makes the WAL a *liveness* recovery mechanism as well as a safety mechanism. A validator that crashed after signing a prevote but before broadcasting it would, without the WAL, lose the vote. With the WAL, the vote is re-broadcast on restart, and the network can still reach quorum.

`Node::initGenesis` calls `state_db_->wipeConsensusWal()` after writing genesis on a fresh-DB path. A fresh DB is a fresh chain; WAL entries from a previous life reference blocks whose height and hash no longer correspond to anything on the current chain. On an existing DB, the WAL survives a restart — that's the crash-recovery case the WAL exists for.

### 6.12 Equivocation detection and slashing

The only slashing offense in Clarity is **equivocation**: a validator signing two conflicting votes at the same `(height, round)`. This is a mathematical fact — two valid signatures over different block hashes (or one block hash and a nil) from the same key — and it is not subject to interpretation.

Equivocation evidence is collected by each validator as it receives votes. When a validator sees two conflicting votes from the same signer at the same `(height, round)`, it records an `EquivocationEvidence` entry. The evidence is recorded **only if both signatures verify**. A forged conflict — two signatures where one or both fail verification — is dropped rather than stored, because unverifiable evidence poisons the proposer's buffer and blocks it from proposing.

The evidence is stored in memory. It survives across heights (a validator that equivocates at height 100 can be slashed in a block at height 105 if the evidence is still held), but it is bounded by `MAX_EQUIVOCATION_EVIDENCE = 256` and by the rule that each `(signer, height, round)` produces at most one entry.

When a proposer builds a block and has pending equivocation evidence, it includes a `Slash` system transaction for each piece of evidence that verifies. The proposer checks each piece with `verifyEquivocationProof` before including it; only verified proofs are included, and the proposer deduplicates so it doesn't include two `Slash` transactions for the same `(signer, height, round)`. The check is important for unbonded validators: a validator that has left the active set but is still inside its unbonding window must stay slashable, so the proposer's verification does not require the target to be in the active set.

When the block is applied, `executeSystemSlash` runs for each `Slash` transaction: it looks up the validator by id; if the validator is unregistered, no-op; if the validator is a seed, no-op (seeds are slashing-exempt); it reduces the validator's stake by `SLASH_AMOUNT_BPS = 500` (5% of the current stake); it applies the infraction penalty, which reduces the validator's `reward_multiplier` by `REWARD_MULTIPLIER_PENALTY = 2000` bps down to a floor of `REWARD_MULTIPLIER_FLOOR = 2000` bps; and it adds the slashed amount to the pot. The slash is a no-op if the target is ineligible (unregistered, seed, or already at the multiplier floor) — the executor applies policy, not evidence validity, and a policy rejection is not a block rejection. This matters because if ineligibility rejected the block, a proposer could halt the chain by including one such transaction in every block.

When a block containing a `Slash` transaction commits, **every node** scans the block's transactions, decodes each `Slash`, and erases matching evidence from its own pending list. Not just the proposer — every node. Only the proposer knows what it *tried* to include; a non-proposer only sees the block. Reading the block as the source of truth keeps all nodes in sync.

Slashing is not subject to a vote. A proof of equivocation is a mathematical fact, and a Byzantine majority cannot forge a signature. If the majority could vote on whether to slash, it could vote to slash an honest validator — the signatures would be forged, but if the vote is the mechanism, the forgery is irrelevant. Automatic application means the safety argument of BFT is economically enforced: a validator that equivocates loses stake and earnings regardless of what the other validators think about it.

### 6.13 Validator identity and key rotation

Every validator has two keys with independent lifecycles:

- **Reward address.** A user-facing Ed25519 public key, normally backed by a mnemonic keystore. Where the validator's block rewards are paid. Freely changeable via `UpdateRewardAddress`, with no effect on consensus participation.
- **Consensus key.** A 32-byte Ed25519 public key that signs proposals, prevotes, precommits, and timeout attestations. It is the validator's identity for BFT purposes. Mutable via `RotateConsensusKey`, but with restrictions.

Both keys are 32-byte Ed25519 public keys. They can be the same value — a validator that registers with a single key uses it for both roles, which is the default for seeds — but the whole point of the split is that they don't have to be.

A vote or equivocation proof at height H verifies against the key that was **authoritative at H**, not against the validator's current key. This is done via `validatorKeyAtHeight(validator_id, height)`, which resolves the validator's key history to find the entry that covers the given height. The history is a list of `(key, valid_from_height, valid_until_height)` entries, ordered by `valid_from_height`, with half-open intervals; the last entry has `valid_until_height == 0` (current). The ranges are gapless and non-overlapping by construction, so every height in a validator's life has exactly one authoritative key.

The reason for height-scoped verification is that it makes consensus-key rotation compatible with the slashing machinery. A validator that equivocates at height H is slashed by proving two conflicting votes at H. Those votes were signed with whatever key was authoritative at H, which may no longer be the validator's current key. If verification used the current key, the proof would fail. The tight rule preserves the property: **you can only be slashed for votes you were authorized to cast.**

`RotateConsensusKey` appends a new entry to the validator's history and seals the previous one. It is rejected if the new key equals the current effective key, if the caller is not the validator's owner, or if the validator has a pending unbond in flight. The rotation is immediate: the old key stops being valid for new signatures the moment the rotation commits. There is no grace period during which both keys could sign, because that would make the height-scoped lookup ambiguous.

### 6.14 The liveness guarantee

Clarity's consensus guarantees liveness under three assumptions: at least `2f+1` validators of the active set are reachable and honest; messages eventually arrive; and timeouts are bounded. Under these assumptions, the chain produces blocks. The mechanism is round advancement: if a round fails to reach quorum, the round number increments and a new proposer takes over. Eventually a round will have a live proposer and reach quorum.

The `EMERGENCY_ROTATION_ROUNDS` threshold provides a fallback for the case where the committed active set is unable to produce blocks. When 30 consecutive rounds time out, a validator proposes an emergency block with a timeout certificate, and the emergency set replaces the offline members. The emergency rotation is a *liveness* mechanism, not a safety mechanism: it changes which validators are in the active set, but it doesn't change the safety rules. An emergency block still requires a quorum of the emergency set to precommit, and the precommit rules are the same.

The block-production pacing adds a fourth regime: on an idle chain, the 10-second heartbeat ensures a block is produced even when there is no user activity. This is what keeps rewards flowing, epoch boundaries firing, and the chain observably alive.

---

## 7. The application layer: AMM, order book, NFTs

### 7.1 The AMM

#### 7.1.1 The pool

A pool is a record in the state SMT, keyed by `H("pool" || pool_id)`. It holds: the pool id, creator, canonical token pair (`token_a < token_b`), reserves of each, total LP supply, fee in basis points, creation height, an active flag, and three fields for rolling volume tracking.

The canonical ordering is enforced: a pool for (A, B) and a pool for (B, A) are the same pool. There is **no uniqueness constraint** on pairs. A pair can have multiple pools, distinguished by fee tier or creator.

#### 7.1.2 Pool creation

A pool is created by a `CreatePool` transaction. The transaction's `token_id` and `amount` carry one side; the payload carries the other side's token, amount, and the fee. The executor canonicalizes the pair and debits both amounts from the sender. `fee_bps` must be at most `AMM_MAX_FEE_BPS = 1000` (10%); the default is 30 bps (0.3%). Both initial reserves must be at least `MIN_POOL_LIQUIDITY = 1 CLRTY` (100,000 atomic units). The pool's `total_liquidity` is set to `floor(sqrt(amount_a * amount_b))`, computed in 128-bit arithmetic — the Uniswap V2 convention, which gives the initial LP a share proportional to the geometric mean of the two deposits.

#### 7.1.3 Adding liquidity

An `AddLiquidity` transaction adds liquidity to an existing pool. The LP tokens minted is the minimum of `amount_a * total_liquidity / reserve_a` and `amount_b * total_liquidity / reserve_b`, both computed in 128-bit arithmetic. An LP who provides unbalanced amounts is credited at the lesser ratio, effectively donating the excess to the pool. There is exactly **one position per (owner, pool)**: a second `AddLiquidity` from the same owner to the same pool adds to the existing position rather than creating a second one.

#### 7.1.4 Removing liquidity

A `RemoveLiquidity` transaction removes a portion of an LP position. If `amount` is zero, the entire position is removed. The LP receives `amount * reserve / total_liquidity` of each side, floored. If the removal empties the pool's entire LP supply, the LP is credited with the *full* reserves rather than the pro-rated share — a special case because integer rounding can leave dust in the reserves on a pro-rata removal, and a pool with 1 unit on each side and no LP shares is not `isClosed()` and cannot be drained or added to. After the removal, if the pool's reserves are both zero and `total_liquidity` is zero, the pool record is deleted.

#### 7.1.5 The swap formula

A `Swap` transaction swaps one token for the other. The formula is the standard constant-product-with-fee:

```
amount_in_with_fee = amount_in * (10000 - fee_bps) / 10000
amount_out = reserve_out * amount_in_with_fee / (reserve_in + amount_in_with_fee)
```

All arithmetic is integer, with 128-bit intermediates. The result is floored, which favors the pool slightly. `min_amount_out` is the minimum the trader will accept; if the computed `amount_out` is less, the swap fails and the fee is charged but no tokens move. This is what protects the trader from a sandwich.

#### 7.1.6 The fee

The fee is charged on the input side. The difference (`amount_in - amount_in_with_fee`) stays in the pool as additional reserve. It is not distributed to LPs explicitly; instead, the pool's reserves grow, and each LP's share of the pool is worth more when they eventually remove liquidity. This is the standard Uniswap V2 model: an LP who never removes liquidity never realizes the fee; an LP who removes realizes their pro-rata share of the accumulated fees at that moment. There is no separate "claim fees" operation.

#### 7.1.7 Pool closure and volume tracking

A pool is **closed** when `total_liquidity == 0 && reserve_a == 0 && reserve_b == 0`. When a `RemoveLiquidity` transaction brings a pool to this state, the pool record is deleted. The last-LP drain special case guarantees that the final removal of a position always brings the pool to exactly this state, regardless of integer rounding.

Each pool tracks a rolling volume for `OrderConditionType::VolumeBelow`. The window is a tumbling window of `ROTATION_INTERVAL` (60) blocks. Each swap contributes its CLRTY-equivalent amount to `volume_current`. When the current height reaches `volume_window_height + ROTATION_INTERVAL`, the window rolls: `volume_last` becomes the previous window's total, and `volume_current` resets to zero. The roll happens lazily, on the next swap after a window ends. `reportedVolume(current_height)` returns `volume_current` if a full window has elapsed (the roll hasn't happened yet, so the in-progress total is now a complete window), or `volume_last` mid-window.

Volume is denominated in CLRTY. For a swap where one side is CLRTY, the volume contribution is the CLRTY-equivalent of the input amount, computed against the *pre-swap* reserves. For a swap in a pool with **no CLRTY side**, the contribution is zero — there is no oracle to convert token/token trades into CLRTY terms. `VolumeBelow` conditions are therefore meaningful only for pools with a CLRTY side.

#### 7.1.8 LP positions

An LP position is an `AmmPosition` record keyed by `H("pos " || position_id)`. It holds the position id, owner, pool id, liquidity, and creation height. There is **one position per (owner, pool)**. LP tokens are not transferable: they are an accounting unit internal to the position, not a separate token. To change ownership, the owner must remove liquidity and re-add it from a different address. When a position's liquidity is fully removed, the position record stays with `liquidity = 0` and its index entry is deleted — invisible to any indexed query, but present in state.

### 7.2 The order book

#### 7.2.1 The canonical frame

Orders are created directionally: "sell A, buy B, receive at least M of B for N of A." That gives a rational limit price `M/N` in B-per-A. Two orders on opposite sides of the same pair are the same market with reciprocal prices. The book **canonicalizes** to a single direction: `base = min(sell_token, buy_token)`, `quote = max(sell_token, buy_token)`, `price = quote per base`, scaled by `BOOK_PRICE_SCALE = 10^10`.

Rounding is direction-preserving: a seller's limit floors (`floor(min_buy_amount * SCALE / sell_amount)`); a buyer's limit ceils (`ceil(sell_amount * SCALE / min_buy_amount)`). Both round toward the "harder to cross" side, so rounding never invents a fill that the exact rationals would have forbidden.

The book key includes a side byte: side 0 sells the base (an ask), side 1 sells the quote (a bid). The `~canonical_price` is stored in the key, so ascending key order yields best-price-first on both sides. A sequence number, drawn from an SMT global, breaks ties at the same price in FIFO order.

#### 7.2.2 Passive orders

A `Passive` order rests in the book and waits for a taker. Its `pool_id` field must be zero. When a `CreateOrder` transaction creates a Passive order, the executor takes the sell-token lock (debits the seller's balance by `sell_amount`), persists the order record, calls the matching engine (which crosses the order against any resting orders on the opposite side at a compatible price), and adds the order to the book index with a fresh sequence number if it rests. If the order fully filled, the record is deleted and no book row is added.

#### 7.2.3 Active orders

An `Active` order routes against a specific AMM pool, identified by a non-zero `pool_id`. An Active order is executed at one of two points: on creation, if it has no conditions; or at the epoch boundary, if it has conditions. A partially filled Active order rests in state and is re-tried at the next epoch boundary.

#### 7.2.4 Order conditions

An order can carry up to 8 conditions. A condition is a `(type, param1, param2)` tuple:

| Type | Meaning | Valid params |
|---|---|---|
| `ExpiresAtHeight` | Cancel when height >= param1 | `param1 != 0`, `param2 == 0` |
| `PriceAbove` | Cancel if the pool price exceeds `param1 / 10^10` | `param1 != 0`, `param2 != 0` (param2 is the pool id) |
| `PriceBelow` | Cancel if the pool price falls below `param1 / 10^10` | `param1 != 0`, `param2 != 0` (param2 is the pool id) |
| `VolumeBelow` | Cancel if the pool's windowed volume is below `param1` | `param1 != 0`, `param2 != 0` (param2 is the pool id) |
| `BalanceBelow` | Cancel if the owner's balance is below `param1` | `param1 != 0`, `param2 == 0` |

A condition that fails at the epoch boundary causes the order to be **cancelled**, refunding the remaining lock minus `ORDER_CANCEL_FEE_ATOMIC` (1 atomic unit).

#### 7.2.5 Fills

A `Fill` records a partial or complete match. A fill produced by the matcher has `source = Limit` and a `maker_order_id`; a fill produced by the router has `source = Amm`, `maker_order_id = 0`, and a `pool_id`. A client that wants to know whether a fill was a book match or an AMM route reads `source`.

#### 7.2.6 The matching process

The matching engine processes a Passive taker as follows: canonicalize the taker; compute the taker's canonical limit price; collect candidate resting orders from the opposite side of the book, best-price-first, capped at `MAX_BOOK_LEVELS_PER_TAKER = 256`; process candidates in order, stopping at the first candidate that doesn't cross; for each crossing candidate, reject stale rows, handle self-trades, compute the fill quantity as the minimum of the two sides' remainders in base units, execute the fill (move tokens, update both orders' `filled_amount`, write fill history), and persist the taker. The execution price is the resting (maker's) price.

#### 7.2.7 Self-trade

If the taker's owner matches the maker's owner, the resting maker is cancelled and the taker continues to the next resting order. The maker is refunded their remaining lock **in full**; no cancel fee is charged. This is deliberate: the maker posted a resting order in good faith and did not choose to cancel it. Charging the maker a fee for a cancellation triggered by someone else's taker would be a griefing vector. The taker's cost is their own transaction fee.

#### 7.2.8 Cancellation and expiry

An order is removed from the book in three cases: explicit `CancelOrder` (refund minus `ORDER_CANCEL_FEE_ATOMIC`); expiry (if `order_expires_at_height != 0` and the height reaches it); or condition failure at the epoch boundary. All three go through the same `deleteRestingOrder` path, which removes the book row, the companion sequence key, the expiry entry, the SMT record, and every index row. A cancellation cannot leave a book row behind.

#### 7.2.9 Active-order routing

The Active-order router is a pure function of `(StateAccess, Order, height, tx_index)` and runs inside the block processor's write transaction. It handles `OrderExecutionMode::Active`. There are two entry points: on creation (for an Active order with no conditions) and at the epoch boundary (for an Active order whose conditions hold).

The router converts the order's limit to the canonical frame using the same function the matcher uses, then computes the maximum input whose *effective execution price* — output over gross input, including the fee — satisfies the limit. For a constant-product pool, the maximum input is:

```
y_max = reserve_out * SCALE / limit_price_scaled
      - reserve_in * 10000 / (10000 - fee_bps)
```

Both divisions are floored, which biases the result slightly below the true maximum, ensuring the effective price at the returned input is at or above the limit. If the pool's current spot price is already at or below the limit, the pool cannot fill at the limit, and the router returns `Rested`.

`executeActiveOrder` returns one of three outcomes:

- **`Filled`.** At least one fill was produced. The order may be fully filled (record deleted) or have a remainder (record updated). The fills are appended to the caller's fill vector. The pool reserves, the counterparty balance, the order record, the fill-history rows, and the pool volume window are all written in the same call.
- **`Rested`.** Nothing was written. The pool exists and contains the order's pair, but its current price does not permit a fill at the order's limit. The caller leaves the order in state; the next epoch boundary retries it.
- **`Unroutable`.** Nothing was written. The order can never fill against this pool: the pool does not exist, is not active, does not contain both of the order's tokens, has zero reserves on one side, or the order's canonical price overflows. The caller cancels the order.

The distinction between `Rested` and `Unroutable` is load-bearing: a pool that is temporarily unfavorable should not cause the order to be cancelled, but a pool that is gone should.

Routed AMM fills count toward the pool's volume window exactly as user `Swap` transactions do, using the same pre-swap reserves and the same CLRTY-equivalent conversion. A `VolumeBelow` condition on a pool therefore sees both user swaps and Active-order routing against the pool.

#### 7.2.10 Epoch fills commitment

Fills produced by the router *on creation* (an Active order with no conditions) are attached to the `CreateOrder` transaction's receipt and are committed to via `receipts_root`. Fills produced by the router *at the epoch boundary* have no transaction to attach to. They are committed to via a dedicated header field, `epoch_fills_root`, computed as a Merkle root over the serialized fill bytes with an `"efil"` domain tag (as opposed to the `"rcpt"` tag used by `receipts_root`, so a fill and a receipt with identical bytes cannot collide across the two trees).

`BlockProcessor::applyBlock` collects the fills produced by `evaluateOrderConditions` into a local vector, passes it to the caller via `BlockResult::epoch_fills`, and (on the non-dry-run path) verifies that `block.header.epoch_fills_root` matches the computed root. Two failure modes are rejected: a non-null root that doesn't match the computed root (catches a proposer that built the header from a different set of fills than the ones the block actually applies), and a null root with non-empty fills (catches a proposer that omitted the field). An empty `epoch_fills_root` (the null hash) means "no epoch fills" and is the correct value for every non-boundary block.

The same check is performed at *proposal time* in `validateProposal`: a validator will not prevote a block whose `epoch_fills_root` disagrees with the dry-run, so an inconsistent block never reaches the commit path. The invariant is checked twice — once cheaply before voting, once authoritatively on apply — which is what prevents the network from wasting a round on a block that would fail at commit.

The `epoch_fills_root` field is part of the block hash, so a header whose root disagrees with the fills it actually produced is rejected before any state mutation. This is what makes an epoch-boundary fill a first-class consensus event while leaving the per-transaction receipt format unchanged.

#### 7.2.11 Fill history indexing

Every fill — from the matcher or from the router — writes three rows to `TBL_FILL_HISTORY`: one pair-view row (keyed by pair, height, tx index, fill index) and two order-view rows (one for the maker, one for the taker; for an AMM fill, the maker slot is written with the taker's order id and the `source` field distinguishes the two). This is what makes `getPairTrades` and `getOrderFills` a single prefix scan instead of a receipt walk.

A quirk of the fill-history key: the `tx_index_in_block` field is a transaction index for transaction-produced fills and an **order id** for epoch-boundary fills, because an epoch-boundary fill has no transaction. A reader distinguishing the two checks whether the block height falls on a rotation boundary; if so, the "tx index" is an order id.

### 7.3 NFTs

#### 7.3.1 The model

An NFT in Clarity is two things at once: a **shadow token** — a `TokenInfo` record with `maxSupply = 1` and `decimals = 0`, whose id equals the NFT's id, and whose balance table entry is 1 for the NFT's owner — and an `NftInfo` record carrying the metadata (a content hash and/or URI), the collection reference, a `frozen` flag, and, for wrapped NFTs, a reference to an underlying token whose balance is held at the NFT's virtual custody address.

There is no VM, no script, no contract storage. The state layer knows about `NftInfo` directly, the same way it knows about `TokenInfo`, `Order`, and `ValidatorInfo`. An NFT transaction is a typed transaction with a payload, not a call into an interpreter.

#### 7.3.2 Shadow tokens

Every NFT gets a shadow token created alongside it. The shadow token's id equals the NFT's id, drawn from the same monotonic `next_token_id` counter that user-created fungible tokens draw from; a user token and an NFT shadow cannot collide. The shadow's `name` and `symbol` are inherited from the NFT's collection when it has one, or defaulted (`NFT #<id>` / `NFT`) when it doesn't. The owner's balance of the shadow token is 1 while they own the NFT and 0 otherwise.

A shadow token is a token. `getTokenInfo`, `getBalance`, `getTokenHolders`, `getTokenSupply`, and `getTokensForAddress` all return meaningful results for it. `TransferNft` moves the shadow token from seller to buyer as part of the same transaction that updates the `NftInfo` record's owner, so a client that watches token balances sees the change without knowing what an NFT is.

#### 7.3.3 Wrapped NFTs and virtual custody

A wrapped NFT holds an amount of an underlying token in custody, at a virtual address derived from the NFT id:

```
Keys::nftAddress(nft_id) = Blake2b("nfa " || LE(nft_id))
```

This address is in the same 32-byte space as real Ed25519 public keys, so the token-balance table — which keys on address bytes — treats it as an ordinary address. A wrapped NFT's underlying balance is just a normal balance at that address. This has three consequences:

1. **The custody is real.** `getBalance(nftAddress(id), token_id)` returns the wrapped amount. The same SMT proofs, the same historical reads, and the same token-balance indexes apply to the custody as to any other balance.
2. **Refills are ordinary transfers.** `TopUpNft` credits the custody address from the sender. A direct `Transfer` to the custody address also works, though it does not update the `wrapped_amount` field on the `NftInfo` record, so the record and the custody can diverge if a client uses raw `Transfer`. `TopUpNft` is the intended path.
3. **Wrapped NFTs compose with the DEX and AMM.** The underlying holding is a balance like any other; the NFT's shadow token is a token like any other. An NFT that wraps an LP position can be sold as an NFT, or the underlying position can be interacted with directly by the NFT's owner using the custody address.

The `wrapped_amount` field on the `NftInfo` record is a cache of the custody balance, not a separate source of truth. It is updated by `WrapNft`, `TopUpNft`, and `BurnNft`; it is not decremented by `TransferNft`, because a transfer moves ownership of the NFT without moving the custody. The custody stays at the virtual address; only the `NftInfo.owner` and the shadow token's balance table entry change.

A collection has a similar virtual address for its reward escrow:

```
Keys::nftCollectionAddress(collection_id) = Blake2b("nca " || LE(collection_id))
```

Same idea, different domain tag, so a collection's escrow and its NFTs' custody can never collide.

#### 7.3.4 Collections

A collection is an `NftCollection` record. It groups NFTs and optionally carries a reward schedule. It has a name, a symbol, an optional base URI (inherited by NFTs that don't set their own URI), a creator (the only address that can refill the reward escrow), a `minted_count` tracking how many NFTs currently belong to it, and an optional reward schedule (reward token id, rate per NFT per epoch, escrow balance, and a paused flag). A standalone NFT with no collection is the throwaway case. Deleting a collection while NFTs reference it is not supported in v1; `minted_count == 0` is the natural gate for a future `DeleteNftCollection`.

#### 7.3.5 Reward schedules

A collection can carry a reward schedule: a rate per NFT per epoch, drawn from a pre-funded escrow. The schedule is per-collection, not per-NFT, because a 10,000-NFT collection with the same rate for every NFT is 100× cheaper to track as one schedule than as 10,000.

The accrual model is **accrue-then-claim**:

- **At the epoch boundary**, the block processor walks every collection with an active schedule and decrements `reward_escrow_remaining` by `minted_count * reward_rate_per_epoch`. If the escrow cannot cover the obligation, it drains what's left and sets `reward_paused = true`. The epoch boundary does not credit any individual holder; it only moves the escrow.
- **At claim time**, `ClaimNftReward` walks every NFT the caller owns, computes the accrual since the NFT's `last_accrual_height`, credits the caller's `pending_rewards`, and resets `last_accrual_height`. The credits flow through the existing `ClaimRewards` path.

The accounting invariant is that the collection's escrow is the single source of truth. The sum of all pending claims across all NFTs is always ≤ the total the escrow has decremented for. Two mechanisms enforce this: the epoch-boundary decrement is the only place the escrow decreases (a `RefillCollectionReward` is the only place it increases); and a claim never decrements the escrow, it only settles the accrued amount into the holder's `pending_rewards`. Since the escrow decremented at the epoch boundary by the full per-epoch obligation, and every NFT's `last_accrual_height` advances only when the holder acts, the pending claims cannot exceed what the escrow has already accounted for.

The epoch-boundary pass is O(collections), not O(NFTs). It runs **before** the staker early-return in `processEpochBoundary`, because the escrow decrement is independent of whether stakers were paid. If it ran after the return, a chain with an empty pot or no stakers would never decrement any collection's escrow, and NFT reward schedules would silently stall.

Transfers and burns settle accrued rewards to the current owner before the NFT record is updated or deleted, so a seller cannot lose rewards they earned and a buyer cannot claim rewards the seller earned.

#### 7.3.6 Transaction types

There are nine NFT transaction types: `CreateNftCollection`, `MintNft`, `WrapNft`, `TransferNft`, `BurnNft`, `UpdateNftMetadata`, `TopUpNft`, `ClaimNftReward`, `RefillCollectionReward`. Their payloads and state effects are documented in the Transactions reference; the key behaviors are:

- `MintNft` creates a standalone NFT. `collection_id` is optional; if set, the collection's `minted_count` is incremented.
- `WrapNft` mints a wrapped NFT. Takes `wrapped_amount` of an underlying token from the creator, credits it to the NFT's virtual custody address, and writes the `NftInfo` with `underlying_token_id` and `wrapped_amount` set. A wrapped NFT's underlying cannot be the NFT's own shadow token.
- `TransferNft` transfers an NFT. Moves the shadow token balance, updates the `NftInfo.owner`, settles accrued rewards to the seller. Custody does not move.
- `BurnNft` burns an NFT. Deletes the shadow token balance and the `NftInfo` record. If wrapped, the custody is released to the current owner. If in a collection, `minted_count` is decremented.
- `UpdateNftMetadata` changes hash and/or URI. Owner-only. A `frozen` flag can be set, after which no further metadata changes are possible.
- `TopUpNft` credits additional underlying to a wrapped NFT's custody. The token must match the NFT's underlying (for wrapped NFTs) or be any token (for standalone NFTs).
- `ClaimNftReward` settles all of the caller's accrued NFT rewards into `pending_rewards`. The caller then claims normally with `ClaimRewards`.
- `RefillCollectionReward` is creator-only. Adds to a collection's reward escrow and un-pauses it if drained.

#### 7.3.7 Ownership and transfer

An NFT's owner is recorded in two places: the `NftInfo.owner` field and the shadow token balance table (the owner has a balance of 1). Both are updated by `TransferNft` in the same transaction. The shadow token balance is the more general source of truth; the `NftInfo.owner` field is what the executor checks for authorization.

`TransferNft` uses `unindexNft` on the old record before `putNft` on the new record, so the previous owner's `forEachNftForOwner` no longer returns the NFT after the transfer. This is why `putNft` itself does not read the old record: a read inside a write path interleaves with the tree's content-addressed node update buffer and can cause subsequent updates to be silently dropped. The cleanup is the caller's job, and the transfer executor does it explicitly.

---

## 8. Economics

### 8.1 Block reward and issuance

Every block issues a fixed reward in CLRTY. The reward is constant regardless of the block's contents. The reward compensates validators for being *available* to produce blocks, not for the specific work of any one block. The block reward is `BLOCK_REWARD = 1 CLRTY = 100,000 atomic units`.

The reward splits immediately into two pools:

| Pool | Share | Amount at 1 CLRTY |
|---|---|---|
| Validator pool | 60% | 0.60000 CLRTY |
| Staker pool | 40% | 0.40000 CLRTY |

The validator pool splits into a producer bonus (20% of the validator pool, paid to the block's proposer) and a set share (80%, split across the active set).

**Issuance is per-block, and blocks are produced whenever there is pending work (a non-empty mempool) or the 10-second heartbeat has elapsed.** On an idle chain, the heartbeat produces one block per 10 seconds, for a floor of `8,640 CLRTY/day`. On a busy chain, blocks are produced as fast as consensus can run — sub-second in the reference implementation — and issuance scales with activity: there is no ceiling other than consensus throughput. This is a deliberate design: the chain pays for block production when it is being used, and pays a minimal heartbeat when it is not.

The issuance rate is a policy parameter. If emission needs to slow, the lever is `BLOCK_REWARD`, not the block interval. Halving `BLOCK_REWARD` halves the emission without changing the reward split, the validator economics, or the staking APY formula.

### 8.2 Validator rewards

Under the normal path (a mixed active set — at least one non-seed validator): the producer bonus goes to the block's proposer; the set share is split evenly across the active set, weighted by each validator's `reward_multiplier`; a validator with a penalized multiplier receives less, and the difference routes to the pot; any validator ID in the active set with no corresponding validator record has its share routed to the pot. Rewards are paid to each validator's **reward address**, not its consensus key.

Each validator starts with a `reward_multiplier` of 100% (10,000 bps). Two things reduce it: proven infractions (equivocation, verified by an on-chain proof) reduce the multiplier by `REWARD_MULTIPLIER_PENALTY = 2000` bps per infraction; and the multiplier has a floor of 2000 bps (20%). There is no automatic recovery from a multiplier penalty. The only way to reset is to unregister, wait out the unbonding period, and re-register — which forfeits uptime history and the stake that was locked during the unbonding window.

### 8.3 The seed-only path

When **every** validator in the active set is a seed, the normal reward split is replaced by a stipend model: the producer bonus is split evenly across all seeds (with a `remainder` distribution of the integer-division leftover), and the set share (80% of the validator pool) is routed to the pot, along with the staker pool. The rationale is twofold: concentration avoidance (paying two seeds the full validator pool would concentrate wealth in two operator addresses) and registration incentive (a new validator sees a clear benefit to joining: the moment a non-seed enters the active set, normal distribution resumes). The policy fires only when *every* active validator is a seed; a single non-seed in the set resumes normal distribution immediately.

The identity `validator_earnings + pot_earnings == block_reward` holds in every case. No CLRTY is created or destroyed by the split.

### 8.4 Staker rewards and the pot

The staker pool does not pay out per block. Instead, it accumulates in a **pot** on a per-block basis, and the pot is drained at each epoch boundary to pay stakers. At every epoch boundary (every 60 blocks), the protocol attempts to pay stakers a target APY. The distribution follows these rules:

- Stakers are weighted by their staked balance.
- Large balances receive a bonus weight: a staker with a balance ≥ `BALANCE_BONUS_THRESHOLD` (1000 CLRTY) receives an additional `BALANCE_BONUS_BPS = 300` bps of weight.
- Time-weighting scales each staker's share by the fraction of the epoch they were staked for. A staker who joined mid-epoch receives a partial share.
- If the pot can cover the target, everyone receives their full share and the pot is drawn down.
- If the pot can't cover the target, everyone receives a proportional share of what's available, and the pot drains to zero.
- If the epoch's contribution to the pool exceeds the target, the excess flows back to the pot for future epochs.
- If the pot exceeds `POT_MAX`, the excess is burned.

The pot fills from: the 40% staker pool; the set share during seed-only blocks; validator reward multiplier penalties; slash proceeds; unknown validator IDs in the active set. The pot drains from: epoch boundary distributions; burns. The pot is a smoothing buffer, not an accumulator: its balance trends toward a level proportional to the reward rate, not toward infinity. The `POT_MAX` burn is the upper bound that enforces this.

### 8.5 APY mechanism

The target APY at any epoch is composed of three parts:

```
effective_apy = min(APY_BASE_BPS + activity_bonus + pot_bonus, APY_MAX)
```

| Component | Constant | Maximum |
|---|---|---|
| Base | `APY_BASE_BPS = 300` | 3.00% |
| Activity | `APY_ACTIVITY_MAX_BPS = 300` | +3.00% |
| Pot bonus | `APY_POT_BONUS_MAX_BPS = 300` | +3.00% |
| **Cap** | `APY_MAX = 900` | **9.00%** |

The base rate is flat. The activity bonus scales with recent transaction throughput, using the epoch's transaction count (the delta between the `tx_counter` meta value and its snapshot at the previous epoch boundary, divided by `ROTATION_INTERVAL`) as the metric. The pot bonus scales with how full the pot is, relative to `pool_baseline = epoch_pool = staker_pool_per_block * ROTATION_INTERVAL`; it begins above `POT_HIGH` and ramps linearly to its maximum at `POT_MAX`. The cap is a policy limit, not a promise: the target is what the protocol tries to pay, and the actual distribution may be lower if the pot is empty.

The payout is computed deterministically from the state at the epoch boundary, so the exact number a staker receives is knowable in advance of the boundary being processed.

### 8.6 Pot thresholds

The pot thresholds are expressed in epochs' worth of the staker pool:

| Threshold | Constant | Epochs | Wall-clock at 10s nominal |
|---|---|---|---|
| `POT_LOW` | 1 week of undistributed rewards | 1,008 | ~1 week |
| `POT_HIGH` | 1 month | 4,320 | ~1 month |
| `POT_MAX` | 3 months | 12,960 | ~3 months |

The wall-clock figures are computed against the 10-second nominal block interval and are for readability only. The actual number of epochs is what matters: `POT_LOW_EPOCHS`, `POT_HIGH_EPOCHS`, and `POT_MAX_EPOCHS` are derived from `SECONDS_PER_EPOCH = ROTATION_INTERVAL * NOMINAL_BLOCK_SECONDS = 600`, and the pot's wall-clock depth is activity-dependent by construction. On a busy chain, 1,008 epochs is much less than a week; on an idle chain, it is about a week.

### 8.7 Rotation

The active set is bounded between `ACTIVE_SET_MIN = 2` (the BFT floor, and the genesis configuration) and `ACTIVE_SET_MAX = 100`. The *target* size is `ACTIVE_SET_DEFAULT = 11`, scaling toward `ACTIVE_SET_MAX` with traffic. The rotation size is:

```
min(ceil(n / TARGET_ROTATION_EPOCHS), n - bftQuorum(n))
```

where `TARGET_ROTATION_EPOCHS = 21`. The `n - bftQuorum(n)` bound is a safety cap: rotation can never remove so many validators that the remaining set falls below quorum. The `ceil(n / 21)` bound is an epoch-proportional cap: no more than 1/21st of the set rotates per epoch. The smaller of the two wins. At n=100: safety cap = 33, epoch bound = 5, so 5 is the rotation size.

The target-size computation at rotation time uses the boundary block's own transaction count, not the EMA. (The APY activity bonus separately uses the epoch's total transaction count divided by `ROTATION_INTERVAL`; the two metrics are related but not identical, and the docs' earlier conflation of them is noted in the corrections section.)

### 8.8 Slashing and unbonding

Slashing is the economic enforcement of BFT safety. A validator that equivocates loses 5% of its current stake and 2000 bps of its reward multiplier (down to a 2000 bps floor). The slashed stake is credited to the pot. Seed validators are exempt from slashing. A validator that has requested unregistration remains slashable for the full unbonding window; its record, address index, and stake persist for `UNBONDING_PERIOD = 120` blocks (two rotation intervals) before the stake is returned. A proof that lands during the window is applied as normal, and the stake return at expiry is the *post-slash* amount. This closes a specific attack: a validator that equivocates and immediately unregisters cannot escape slashing by racing the proof.

The unbonding window is a policy choice, not a safety requirement. 120 blocks is enough for any honest proposer to include a proof that any peer has observed. A longer delay is strictly safer and only costs the departing validator liquidity.

### 8.9 Total supply

Genesis has an initial supply of 250,000 CLRTY: 249,980 to the treasury and 10 to each of the two seed validators. Total supply increases by the block reward each block; there is no hard cap. The growth rate is bounded by the block reward and the block rate.

---

## 9. Network

### 9.1 Transport

Every connection is a TCP socket, IPv4 or IPv6, driven by a single `io_context`. The maximum message size is 16 MiB. Every message is framed with a 10-byte header (4-byte magic, 2-byte type, 4-byte payload size). The magic is network-specific and derived from the chain ID; a peer that receives a header with the wrong magic closes the connection. The header is always plaintext; the payload is encrypted once the session is established.

### 9.2 Handshake

The handshake runs in four phases:

1. **Version and Verack.** Exchange protocol version, network nonce, timestamp, listen port, agent string, best height. Each side checks the magic, the protocol version, and that the peer's network nonce is not its own (self-connection prevention).
2. **Auth.** Each side sends a 128-byte message carrying its identity public key, an ephemeral X25519 public key, and an Ed25519 signature over `Blake2b(initiator_nonce || responder_nonce || identity_pubkey || ephemeral_pubkey)`. The signature binds the identity, the ephemeral key, and the session nonces.
3. **AuthReady.** An empty message whose AEAD tag is the key confirmation. Neither side encrypts anything before sending its own `AuthReady`, and neither accepts anything encrypted before receiving the peer's. The two `Auth` messages cross on the wire, so `AuthReady` is the synchronization point that ensures neither side starts encrypting under a key the other hasn't derived.
4. **Established.** Application messages flow.

A peer that fails the Auth exchange is closed immediately and reported as misbehaving. An `AuthReady` mismatch closes the peer without a ban — a session-key disagreement is not evidence of misbehavior.

### 9.3 Session encryption

The session key is derived from `X25519(our_ephemeral_secret, their_ephemeral_pubkey)` combined with both ephemeral public keys, both identity public keys, and both network nonces, all hashed through Blake2b with a domain separator. The result is split into two directional keys via labelled Blake2b calls — the lower-nonce side sends under one key and receives under the other, and the roles flip on the higher-nonce side. The ephemeral secret is wiped after key derivation, giving forward secrecy: an attacker who compromises a validator's long-term identity key cannot decrypt past session traffic.

Every message uses XChaCha20-Poly1305 with a 24-byte nonce constructed from an 8-byte per-direction counter, and an AAD that binds the message type and the direction. The direction tag makes reflection (a message sent by A cannot be replayed back to A), type confusion (a `Prevote` cannot be re-framed as a `Precommit`), and cross-direction attacks impossible. The nonce never wraps; the code checks before incrementing and closes the connection if it would overflow.

### 9.4 Sync and relay

A peer that falls behind catches up via `GetHeaders` / `Headers` / `GetBlocks` / `Blocks`. The `SyncManager` per peer drives a small state machine — request headers, receive them, request blocks, apply them, repeat — bounded by `MAX_HEADERS_PER_REQUEST = 2000` and a computed `MAX_BLOCKS_PER_REQUEST` that fits in one message. Blocks are applied through the same `applyCommittedBlock` path consensus uses, so sync and consensus stay consistent. Requests time out (30s for headers, 60s for blocks); timeouts score the peer but don't disconnect.

A `SyncManager` that is caught up periodically re-issues `GetHeaders` (every 30 seconds) so that a peer that commits new blocks while we are idle is discovered without needing a relay message. This is what makes a node self-heal after briefly falling behind.

Block and transaction relay use the same loop-breaking rule: a node that already has the object drops the incoming message without re-broadcasting. For blocks, `chain_db_->hasBlock(hash)`; for transactions, `mempool_->contains(txid)`. Without this rule, a block or transaction would circulate forever.

### 9.5 Proof serving

A client that holds a state root can request a proof for any key at any version via `GetProof` / `Proof`. The request carries a typed descriptor (account address, `(address, token id)` pair, validator id, global state name, or AMM pool id) rather than a raw SMT key, so the client never has to know how keys are derived. The server resolves the descriptor to the same 32-byte SMT key the state layer uses, walks the tree from the requested version's root, and replies with the proof *and* the root it was proven against.

The root travels with the proof because the client's verification must be self-contained: `verifyProof(expected_root, proof)` recomputes the root from the proof and compares. The client does not need to trust that the server picked the right root, because if it picked a wrong one, verification fails. This is what makes a light client possible without syncing the chain. A proof against a version older than the pruning horizon returns `VersionUnavailable`; a key that is not present at the version returns `KeyNotFound`.

### 9.6 Rate limiting

Each peer has a token bucket for its message stream, plus a stricter separate bucket for consensus messages. The per-peer cost table reflects the asymmetry of work: `GetProof` costs 50, `GetHeaders` / `GetBlocks` cost 20, `Block` / `Blocks` cost 10, `Tx` / `Proof` cost 5, control messages cost 1. A peer that floods expensive-to-serve messages is cut off and disconnected.

Above the per-peer buckets is a **node-wide aggregate bucket**. The per-peer bucket bounds what any one peer can do; it does not bound the sum: many peers each staying under their own cap can still saturate the event loop's serving capacity. The aggregate bucket is charged by message type at the same point, using a separate and deliberately *compressed* cost table (`GetProof` costs 10 at the aggregate level, not 50, so a single legitimate proof request does not consume an eighth of the budget). A trip on the aggregate bucket closes the offending connection **without** reporting misbehavior or banning — a peer behind a shared NAT can trip the aggregate budget through no fault of its own.

### 9.7 Peer management

An address book stores known peers, persisted to disk. A ban list records misbehaving peers, with a threshold at which they are banned. Outbound connection maintenance dials enough peers to maintain a target. Inbound connections are bounded by a maximum. Two nodes that dial each other simultaneously are deduplicated by a rule based on their network nonces: the connection dialed by the lower-nonce node is kept.

### 9.8 Consensus startup gate

A validator defers consensus start until it has enough peers to plausibly form quorum: `reachable = 1 + established ≥ bftQuorum(active_set)`. This is a small liveness safeguard — a validator does not start a round it cannot finish — and a startup ordering measure.

---

## 10. Security considerations

### 10.1 The consensus safety proof

The safety claim is: **two honest validators never commit different blocks at the same height.** The proof reduces to three lemmas:

1. **A validator casts at most one prevote and one precommit per round.** The engine's step transitions enforce this; the engine never transitions backward.
2. **A precommit quorum on a block X implies that every honest validator that later precommits has seen a polka for X or has X as its lock or valid value.** This follows from the precommit rules.
3. **An honest validator's lock is only superseded by a polka in a strictly higher round.** This follows from the lock rules.

Combining: if two honest validators commit different blocks at the same height, their precommit quorums intersect in an honest validator, which would have precommitted both blocks in the same round (contradicting lemma 1) or would have violated the lock rules (contradicting lemmas 2 and 3). The full proof is the standard Tendermint safety proof, and the pieces of the code that implement it are named in §6.6.4.

### 10.2 Equivocation and automatic slashing

Equivocation is the only slashing offense. Evidence is recorded only when both signatures verify; a forged conflict is dropped. Slashing is not subject to a vote: a proof is a mathematical fact, and a Byzantine majority cannot forge a signature. Automatic application means the BFT safety argument is economically enforced. The full mechanism is described in §6.12.

### 10.3 Height-scoped key verification

A vote or equivocation proof at height H verifies against the key that was authoritative at H, not the validator's current key. This is what makes consensus-key rotation compatible with slashing. It preserves the property that **you can only be slashed for votes you were authorized to cast.** The key history's ranges are half-open and gapless; every height in a validator's life has exactly one authoritative key. The full mechanism is described in §6.13.

### 10.4 Network security

Peer identity is authenticated before any application message is processed. Session keys are derived from ephemeral X25519 exchanges, giving forward secrecy. Every authenticated message carries an AEAD tag that binds the message type and direction, making reflection, type confusion, and cross-direction attacks impossible. The two rate limiters bound per-peer and total work, with different cost tables for the two scopes so that a single legitimate expensive request does not dominate the aggregate budget. The full mechanism is described in §9.

### 10.5 Known limitations

- **No slashing for liveness failures.** A validator that is offline loses active-set membership, but its stake is not reduced. Only equivocation is slashed. Downtime is often environmental, and slashing for it would punish a validator for a datacenter outage rather than malice.
- **No RPC authentication beyond the admin token.** Read methods are unauthenticated. The metrics endpoint is bound to loopback by default and has no authentication. An operator exposing the RPC endpoint to the public internet should put a reverse proxy in front.
- **No divergence detection or repair.** With the atomic commit discipline, divergence should not be possible. If it happened, the only recovery is to resync from scratch.
- **No cross-network genesis replay protection beyond the chain ID.** The three networks use distinct chain IDs, and no runtime check enforces this beyond the genesis constant.
- **No light-client P2P proofs from the wallet.** The wallet's `balance --verify` requests a proof over RPC and verifies it locally, but the root comes from the RPC endpoint. A fully trustless light client would fetch headers over P2P and follow the header chain itself; that is the next milestone.
- **The consensus WAL and the mempool are not encrypted.** Both are stored in plaintext in the MDBX database. The WAL contains votes the validator signed (not the signing key), and the mempool contains signed transactions. An operator should encrypt the data directory at rest.
- **No hardware-wallet support and no multi-signature accounts.** High-value keys should use the offline `transaction_signer` on an air-gapped machine.
- **No transaction fee market mechanism.** Fees are fixed by the sender; there is no fee auction. A transaction with a low fee may sit in the mempool indefinitely if the block is full.
- **Live SMT tables accumulate stale nodes.** Content-addressed storage never deletes. A mark-and-sweep pass is not implemented in v1; the leak is bounded by the total number of distinct subtrees the chain has ever produced.
- **No per-table byte metrics.** The metrics endpoint reports total DB size and SMT entry counts, but not per-table byte estimates.

---

## 11. Implementation status and open questions

### 11.1 Status

The reference implementation is code-complete and pre-launch. It builds, the full test suite passes, and the end-to-end path has been exercised on a live two-validator regtest. The RPC surface, the wallet layer, the P2P layer with authentication and encryption, and a Prometheus-compatible metrics endpoint are complete and tested. The mainnet and testnet parameters are pinned in `GlobalConfig` (chain IDs, genesis hashes, seed addresses) but the networks are not deployed. The test suite is the acceptance gate; the project reports a pre-launch, code-complete state.

### 11.2 Design choices that are not bugs

- **No batch mint.** Minting N NFTs is N transactions. A batch mint is a convenience gap, not a limitation.
- **No collection deletion.** A collection with NFTs in it cannot be deleted. Deleting an empty collection is not exposed in v1; `minted_count == 0` is the natural gate for a future transaction.
- **No per-NFT reward schedules.** A reward schedule lives on a collection. A per-NFT schedule is roughly 100× more expensive at the epoch boundary. Per-collection is the v1 default; a per-NFT override is an additive change.
- **NFT rewards are claimed, not pushed.** The escrow decrements at every epoch boundary, but the holder's balance is credited only on claim. Pushing would cost one write per holder per epoch, which is unbounded; accrue-then-claim costs one write per claim.
- **AMM positions are not deleted when a pool closes.** The zeroed position record persists, unreachable from any index. Cleaning it up would require a `pool_id → [position_ids]` index or a scan.

### 11.3 Open questions

- **Per-table byte metrics.** `StateDB::tableStats` exists; wiring it into the metrics handler is a few lines. Until it is wired, diagnosing "which table is eating disk space" requires `mdbx_stat`.
- **Live-SMT garbage collection.** A mark-and-sweep pass would bound the stale-node leak. It is not implemented in v1.
- **Wallet P2P light-client.** The wallet verifies proofs locally but trusts the RPC endpoint for the root. A P2P light client that follows the header chain is the next milestone.
- **Batch mint and per-NFT rewards.** Both are additive extensions.
- **The `avg_tx_per_block` divergence.** The active-set target size at rotation uses the boundary block's transaction count, while the APY activity bonus uses the epoch's transaction count divided by `ROTATION_INTERVAL`. The docs' earlier description of an EMA for active-set sizing is not what the code does. Whether this is intentional or should be unified is an open question; the whitepaper describes the code.

---

## Appendix A: Protocol parameters

| Symbol | Value | Unit | Consensus-relevant? |
|---|---|---|---|
| `DECIMALS` | 5 | — | Yes |
| `ATOMIC_UNITS_PER_COIN` | 100,000 | atomic units | Yes |
| `BLOCK_REWARD` | 100,000 | atomic units (1 CLRTY) | Yes |
| `STAKER_SHARE_BPS` | 4,000 | bps (40%) | Yes |
| `VALIDATOR_SHARE_BPS` | 6,000 | bps (60%) | Yes |
| `PRODUCER_BONUS_BPS` | 2,000 | bps (20% of validator pool) | Yes |
| `SET_SHARE_BPS` | 8,000 | bps (80% of validator pool) | Yes |
| `VALIDATOR_MIN_STAKE` | 1,000,000 | atomic units (10 CLRTY) | Yes |
| `AUTO_STAKE_THRESHOLD` | 100,000 | atomic units (1 CLRTY) | Yes |
| `BALANCE_BONUS_THRESHOLD` | 100,000,000 | atomic units (1000 CLRTY) | Yes |
| `BALANCE_BONUS_BPS` | 300 | bps (3%) | Yes |
| `APY_BASE_BPS` | 300 | bps (3%) | Yes |
| `APY_ACTIVITY_MAX_BPS` | 300 | bps (+3%) | Yes |
| `APY_POT_BONUS_MAX_BPS` | 300 | bps (+3%) | Yes |
| APY cap | 900 | bps (9%) | Yes |
| `ACTIVE_SET_MIN` | 2 | validators | Yes |
| `ACTIVE_SET_DEFAULT` | 11 | validators | Target |
| `ACTIVE_SET_MAX` | 100 | validators | Yes |
| `ROTATION_INTERVAL` | 60 | blocks | Yes |
| `TARGET_ROTATION_EPOCHS` | 21 | epochs | Yes |
| `EMERGENCY_ROTATION_ROUNDS` | 30 | rounds | Yes |
| `OFFLINE_CHECK_INTERVAL` | 10 | blocks | Yes |
| `OFFLINE_KICK_BLOCKS` | 20 | blocks | Yes |
| `UNBONDING_PERIOD` | 120 | blocks | Yes |
| `UPTIME_REMOVAL_THRESHOLD_BPS` | 2,500 | bps (25%) | Yes |
| `UPTIME_ACTIVE_MIN_BPS` | 9,000 | bps (90%) | Yes |
| `UPTIME_EMA_ALPHA_BPS` | 2,000 | bps (20%) | Yes |
| `TRAFFIC_EMA_ALPHA_BPS` | 2,000 | bps (20%) | Yes |
| `TRAFFIC_SATURATION_TX` | 1,000 | txs/block | Yes |
| `ACTIVE_SET_UPDATE_INTERVAL` | 600 | blocks | Yes |
| `SLASH_AMOUNT_BPS` | 500 | bps (5%) | Yes |
| `REWARD_MULTIPLIER_START` | 10,000 | bps (100%) | Yes |
| `REWARD_MULTIPLIER_PENALTY` | 2,000 | bps (20 pts) | Yes |
| `REWARD_MULTIPLIER_FLOOR` | 2,000 | bps (20%) | Yes |
| `SEED_SLASH_EXEMPT` | true | — | Yes |
| `NOMINAL_BLOCK_SECONDS` | 10 | seconds | Modelling |
| `MIN_BLOCK_INTERVAL_MS` | 10,000 | ms | Norm, not enforced |
| `SECONDS_PER_EPOCH` | 600 | seconds | Modelling |
| `POT_LOW_EPOCHS` | 1,008 | epochs | Yes |
| `POT_HIGH_EPOCHS` | 4,320 | epochs | Yes |
| `POT_MAX_EPOCHS` | 12,960 | epochs | Yes |
| `AMM_DEFAULT_FEE_BPS` | 30 | bps (0.3%) | Default |
| `AMM_MAX_FEE_BPS` | 1,000 | bps (10%) | Yes |
| `MIN_POOL_LIQUIDITY` | 100,000 | atomic units (1 CLRTY) | Yes |
| `BOOK_PRICE_SCALE` | 10,000,000,000 | — | Yes |
| `ORDER_CANCEL_FEE_ATOMIC` | 1 | atomic units | Yes |
| `MAX_BOOK_LEVELS_PER_TAKER` | 256 | orders | Yes |
| `MAX_EQUIVOCATION_EVIDENCE` | 256 | entries | Node-local |
| `MAX_HEADER_BYTES` | 8,192 | bytes | Yes |
| `MAINNET_SMT_HISTORY_BLOCKS` | 2,048 | versions | Node-local |
| `TESTNET_SMT_HISTORY_BLOCKS` | 512 | versions | Node-local |
| `REGTEST_SMT_HISTORY_BLOCKS` | 64 | versions | Node-local |

Chain IDs: mainnet `0x434C5254` ('CLRT'), testnet `0x434C5454` ('CLTT'), regtest `0x434C5247` ('CLRG').

HRPs: mainnet `clrty`, testnet `tclrty`, regtest `rclrty`.

---

## Appendix B: State key domain tags

| Tag | Function | Payload | Output kind |
|---|---|---|---|
| `acct` | `account` | 32-byte address | SMT key |
| `bal ` | `tokenBalance` | 32-byte address + 4-byte LE token id | SMT key |
| `tok ` | `token` | 4-byte LE token id | SMT key |
| `tsup` | `tokenSupply` | 4-byte LE token id | SMT key |
| `val ` | `validator` | 8-byte LE validator id | SMT key |
| `vadr` | `validatorByAddress` | 32-byte address | SMT key |
| `ord ` | `order` | 8-byte LE order id | SMT key |
| `oexh` | `orderExpiry` | 8-byte LE height | SMT key |
| `glob` | `global` | UTF-8 name (≤64 bytes) | SMT key |
| `pool` | `ammPool` | 8-byte LE pool id | SMT key |
| `pos ` | `ammPosition` | 8-byte LE position id | SMT key |
| `pidx` | `ammPositionIndex` | 32-byte owner + 8-byte LE pool id | SMT key |
| `rcpt` | `receipt` | 32-byte tx hash | SMT key |
| `oseq` | `orderSequence` | 8-byte LE order id | SMT key |
| `vkey` | `validatorKeyHistory` | 8-byte LE validator id | SMT key |
| `nft ` | `nft` | 8-byte LE NFT id | SMT key |
| `ncol` | `nftCollection` | 8-byte LE collection id | SMT key |
| `nfa ` | `nftAddress` | 8-byte LE NFT id (via `blake2b`, not `hashDomain`) | 32-byte address |
| `nca ` | `nftCollectionAddress` | 8-byte LE collection id (via `blake2b`, not `hashDomain`) | 32-byte address |
| `obok` | book pair key | `min(sell,buy)` + `max(sell,buy)` (not in `Keys.h`) | Index key |

The `nfa ` and `nca ` tags are the only two that produce a 32-byte **address** (used as a balance-table key) rather than an SMT key. The domain separation is the same idea; the output type differs because the balance table keys on address bytes.

---

## Appendix C: Genesis configuration

- **Genesis supply:** 250,000 CLRTY.
- **Treasury:** 249,980 CLRTY to address `0x…0001` (a 32-byte address whose last byte is `0x01`).
- **Seed 1:** 10 CLRTY (`VALIDATOR_MIN_STAKE`), reward address per network, consensus key `5a46e6c209758cc54cc1d77f316ae2caa3458d50a2edb1319c4cdf5b958e4f63`.
- **Seed 2:** 10 CLRTY, consensus key `d0c96f3a5b8511a100ea7bc1a0521e09c6258f717d36b1a5e5b4322e32704c15`.
- **Active set:** {seed 1, seed 2}, size 2.
- **Quorum:** `bftQuorum(2) = 2`. Genesis tolerates **zero** Byzantine validators and requires both seeds online for liveness. This is the only configuration in which zero faults are tolerated.
- **Genesis timestamp:** `1767225600000` ms (2026-01-01T00:00:00Z).
- **Pinned genesis hashes:**
  - Mainnet: `eb03ccc1fd7ee6fc85f141183c19d4eabe4876afbc09b8faedb5b8b86264b683`
  - Testnet: `2c6f71f6440e64bd1e80514d2239f88ed62b6a2af6f3e0988dd6afd132438692`
  - Regtest: `571dd8db044a01b6e6c0634f468c50693586cb4f58e956f7f05cf118c0a5a01e`

A genesis-construction change that produces a different hash fails node startup with a "genesis mismatch" error rather than silently diverging from other nodes on the same network.

---

## Appendix D: Claims to source

| Claim | Enforced by |
|---|---|
| State root is canonical for a key set | `SparseMerkleTree.cpp`, `ManyInsertsAreOrderIndependent`, `ApplyBatchMatchesSequential` |
| Dry-run and apply produce the same root | `BlockProcessor::applyBlock`; `MatchingSimulateAndApplyProduceSameRoot`, `MatchingRootIdenticalAcrossFreshInstances`, `NftReward_SimulateAndApplyProduceSameRoot` |
| A validator precommits at most once per round | `enterPrecommit`, `broadcastVote` (never signs a second value for a `(height, round, type)`) |
| A lock is superseded only by a strictly higher-round polka | `enterPrecommit`, `selectPrevoteHash` |
| Votes are recorded regardless of step; only transitions are step-gated | `handleVote` (comment and code) |
| `epoch_fills_root` is checked at proposal time and apply time | `validateProposal`, `applyBlock` |
| Emergency set is deterministic across proposer and verifier | `resolveActiveSet` (single call site) |
| Emergency rotation cannot override a held quorum | `Node::handleIncomingProposal` (`heldQuorumBlock` check) |
| Commit apply retries in place, then halts | `tryApplyCommit`, `haltConsensus` |
| A relay-applied block unsticks the engine | `noteChainHead`, `pollTimers` |
| Blocks are produced when the mempool is non-empty or the 10s heartbeat elapses | `has_pending_work` (mempool non-empty), `MIN_BLOCK_INTERVAL_MS`, `next_propose_not_before_ms_` |
| Votes verify against the height-authoritative key | `verifyVoteSignature`, `validatorKeyAtHeight` |
| Equivocation evidence is recorded only if both signatures verify | `insertVote` |
| Slashing is automatic, not voted | `executeSystemSlash` (no vote path) |
| Evidence is erased by every node on commit | `tryApplyCommit` (scans block for `Slash` txs) |
| The WAL is replayed and votes re-broadcast on restart | `replayWalForHeight` |
| Domain tags prevent cross-namespace collisions | `Keys.h` |
| NFT custody is a real balance at a virtual address | `nftAddress`, token-balance table |
| NFT reward escrow is single-writer | `processEpochBoundary` (only decrement), `RefillCollectionReward` (only increment) |
| NFT reward pass runs before the staker early-return | `processEpochBoundary` (placement) |
| Active-order fills commit via `epoch_fills_root` at the boundary | `evaluateOrderConditions`, `computeEpochFillsRoot` |
| `has_pending_work` is the mempool | `Node::buildConsensusDeps` |
