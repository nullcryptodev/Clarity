# Design

Clarity's architecture is the result of a series of decisions, each made to solve a specific problem. This document is organized around those decisions: what the problem was, what the choice was, and what it costs. It's not a reference; it's the reasoning a contributor needs before proposing a change.

The intent is that someone who reads this document before reading the code sees the code as obvious rather than surprising. The code follows the reasoning here. When the code doesn't, that's a bug — either the code drifted, or the reasoning is stale and this document needs updating.

## Table of contents

- [The core principles](#the-core-principles)
  - [State is a Merkle tree, not a database of accounts](#state-is-a-merkle-tree-not-a-database-of-accounts)
  - [Everything is a first-class state object](#everything-is-a-first-class-state-object)
  - [State transitions are pure functions](#state-transitions-are-pure-functions)
  - [One block, one round, final on commit](#one-block-one-round-final-on-commit)
- [The write model](#the-write-model)
  - [Writes write; callers read when they need to](#writes-write-callers-read-when-they-need-to)
  - [Non-SMT writes may be gated on dry_run; SMT writes may not](#non-smt-writes-may-be-gated-on-dry_run-smt-writes-may-not)
  - [Every state change is atomic with the block that caused it](#every-state-change-is-atomic-with-the-block-that-caused-it)
  - [The prune is part of the commit](#the-prune-is-part-of-the-commit)
- [The tree](#the-tree)
  - [Compressed radix, not fixed-depth](#compressed-radix-not-fixed-depth)
  - [Canonical by construction](#canonical-by-construction)
  - [Content-addressed, deduplicated, and unpruned](#content-addressed-deduplicated-and-unpruned)
  - [Companion keys, not widened records](#companion-keys-not-widened-records)
  - [Domain-separated key derivation](#domain-separated-key-derivation)
- [Consensus](#consensus)
  - [BFT with immediate finality](#bft-with-immediate-finality)
  - [The dry-run/apply split](#the-dry-runapply-split)
  - [Retry the block, don't advance the round](#retry-the-block-dont-advance-the-round)
  - [Height-scoped key verification](#height-scoped-key-verification)
  - [Automatic slashing](#automatic-slashing)
  - [System transactions never reject the block](#system-transactions-never-reject-the-block)
- [The economy](#the-economy)
  - [Epoch-based staking, block-based validators](#epoch-based-staking-block-based-validators)
  - [Accrue-then-claim, not pay-per-epoch](#accrue-then-claim-not-pay-per-epoch)
  - [The pot as a smoothing buffer](#the-pot-as-a-smoothing-buffer)
  - [Rotation bounded by BFT safety](#rotation-bounded-by-bft-safety)
  - [Seed validators as a bootstrap anchor](#seed-validators-as-a-bootstrap-anchor)
- [The transaction model](#the-transaction-model)
  - [Typed transactions, not a scripting VM](#typed-transactions-not-a-scripting-vm)
  - [No contract storage, no interface discovery](#no-contract-storage-no-interface-discovery)
  - [Every NFT is also a token](#every-nft-is-also-a-token)
  - [Custody as a virtual address](#custody-as-a-virtual-address)
- [The network](#the-network)
  - [Pull metrics, not push](#pull-metrics-not-push)
  - [Two rate limiters, two cost tables](#two-rate-limiters-two-cost-tables)
  - [The aggregate trip doesn't ban](#the-aggregate-trip-doesnt-ban)
  - [AuthReady synchronizes encryption](#authready-synchronizes-encryption)
- [The interface](#the-interface)
  - [Encoders are presentation, codecs are data](#encoders-are-presentation-codecs-are-data)
  - [Hex on the wire, integers internally](#hex-on-the-wire-integers-internally)
  - [Bech32m everywhere user-facing](#bech32m-everywhere-user-facing)
- [What this buys, and what it costs](#what-this-buys-and-what-it-costs)

## The core principles

### State is a Merkle tree, not a database of accounts

Clarity's persistent state is a **single Merkle tree** whose root is committed into every block header. Every account, token, validator, order, pool, NFT, and global value has exactly one position in the tree. The root is a 32-byte hash that commits to all of them.

The alternative — a relational database with a separate "state hash" computed at block boundaries — has two problems. First, it makes proofs harder: a client can't verify a fact about the state without trusting the server that produced the hash or re-executing the chain. Second, it makes consensus harder: two nodes with the same logical state must compute the same hash, which means the hash function must be a canonical function of the state, which is exactly what a Merkle tree is and what a relational database isn't.

Every read and every write in `StateAccess` routes through the tree. There is no side table that participates in consensus but isn't in the tree. The tree's root is the state root, full stop.

The consequence is that a state change of any kind — a balance update, an order creation, a validator rotation — walks O(log N) nodes and rewrites the path from leaf to root. That's the cost of a Merkle tree, and it's the price paid for proofs, light clients, and canonicity.

### Everything is a first-class state object

An NFT is not a contract. A token is not a contract. An AMM pool is not a contract. An order is not a contract. They are all records in the state tree, indistinguishable at the state layer from an account: each has a key, a serialized value, and a position in the SMT.

This is a deliberate rejection of the general-purpose contract model. There is no VM, no bytecode, no storage slots, no interface discovery, no ABI. A token is a `TokenInfo` record with a name, symbol, decimals, and supply. An NFT is a `NftInfo` record plus a shadow token. A pool is an `AmmPool` record with reserves and a fee. An order is an `Order` record with a pair, a limit, and conditions.

The consequence is that adding a feature means adding a record type and a transaction type, not writing a contract. The executor knows about `TokenInfo`, `AmmPool`, `Order`, `NftInfo`, `NftCollection`, and `ValidatorInfo` directly. The RPC layer exposes them as first-class objects. The state layer treats them as opaque blobs at their SMT positions. There is nothing that has to be "called" to observe or modify them.

The cost is that Clarity can't do arbitrary things. A user can't deploy a novel DEX design, a lending protocol, or a derivative without a hard fork. That is intentional. The feature set that does exist — the DEX, the AMM, the NFT system — is curated, tested, and consistent. It's the same bet Uniswap V1 made against a general VM, generalized to a chain.

### State transitions are pure functions

Every state change inside `applyBlock` is a pure function of the block and the state it runs against. Nothing reads wall-clock time, local peer state, hardware entropy, or any other non-deterministic source.

This is why the emergency rotation decision lives in the block header rather than a per-node timer. A validator can look at its own clock to decide *whether* to set the flag on a block it proposes, but only the *value* it sets goes into the block, and only the block feeds the state. Two honest nodes that receive the same block reach the same state regardless of when they received it or what their local clock says.

The same rule holds for the matching engine, the Active-order router, the validator key-history maintenance, and the NFT reward accrual. They read nothing but their arguments: a `StateAccess`, the record being processed, and the height/round. There is no shared mutable state, no thread-local context, no ambient time.

The consequence is that a proposer can simulate a block to compute its state root without committing anything, and the resulting root is what the block header will carry. Any node that later applies the same block computes the same root. This is what makes the dry-run/apply split possible, and the dry-run/apply split is what makes the BFT proposal phase work at all.

The cost is that any feature that would naturally depend on wall-clock time — say, a "swap expires in 30 seconds" order — has to express its condition in terms of block height instead. That's a small constraint in practice and it's what makes consensus tractable.

### One block, one round, final on commit

Clarity's consensus produces exactly one canonical block per height. There is no fork choice, no longest-chain rule, no probabilistic finality, no reorg. Once a block reaches precommit quorum, it is the block at that height, and no competing block can ever displace it.

This is the standard BFT model and it has a well-understood cost: the chain stalls if fewer than `2f+1` validators are online, where `f` is the number of Byzantine validators tolerated. There is no "the honest majority produces blocks anyway" fallback. The network either has quorum or it doesn't.

The consequence is that everything downstream can assume a linear, append-only sequence of blocks. There are no side chains, no uncles, no orphaned blocks to reconcile. The state at height H is a function of the blocks at heights 0 through H, and nothing else.

The cost is a liveness assumption that Bitcoin doesn't have. Bitcoin produces blocks with a single miner even if 99% of the network is offline. Clarity produces blocks only if a supermajority of the active set is online and coordinated. The trade-off is that Clarity's finality is immediate: a block at height H is final in the same second it commits, and no client ever has to wait N confirmations. For a chain whose purpose is DEX and AMM activity, immediate finality is worth the liveness cost.

## The write model

### Writes write; callers read when they need to

Every `putX` method on `StateAccess` is a pure write. It reads nothing before it writes. Every `deleteX` is a pure delete. When a caller needs to inspect an old record — say, to clean up its index rows before writing a new version — the caller reads the old record first, then calls a dedicated unindex method, then calls the new `putX`.

The rule exists because a read inside a write path interleaves with the tree's content-addressed node update buffer in a way that can cause subsequent updates in the same or a later transaction to be computed against a stale root and silently dropped. The exact mechanics are subtle: the tree's `updateRecursive` is stateful across a single call, and a read between writes can leave the recursion with a stale view of the subtree it's about to modify.

This was learned the hard way during NFT development. An early `putNft` read the old record first to unindex it, and the result was that a reward-pass update in a subsequent transaction was silently lost. The fix was to make `putNft` a pure write and move the read to the caller, which is where every other `putX` already had it. The rule is now documented on every `putX` method so a future change doesn't reintroduce the pattern.

The consequence is that the write path is uniform: no `putX` has side effects on the read side, and every caller that needs to know the old state reads it explicitly. This makes the write path cheaper (no wasted reads) and easier to reason about (a `putX` is exactly the write it says it is).

### Non-SMT writes may be gated on dry_run; SMT writes may not

The block processor has two paths for a block: a *dry-run* path used by the proposer to simulate a block before its state root is known, and an *apply* path used by every node that receives a committed block. Both paths must produce the same state root, byte for byte, or the proposer's block will be rejected on apply.

The rule that makes this hold is: **every state change that touches the SMT happens on both paths.** Only writes to the meta table and to non-SMT index tables may be gated on `!ctx.dry_run`. The dry-run path aborts its transaction at the end, so any SMT write it makes is discarded; the apply path commits it. If a change were gated, the two paths would disagree on the root and the block would be rejected.

This invariant was violated once, in the earliest version of the block processor, and the symptom was that blocks 1 and 2 were committed by consensus but rejected by every node that tried to apply them. The fix was to unify the write paths, and the `MatchingSimulateAndApplyProduceSameRoot`, `MatchingRootIdenticalAcrossFreshInstances`, and `NftReward_SimulateAndApplyProduceSameRoot` tests are the canaries that catch a future violation.

The consequence is that the block processor's dry-run and apply paths are structurally identical except for the final `txn.commit()` vs. `txn.abort()`. A contributor adding a new state-changing operation to the executor doesn't have to know which path it will run on; it runs on both.

### Every state change is atomic with the block that caused it

The block processor opens a single MDBX write transaction per block, applies the block's transactions, writes the block index and the chain head, runs the retention prune, and commits. Either all of it lands or none of it does.

This is why state and chain data share one MDBX file. If they were separate files, the atomic commit would have to be simulated with a two-phase commit, and any crash between the two phases would leave the DB in a state where the block was committed but the state wasn't (or vice versa). With one file, MDBX's own transaction gives the invariant for free.

The consequence is that a crash at any point leaves the DB at a consistent block boundary. The WAL exists separately for consensus-internal state (the votes a validator has signed, the locks it holds) and is not part of the atomic commit; its purpose is to make sure a validator that crashed mid-round can't sign a conflicting vote after restart.

### The prune is part of the commit

Historical pruning runs inside the block-commit transaction, before `txn.commit()`. It is not a separate pass or a background task. A prune failure aborts the entire block commit.

This is a deliberate choice. A storage failure that prevents pruning is a real problem: if the prune failed silently, the historical tables would grow unbounded behind a warning, and an operator might not notice until the disk filled. By making the prune part of the commit, a prune failure halts the block processor and surfaces the problem. The consensus retry mechanism then retries the block; if the retries are exhausted, the engine halts loudly with a `halted()` flag and an `on_consensus_halt` callback.

The consequence is that the retention window is *exact*: after block H commits, the oldest retained version is exactly `H - smt_history_blocks`. There is no grace period, no throttling, no "the prune will catch up eventually". A node's historical tables are always bounded by the configured window, and the bound is tight.

## The tree

### Compressed radix, not fixed-depth

The state tree is a **compressed radix trie**: a Patricia-trie-style structure where a chain of single-child internal nodes is collapsed into a single branch carrying the shared prefix. The tree's height is O(log N) in the number of leaves, not the fixed 256 a non-compressed binary trie would require.

This is not a micro-optimization. A fixed-depth binary trie writes 256 rows per state update — one per level of the tree — regardless of how many keys actually exist. A compressed radix trie writes O(log N) rows, and for a chain with a million accounts that's about twenty. The difference is a factor of ten to a hundred in storage growth, and it's the difference between a chain that can run on commodity hardware and one that can't.

The trade-off is complexity. The insert and delete logic in a Patricia trie has to handle splitting a leaf into a branch, splitting a branch at a divergence point, and collapsing a branch after a delete. The `SparseMerkleTree::updateRecursive` implementation is the most intricate code in the state layer, and its correctness relies on two invariants (see below) that a fixed-depth trie doesn't need.

The consequence is that the state layer's write cost is bounded by the *content* of state, not by the tree's nominal depth. A chain that grows its state slowly stays cheap to update; a chain that churns its state heavily pays proportionally to the churn, not to the tree's height.

### Canonical by construction

The tree's root is a pure function of its key set. Two nodes with the same accounts, tokens, orders, pools, and NFTs produce the same root, regardless of the order in which those objects were created or how many times they were updated. This is what makes the tree a Merkle commitment rather than a log.

The property is enforced by two invariants:

1. **Every branch consumes at least one bit.** A branch's prefix length plus its branching bit is the number of key bits that branch consumes. Since prefix length is bounded by 256 and every descent consumes at least one bit, the tree's height is bounded by the key length and by the number of distinct keys.

2. **No branch has a default child.** When one of a branch's children becomes empty (as a result of a delete), the branch is *collapsed*: it's replaced by the surviving child with an extended prefix. The result is that every branch in a well-formed tree has two non-default children.

Together, these invariants make the tree a canonical representation of its key set. The `ManyInsertsAreOrderIndependent` and `ApplyBatchMatchesSequential` tests cover this; the earlier split-on-insert bug (which used the shared prefix from bit 0 rather than from the current position) produced order-dependent roots and was caught by these tests before it could affect the network.

### Content-addressed, deduplicated, and unpruned

The tree stores nodes by content hash, not by path. A node whose subtree didn't change between two versions has the same hash at both versions and is stored once. A node whose subtree changed has a different hash and is stored separately.

The consequence is that historical state grows with *state changes*, not with block count. A chain that produces a million blocks with no state changes has no historical growth; a chain that produces ten blocks with a million state changes has a lot. This is exactly the property you want if the goal is to serve historical proofs against recent versions.

The flip side is that the *live* tree also accumulates stale nodes. When a branch is rewritten (a leaf split, a branch collapse), the old branch's hash is no longer reachable from the current root, but its row is still in `TBL_SMT_NODES`. Content-addressed storage doesn't delete. Over time, the live tables grow with the total number of distinct subtrees the chain has ever produced, not with the current tree's size.

This is a known cost and it's currently unbounded. For a chain that grows its live state monotonically — new accounts, new tokens, new pools — the leak is small relative to the live tree itself. For a chain that churns its state heavily, it's a candidate for future mark-and-sweep garbage collection. It's not a v1 concern.

### Companion keys, not widened records

Adding a new feature to a state record almost never means widening the record. Instead, the new feature gets a **companion key** — a separate SMT key in a different namespace, holding its own value, updated alongside the record it accompanies but stored independently.

The validator's consensus-key history is the canonical example. `ValidatorInfo` is a fixed-layout record with a stable wire format; adding a history field would hard-fork every previously serialized record. Instead, the history lives under `Keys::validatorKeyHistory(id)`, a separate SMT leaf holding a list of `(key, from, until)` entries. The record's `consensus_key` field remains a cache of the current key; the history is the source of truth.

The same pattern appears in the order book's sequence companion (`Keys::orderSequence(order_id)`) and in the NFT shadow token (a separate `TokenInfo` keyed by the NFT's id). The rule is: if a feature's state doesn't fit cleanly into an existing record's layout, give it a companion key.

The consequence is that a new feature can be added without a codec change. Existing records continue to decode and verify. A legacy validator whose history was never written falls back to its `effectiveConsensusKey()`, which is the same answer the pre-feature code would have given.

### Domain-separated key derivation

Every state object's key is `Blake2b(domain4 || payload)`, where `domain4` is a 4-byte ASCII tag identifying the object's kind. Two different kinds of objects can never collide, even if their payloads happen to be identical. An account and a validator with the same address bytes hash to different keys because their domains are different.

Once a domain tag is deployed, it must never change. Changing a tag moves every key in that namespace, orphaning the state it references. The tags are part of the chain's identity, the same as the block format and the consensus rules.

The consequence is that the state layer is extensible without collision risk. A new feature adds a new domain tag; existing tags continue to mean what they always meant. The `Keys::*` namespace in `SparseMerkleTree.h` is the single source of truth for what each tag means, and adding an entry there is a hard-fork-level decision.

## Consensus

### BFT with immediate finality

Clarity uses a variant of Tendermint-style BFT with three phases per round: propose, prevote, precommit. A block commits when `2f+1` validators precommit it, and once committed it is final.

The consequence is that there is no fork choice. A block at height H is the block at height H. No competing block can displace it. Clients don't wait for confirmations; the first block they see is the block they can act on.

The cost is a liveness assumption. Below quorum, the chain stalls. There's no difficulty adjustment, no fallback to a probabilistic rule. The emergency rotation mechanism (which derives a replacement active set when the committed set can't form quorum) is the only escape, and it's a coordinated, on-chain decision rather than an implicit one.

### The dry-run/apply split

The block processor distinguishes between *simulating* a block (the proposer needs to know what state root a candidate block would produce) and *applying* a finalized block (every other node commits it). The dry-run path runs the same state transition as the apply path, but with a different set of preconditions:

- **Dry-run skips** structural header checks, quorum verification, and the state-root comparison.
- **Apply runs** all of them.

The dry-run path is used by the proposer to compute the state root that the block header will carry. Once it has the root, it fills it in, signs the block, and broadcasts. The other nodes apply it and verify that the state root matches what their own state transition produces.

The invariant that makes this work is that the *state changes* are identical on both paths. Only the *verification* differs. This is why the "every SMT write happens on both paths" rule exists. If a state change were gated on the apply path, the dry-run's root would differ from the apply's, and the block would be rejected.

The consequence is that the proposer doesn't have to have the state root before it starts building a block. It builds the block, simulates it to get the root, and updates the header. This is what makes the BFT proposal phase tractable: the proposer can iterate.

### Retry the block, don't advance the round

A failed `on_block_committed` callback is not treated as a failed round. The block already has `2f+1` precommits; advancing the round would re-propose a block every honest validator is locked on and would push a validator with a persistent apply failure toward emergency rotation — the worst possible response to a local disk problem.

Instead, the consensus engine retries the same block with a linear backoff, up to `max_commit_retries`. If every retry fails, it halts: `running_ = false`, `halted_ = true`, `on_consensus_halt` fires once. No height advance, no WAL truncation, no `pending_height_`.

The other way out is `noteChainHead(Height)`. If a relay or sync path applied the block while consensus was retrying, the node calls `noteChainHead` to tell the engine the chain has already moved; the next `pollTimers` abandons the retry and enters the reported height directly.

The consequence is that the consensus engine's view of the chain stays consistent with the actual chain head. It doesn't march forward to height N+1 while the chain is stuck at N. And operators get a loud, observable signal (`halted()`, `on_consensus_halt`) that something is wrong with storage rather than with consensus.

### Height-scoped key verification

A vote or equivocation proof at height H verifies against the key that was authoritative at H, not against the validator's current key. This is what makes consensus-key rotation compatible with the slashing machinery.

If verification used the current key, a validator that rotated would escape any pending equivocation proof against its old key. Worse, a validator whose old key was compromised could be slashed for votes that the old key never signed (because a different key would fail the current-key check and thus look like equivocation). The tight, height-scoped rule preserves the property: you can only be slashed for votes you were authorized to cast.

The key history's ranges are half-open and gapless. Every height in a validator's life has exactly one authoritative key. If the ranges overlapped, an equivocation proof would be ambiguous about which key to check against.

The consequence is that consensus-key rotation is safe. A validator can rotate to a fresh key without losing the ability to be slashed for past misbehavior, and without accidentally becoming slashable for behavior it never authorized.

### Automatic slashing

A proof of equivocation is a mathematical fact: two valid signatures over conflicting values at the same `(height, round)` from the same key. It is not subject to a vote. A Byzantine majority could vote to slash an honest validator, but it cannot forge a signature. Automatic application means the safety argument of BFT is economically enforced: a validator that equivocates loses stake and earnings regardless of what the other validators think.

The evidence is encoded in the block itself, as a `Slash` system transaction. When a block containing a `Slash` commits, every node scans the block's transactions, decodes each `Slash`, and erases matching evidence from its own pending list. Every node does this, not just the proposer. Reading the block as the source of truth is what keeps all nodes in sync.

Evidence is recorded only when both votes' signatures verify. A forged conflict is dropped rather than stored, because unverifiable evidence poisons the proposer's buffer and blocks it from proposing.

### System transactions never reject the block

A system transaction whose target is ineligible for the operation — a `Slash` against a seed, an unregistered validator, or a validator with nothing left to slash — is a no-op at the transaction level, not a block rejection. The distinction is load-bearing. If ineligibility rejected the block, a proposer could halt the chain by including one such transaction in every block it produced.

Validity of the *evidence* is enforced upstream (`verifyEquivocationProof`), and a malformed proof is rejected before the transaction enters the block. But the executor's policy checks are permissive: they apply the effect if the target is eligible, and do nothing if it isn't.

This is a general principle: a system transaction that the chain itself generates must not be a vector for one validator to halt the chain. The same rule applies to every future system-transaction type.

## The economy

### Epoch-based staking, block-based validators

Validator rewards are distributed every block. Staker rewards are distributed every epoch (60 blocks). The asymmetry keeps the per-block state transition cheap: the block-level reward path only touches validator records, while the epoch-boundary path does the O(stakers) work of distributing accumulated rewards.

The NFT collection reward accrual joins the epoch-boundary pass. The per-epoch obligation is `minted_count * reward_rate_per_epoch`, computed once per collection, so the pass is O(collections), not O(NFTs). A chain with a million NFTs across a hundred collections pays a hundred SMT writes per epoch, not a million.

The consequence is that the per-block cost is bounded and predictable. A block that produces a hundred transactions doesn't do a hundred times the reward work of a block that produces one; it does the same reward work plus the transaction work.

### Accrue-then-claim, not pay-per-epoch

Staker rewards and NFT rewards both use the **accrue-then-claim** model. At the epoch boundary, the pot is credited or the collection's escrow is decremented by the total obligation. Holders' balances are updated only when they claim.

The alternative — pushing rewards to every holder at the epoch boundary — would cost one SMT write per holder per epoch, which is unbounded. Accrue-then-claim costs one write per claim, which is bounded by activity. For a chain with a thousand stakers, the difference is a thousand writes per epoch versus (say) ten writes per epoch that roughly a thousand stakers collectively make.

The invariant that makes the model sound is that the accumulator is the single source of truth. For staking, the pot holds the rewards; for NFT collections, the escrow holds them. A claim never decrements the accumulator; it only settles the accrued amount to the holder. Since the accumulator was decremented at the epoch boundary by the full obligation, and every holder's accrual clock advances only when they claim, the sum of all pending claims can never exceed what the accumulator has accounted for.

### The pot as a smoothing buffer

The pot accumulates staker rewards when activity is low and releases them when activity is high. It decouples the staker payout from the current block's activity, giving a more stable APY.

The pot is the destination for every unallocated reward: validator pool remainders when the active set contains unknown validator IDs, reward multiplier penalty differences, seed-only set shares, and slash proceeds. When it grows past `POT_HIGH_EPOCHS` epochs' worth of baseline, the APY calculation stops adding a pot bonus, which keeps a well-funded pot from inflating staker rewards forever.

The consequence is that the staking APY has a floor (from activity) and a ceiling (from pot contribution), and the two are independent. A quiet epoch with a full pot still pays stakers reasonably; a busy epoch drains the pot slowly.

### Rotation bounded by BFT safety

Validator rotation is bounded by two independent caps:

- `n - bftQuorum(n)` — the maximum number of validators that can be removed without risking the set falling below quorum if the incoming validators aren't yet confirmed online.
- `ceil(n / 21)` — the epoch-proportional bound, which turns the set over once over `TARGET_ROTATION_EPOCHS` epochs.

Both bounds are applied and the smaller one wins. At `n = 100`, the safety cap is 33 and the epoch bound is 5, so 5 is the rotation size. At `n = 4`, the safety cap is 1 (since `bftQuorum(4) = 3`), and the epoch bound is 1, so 1 is the rotation size.

The consequence is that rotation can never break quorum, regardless of what happens to the incoming validators. A validator that fails to come online doesn't compromise the chain's liveness; the rotation was sized assuming the worst.

### Seed validators as a bootstrap anchor

Every network's genesis declares two seed validators. They are the initial active set and they are never removed by normal rotation, offline removal, or unhealthy culling. Emergency rotation is the one path where they can be dropped, because the chain is already stalled and a failed seed is exactly what needs to be replaced.

The consequence is that a new chain always has a live, coordinated set of validators to bootstrap from. Without seeds, genesis would have to declare an empty set and the chain would never produce a block. With seeds, the chain produces blocks from the first second, and new validators can register and be promoted at the first epoch boundary.

The trust assumption is explicit: seeds are the project's own nodes. A chain whose seeds go offline stalls, which is why they're the last thing to be dropped and why they're the only validators the project is expected to operate directly.

## The transaction model

### Typed transactions, not a scripting VM

Every transaction is a typed payload with a fixed structure. `Transfer` has `to`, `amount`, `token_id`. `CreateOrder` has a pair, a sell amount, a minimum buy amount, a mode, an optional pool id, an expiry, and up to eight conditions. `MintNft` has a collection id, a metadata hash, and a URI. There is no scripting language, no bytecode, no contract that runs.

The consequence is that the transaction's effects are fully determined by its type and its payload. There is no way to hide behavior in a script, no way to make a transaction that does something surprising. An auditor who reads the transaction types knows everything the chain can do.

The cost is that adding a new behavior means a hard fork. There is no way for a user to deploy something the chain doesn't already know about. This is the same trade-off as "everything is a first-class state object": it's a bet that a curated feature set with a strong, consistent implementation beats a flexible platform with unpredictable emergent behavior.

### No contract storage, no interface discovery

Because there are no contracts, there is no per-contract storage and no interface discovery. Every state record is at a well-known key derived from the record's identity. A client that knows a token's id can find its metadata, its supply, its holders, its transfers, and its pool positions by calling the corresponding RPC methods. There is no "what's this token's ABI?" step.

The consequence is that a client's job is to know the state schema, not to discover it at runtime. This is what makes the RPC surface stable and the state layout auditable. Adding a field to `TokenInfo` requires an RPC method update; adding a new record type requires new RPC methods. There is no way for a contract deployer to add a method that the RPC doesn't know about.

### Every NFT is also a token

An NFT in Clarity is two things at once: a `NftInfo` record carrying the metadata and ownership, and a *shadow token* — a `TokenInfo` record with `maxSupply = 1` and `decimals = 0`, whose id equals the NFT's id, and whose balance table entry is `1` for the NFT's owner.

The consequence is that every existing token mechanism works on NFTs without special-casing. `getTokenInfo` returns the shadow's metadata. `getBalance` returns `1` for the owner. `getTokenHolders` returns the owner. The DEX and AMM treat the NFT as a tradeable asset with a supply of one. A proof of "who owns NFT 42" is a proof of the shadow token's balance at the NFT's id.

The alternative — a separate NFT namespace that the DEX and AMM don't understand — would have required special-casing every token operation to check "is this an NFT?". The shadow token avoids that by making an NFT just a token with `maxSupply = 1`.

### Custody as a virtual address

A wrapped NFT holds an underlying token balance at a *virtual address* derived from the NFT's id: `Keys::nftAddress(nft_id) = Blake2b("nfa " || LE(nft_id))`. This address is in the same 32-byte space as real Ed25519 public keys, so the balance table treats it as an ordinary address.

The consequence is that the custody is a real balance. It participates in proofs, historical reads, and the by-token balance index the same way every other balance does. A client that wants to see the wrapped amount calls `getBalance(nftAddress(id), token_id)`, the same call it makes for any other address. A client that wants to verify a wrapped NFT's backing can request a Merkle proof against the balance table entry at the custody address, and it verifies with the same `verifyProof` function used for every other proof.

The alternative — storing the custody as a field on the `NftInfo` record — would have required every balance query to know about NFTs. The virtual-address approach keeps the state layer uniform: there are accounts, and there are balances, and an NFT's custody is just a balance at an account whose key is derived from the NFT's id.

## The network

### Pull metrics, not push

The metrics endpoint is a pull endpoint. A Prometheus-compatible scraper asks for metrics, and the node answers. The node never sends anything.

The consequence is that an unreachable monitoring system causes zero work at the node. A push-based model would have to buffer, drop, or back off when the push target was down, and every one of those choices is a failure mode. A scrape-based model has no such failure mode; if the scraper isn't there, nothing happens.

The same principle applies to the endpoint's isolation. It's on its own port, its own worker pool, and its own rate limiter, so a scrape can't starve the RPC server and an RPC flood can't starve a scrape. RPC endpoints are frequently exposed to the public internet; metrics endpoints frequently are not. The two should be independently configurable, and they are.

### Two rate limiters, two cost tables

Every peer has a per-peer token bucket that charges messages by type. Above that, there's a *node-wide aggregate bucket* that charges the same messages with a compressed cost table.

The per-peer bucket bounds what any one peer can do. The aggregate bucket bounds the sum. Without the aggregate bucket, a hundred peers each staying under their per-peer cap could still saturate the io_context thread's serving capacity.

The two tables are deliberately different. The per-peer table charges `GetProof` a cost of 50 (because serving one proof is roughly 50× a control message). The aggregate table charges it 10. The reason is that a single legitimate proof request shouldn't consume 20% of a modest aggregate budget; the aggregate budget is there to bound floods, not to charge fairly. Expensive types still cost more than cheap ones, but not proportionally so.

### The aggregate trip doesn't ban

When the per-peer bucket trips, the peer is reported as misbehaving, and a threshold of misbehaviors leads to a ban. When the aggregate bucket trips, the offending connection is closed but the peer is not reported and not banned.

The reason is that a peer behind a shared NAT can trip the aggregate budget through no fault of its own. The budget is node-wide; if a legitimate but chatty application behind one NAT exhausts it, every peer behind that NAT is implicated. Banning an IP would punish all of them. The correct response is to shed the message and close the connection, not to blacklist.

### AuthReady synchronizes encryption

The handshake has four phases: `Version` (exchange identifying info), `Verack` (acknowledge), `Auth` (signed challenge-response with ephemeral key), and `AuthReady` (encrypted confirmation).

The `Auth` messages cross on the wire. A peer that sends `Auth` may not yet have received the peer's `Auth`, which means it may not yet know the peer's ephemeral key and therefore cannot yet derive the session key. The `AuthReady` message is the synchronization point: neither side encrypts anything before sending `AuthReady`, and neither accepts anything encrypted before receiving the peer's. The message itself is empty; its AEAD tag is the confirmation that both sides derived the same key from the same inputs.

The consequence is that a session-key disagreement is detected before any application data flows. If the two sides derive different keys (a bug, a version mismatch, or an active attacker), the `AuthReady` tag fails to verify and the peer is closed. A wrong key produces a failing AEAD, not a false acceptance.

## The interface

### Encoders are presentation, codecs are data

The RPC layer has its own encoders (`Rpc::encodeAccount`, `Rpc::encodeToken`, etc.) that produce JSON for clients. These are *not* the same as the state codecs (`Account::serializeState`, `TokenInfo::serializeState`, etc.) that produce the bytes stored in the SMT.

The distinction is deliberate. The state codec has to be fixed forever — it's part of the chain's identity, and changing it changes the state root. The RPC encoder can change — it's a client interface, and if a field is added or renamed, clients can adjust. The RPC encoder emits hex strings for numbers, bech32m for addresses, and human-readable names for enum values. The state codec emits raw little-endian integers, raw 32-byte addresses, and raw bytes.

The consequence is that RPC changes don't require a fork and state changes don't require an RPC change. The two evolve independently, and the only invariant is that the RPC encoder produces JSON that faithfully represents the underlying state record.

### Hex on the wire, integers internally

Every number on the RPC wire is a `"0x"`-prefixed hex string, even for small values like counts and enum codes. The reason is JavaScript. Numbers above 2^53 lose precision in IEEE-754 doubles, and every JSON parser that follows the JavaScript convention (which is most of them) has the same problem. A balance of 10^18 atomic units is exactly the kind of value that a JSON number can't represent accurately.

The alternative would be to serialize small values as JSON numbers and large values as hex strings, which is worse: it makes the wire format depend on the value, which means a client can't know the type of a field without knowing its magnitude. Uniformly hex-encoded numbers are unambiguous, at the cost of a few extra bytes per field.

The same rule applies to addresses (bech32m strings, not raw bytes) and hashes (`"0x"`-prefixed hex, always 32 bytes). Every user-facing field has a single canonical representation, and every client parses it the same way.

### Bech32m everywhere user-facing

Addresses are bech32m strings with distinct HRPs per network (`clrty`, `tclrty`, `rclrty`). The same underlying 32-byte Ed25519 public key encodes to a different string on each network, so a mainnet address used on testnet is rejected with a clear error rather than silently accepted.

The alternative — raw hex addresses — works but has no network check and no checksum. A typo produces a valid-looking address that goes to the wrong destination. Bech32m's checksum catches typos, and the HRP catches network mix-ups. The cost is a longer string, which matters less than the possibility of losing funds to a typo.

The rule is that any user-facing surface — the RPC, the wallet CLI, the address utility — emits bech32m. Raw hex is accepted on input for tooling, but the canonical form is bech32m. The one exception is the consensus key, which is a signing key rather than an address and is emitted as raw hex; the distinction matters because a client that can't tell a signing key from an address can't tell which one to use for a given operation.

## What this buys, and what it costs

The design decisions above are unified by a single principle: **the chain is a state machine whose state is committed by a Merkle tree, and every operation on that state is a pure function of its inputs.** Everything else follows.

The consequence is a chain that is provable, auditable, and reproducible. A light client can verify a fact about the state without syncing the chain. An auditor can trace every state change from a transaction to a root update. Two nodes with the same state produce the same root. Two nodes with the same block produce the same state.

The cost is that the chain is less flexible than a general-purpose VM. Features must be designed into the protocol. New behaviors require forks. Some operations that would be natural in a contract-based chain — composability, callbacks, reentrancy — don't exist.

The bet is that this trade-off produces a better chain for the specific things Clarity does: a native currency, a token system, a DEX with a limit-order book and AMM routing, and NFTs with on-chain rewards. For those things, the pure-function model gives provability, determinism, and predictability. For arbitrary computation, it doesn't, and doesn't try to.

The document you're reading describes why each choice was made. When the code and this document disagree, one of them is wrong; the code is the ground truth, and this document should be updated to match it. When a future change would contradict one of the principles here, the principle should be examined first. Some of them are load-bearing; others are conveniences that can be revisited. The ones that are load-bearing are the ones whose violation produces a bug — the state-root mismatch, the stale update, the equivocation that can't be proven. Those are the invariants the chain depends on.