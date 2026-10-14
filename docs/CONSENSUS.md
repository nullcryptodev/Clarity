# Consensus

How Clarity produces blocks: the protocol, the rules, the safety argument, the failure modes, and the recovery paths.

This document is written for someone who needs to audit the consensus layer, extend it, or understand why a given block was accepted or rejected. It describes the protocol as it exists in the code, not as an aspirational design.

## Table of contents

- [Overview](#overview)
- [The BFT protocol](#the-bft-protocol)
  - [Rounds and steps](#rounds-and-steps)
  - [The three phases](#the-three-phases)
  - [Quorum](#quorum)
  - [Proposer selection](#proposer-selection)
- [Locking and safety](#locking-and-safety)
  - [When a validator locks](#when-a-validator-locks)
  - [The valid-value state](#the-valid-value-state)
  - [Round-crossing recovery](#round-crossing-recovery)
  - [Why these rules are safe](#why-these-rules-are-safe)
- [The block lifecycle](#the-block-lifecycle)
  - [Proposal](#proposal)
  - [Voting](#voting)
  - [Commit](#commit)
  - [The dry-run/apply split](#the-dry-runapply-split)
- [Timeouts and round advancement](#timeouts-and-round-advancement)
  - [Timeout scaling](#timeout-scaling)
  - [Round skipping](#round-skipping)
- [Commit failure handling](#commit-failure-handling)
  - [Retry in place](#retry-in-place)
  - [Halt](#halt)
  - [noteChainHead](#notechainhead)
- [The active set](#the-active-set)
  - [Size bounds](#size-bounds)
  - [Traffic-responsive sizing](#traffic-responsive-sizing)
  - [Rotation](#rotation)
  - [Offline removal](#offline-removal)
  - [Seed protection](#seed-protection)
- [Emergency rotation](#emergency-rotation)
  - [When it triggers](#when-it-triggers)
  - [The timeout certificate](#the-timeout-certificate)
  - [The emergency active set](#the-emergency-active-set)
  - [Verification](#verification)
- [Validator identity and key rotation](#validator-identity-and-key-rotation)
  - [The two keys](#the-two-keys)
  - [Height-scoped verification](#height-scoped-verification)
  - [Rotation and the history](#rotation-and-the-history)
- [Slashing](#slashing)
  - [Equivocation](#equivocation)
  - [Evidence handling](#evidence-handling)
  - [The slash transaction](#the-slash-transaction)
  - [Why slashing is automatic](#why-slashing-is-automatic)
- [The write-ahead log](#the-write-ahead-log)
  - [What the WAL holds](#what-the-wal-holds)
  - [Replay on restart](#replay-on-restart)
  - [The fresh-genesis wipe](#the-fresh-genesis-wipe)
- [The liveness guarantee](#the-liveness-guarantee)
- [The safety argument](#the-safety-argument)
- [What consensus does not do](#what-consensus-does-not-do)

## Overview

Clarity's consensus is a variant of Tendermint-style Byzantine Fault Tolerant (BFT) proof-of-stake. Validators are selected from a bounded active set, rotate at epoch boundaries, and sign blocks in rounds. A block commits when `2f+1` validators precommit it, where `f = (n - 1) / 3` is the maximum number of Byzantine validators the protocol tolerates.

Once a block commits, it is final. There is no fork choice, no longest-chain rule, no probabilistic finality, no reorg. The chain is a linear sequence of committed blocks from genesis forward.

The consensus engine is `Consensus::BftConsensus`. It holds no persistent state of its own; every durable fact lives either in the block headers (for committed blocks) or in the write-ahead log (for the local validator's own votes and locks). A validator that crashes mid-round and restarts replays its WAL, reconstructs its position, and resumes from where it left off without ever signing a conflicting vote.

## The BFT protocol

### Rounds and steps

Consensus proceeds height by height. For each height there is a sequence of rounds; for each round there are three steps:

- **Propose** — the proposer for this round builds a block and broadcasts it.
- **Prevote** — every validator casts a vote for the block it believes should be committed, or a nil vote if it has not seen a valid proposal.
- **Precommit** — every validator casts a second vote, this time for the block that reached a prevote quorum (a "polka") in this round, or for its lock if no new polka formed.

When `2f+1` precommits land on the same block, the block commits and the engine advances to the next height.

If a round fails to reach quorum — the proposer is offline, the network is partitioned, the proposal doesn't arrive in time — the round number increments and a new proposer takes over. The engine may go through many rounds at a single height before committing.

### The three phases

**Propose.** The proposer for round R at height H builds a candidate block, simulates it to compute the state root, fills in the header, signs the proposal, and broadcasts it. The other validators receive the proposal, verify its signature against the expected proposer, deserialize the block, run their own simulation to confirm the state root, and hold it as the candidate for this round. A validator that has already voted in a previous round may re-propose its locked block; the rules for this are covered under locking.

**Prevote.** Once a validator has a candidate block for the round, it casts a prevote for that block. If it has no candidate — the proposal hasn't arrived, or arrived but failed verification — it casts a nil prevote. The prevote commits the validator to a specific block hash for this round; the validator cannot change its prevote within the round.

**Precommit.** When a validator observes a prevote quorum (a polka) for a block within a round, it casts a precommit for that block. If no polka formed — say, the round timed out before enough prevotes arrived — it casts a precommit for its lock if it has one, or nil otherwise. The precommit is the vote that commits; when `2f+1` precommits land on the same block, that block is final.

The three phases exist because a two-phase protocol (propose + vote) cannot guarantee that two honest validators don't commit different blocks in the same round. The prevote phase is where the network agrees on a single candidate; the precommit phase is where the network commits to it. Splitting the two is what gives BFT its safety.

### Quorum

The quorum threshold is `bftQuorum(n) = (n * 2) / 3 + 1`, where `n` is the size of the active set.

| Validators (N) | Quorum | Tolerated faults |
| --- | --- | --- |
| 1 | 1 | 0 |
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

This is the standard BFT safety argument, and it applies here in the standard form.

### Proposer selection

`proposer = active_set[(height + round) mod active_set_size]`.

The proposer rotates deterministically with every height and every round. If the proposer for round R is offline, round R+1 has a different proposer; if that one is also offline, round R+2 has yet another. The rotation is what makes a single offline validator delay the chain by one round rather than halt it indefinitely.

The proposer for a given round is identified by the validator's id, not by its index in the set. The index is a hint that ships in the proposal (for compactness when packing quorum signatures into a committing block), but the id is authoritative. A receiver that resolves the id and finds that the index disagrees rejects the proposal.

This matters when the emergency active set differs from the committed set: index 5 in the committed set is a different validator than index 5 in the emergency set. The id is stable across the two; the index is not.

## Locking and safety

### When a validator locks

A validator **locks** on a block when it precommits to that block after seeing a prevote quorum (a polka) for it. The lock is set at *precommit* time, not at prevote time.

This distinction is important. A validator that prevoted block X but never saw a polka for X is not locked on X. If a new round proposes block Y, the validator is free to prevote Y. Only after observing that a quorum of the active set also prevoted X does the validator commit itself to X.

Once locked, the validator's prevote in any subsequent round is for the locked block, *unless* a newer polka (from a round strictly greater than the lock round) supersedes the lock. The precommit is for the block that reached a polka this round, or for the locked block if no new polka formed.

The lock survives round transitions within a height and is cleared only when the height changes. A validator that locked on X at height H round 3 is still locked on X in round 4, 5, 6, and so on until a new polka (in a round greater than 3) supersedes it.

### The valid-value state

Closely related to the lock is the **valid value**: the most recent block for which the validator has seen a polka. The validator records `(valid_hash, valid_round)` whenever it observes a polka, whether or not it then precommits.

At prevote time, the validator's selection rules are:

1. If the validator has a lock and the lock has not been superseded by a newer polka, prevote the locked block.
2. Otherwise, if the validator has a valid value (from a polka in any round at this height), prevote that.
3. Otherwise, prevote the proposal for this round.
4. Otherwise, prevote nil.

The valid value and the lock are distinct. A validator can have a valid value without a lock (if it saw a polka but didn't precommit before the round advanced), and it can be locked on a block that isn't its most recent valid value (if it locked on X in round N and saw a polka for Y in round N+1 that it didn't have time to precommit before the round advanced again).

The combination is what makes round-crossing recovery work. A validator that was late in round N can, on entering round N+1, still prevote the block that reached a polka in round N — either because it locked on it or because it recorded the polka as its valid value.

### Round-crossing recovery

The subtle case is a validator that times out in round N, has not seen a polka, and sees a proposal for round N+1 before its own timer has fully settled. The validator has not locked on anything, has no valid value, and is free to accept the round-N+1 proposal. This is the standard case and works cleanly.

The harder case is a validator that was on the edge of round N: it saw enough prevotes to form a polka for X but didn't have time to precommit before the round advanced to N+1. On entering N+1, it has a valid value (the polka for X) but no lock. It prevotes X in round N+1. The proposer for N+1 may be proposing Y. The prevote for X doesn't help Y commit, but it doesn't hurt either — the round N+1 polka requires 2f+1 prevotes for Y, and if the network is largely on Y, they'll get there.

The mechanism that makes this work in practice is the proposal queue. A proposal for round N+1 that arrives while the validator is still in round N is stashed and delivered when the local round advances. Combined with the valid-value rule, this means a validator that was on the cusp of forming a polka in round N can still prevote the right block in N+1 without having to have completed the round.

### Why these rules are safe

The safety claim is: **two honest validators never commit different blocks at the same height**.

Suppose validator A commits block X at height H round R, and validator B commits block Y at height H round S, with X ≠ Y. Both commits required a precommit quorum: `2f+1` precommits for X in round R, and `2f+1` precommits for Y in round S.

If R = S, the two quorums intersect in at least `n/3 + 1` validators, of which at least one is honest. That honest validator precommitted both X and Y at the same height and round, which contradicts the protocol — a validator precommits exactly once per round.

If R < S, the safety argument reduces to showing that a precommit quorum for X in round R implies that no honest validator will precommit Y in any later round. This follows from the lock rules: an honest validator that precommitted X is locked on X, and at round S it can only precommit Y if it saw a polka for Y in a round greater than R. But a polka for Y in a round greater than R requires `2f+1` prevotes for Y in that round; and since the polka for X in round R had `2f+1` prevotes for X, the intersection of the two sets contains an honest validator. That validator prevoted X in round R (via the polka) and Y in a later round — but by the valid-value rule, it can only prevote Y in a later round if it saw a polka for Y in a round at least as new as its valid round. Since it had a valid value for X (from the round-R polka), it would need to have seen a polka for Y in a round strictly greater than R. This is possible in principle — a polka for Y in round R+1 exists if 2f+1 validators prevoted Y in R+1 — but it requires the honest validator to have seen the polka for Y and then to have updated its valid value to Y.

The full proof is the standard Tendermint safety proof and holds for the same reasons. The parts that matter for reading the code are: (a) precommits on two different blocks in the same round are impossible for an honest validator; (b) a lock prohibits prevoting anything other than the locked block or a newer-polka block; (c) the polka-on-the-locked-block rule is what makes the "newer polka" condition decidable.

## The block lifecycle

### Proposal

The proposer for round R at height H calls `propose()`:

1. If the validator has a lock or valid value with a known block, re-propose that block. This is the round-crossing case: an honest proposer that locked on X in round N re-proposes X in round N+1, so the network can commit X even after a failed round.
2. Otherwise, build a fresh block: gather transactions from the mempool, compute the transaction root, set the header fields (height, parent hash, timestamp, chain id, proposer, active set, emergency flag if applicable), simulate the block to get the state root, fill in the state root, sign the proposal, and broadcast.

The proposer does not need to know the state root before building the block. It builds the block, simulates it, then fills in the root. This is what makes the dry-run/apply split work.

### Voting

Each validator, on observing a valid proposal for the current round, casts a prevote for that block. The prevote carries the block hash, the validator's id, the validator's index in the set (advisory), and a signature over `voteSigningHash(height, round, is_nil, block_hash)`.

A validator that has no valid proposal for the round by the time its prevote timeout fires casts a nil prevote instead. Nil prevotes do not contribute to a polka; they are a validator saying "I did not see a proposal I could vote for".

Prevotes are received and recorded. When `2f+1` prevotes for the same block hash accumulate, a polka forms. The validator that observes the polka transitions to precommit.

The precommit is analogous: a vote for the block that reached the polka, or for the locked block if no new polka formed, or nil.

### Commit

When `2f+1` precommits for the same block hash accumulate, the block commits. The precommits become the block's `quorum_signatures`. The block is written to the chain, its state transition is applied, the chain head advances, and the engine enters the next height.

The block's `commit_round` is set to the round in which the quorum formed. This may differ from the round the block was proposed in — for example, if a proposal for round R took longer than expected and the network moved on to round R+1 before precommitting, the commit_round is R+1 while the proposal round was R. The `commit_round` field is **excluded from the block hash** precisely because of this case: if it were part of the hash, the hash would change between proposal and commit, invalidating every signature.

### The dry-run/apply split

The block processor distinguishes two paths for a candidate block:

- **Simulate.** The proposer runs the block's state transition with `dry_run = true`. The processor applies the transactions, computes the resulting state root, and aborts the transaction. Nothing is committed.
- **Apply.** Every node that receives a committed block runs the same state transition with `dry_run = false`. The processor applies the transactions, computes the state root, and commits the transaction.

For the block to be accepted by the other nodes, the simulate root and the apply root must be identical. This requires that the two paths make the same state changes.

The invariant that makes this hold is: **every state change that touches the SMT happens on both paths.** Only writes to the meta table and to non-SMT index tables may be gated on `!ctx.dry_run`. The dry-run path aborts its transaction at the end, so any state change it makes is discarded; the apply path commits it. If a change were gated, the two paths would produce different state roots and the block would be rejected.

This invariant has been violated once, in the earliest version of the block processor, and the symptom was that blocks 1 and 2 were committed by consensus but rejected by every node that tried to apply them. The fix was to unify the write paths, and the tests `MatchingSimulateAndApplyProduceSameRoot`, `MatchingRootIdenticalAcrossFreshInstances`, and `NftReward_SimulateAndApplyProduceSameRoot` are the canaries that catch a future violation.

## Timeouts and round advancement

### Timeout scaling

Each round has a timeout that scales exponentially with the round number. Round 0 has the base timeout; each subsequent round doubles it, up to a maximum. The scaling is what makes the network resilient to jitter without liveness loss: a round that times out because a proposal was slow gets a second chance with a longer window.

The timer is driven by `pollTimers()`, which is called from the consensus loop. When the current round's timer expires, the engine advances:

- If in **Propose**, cast a timeout vote and move to **Prevote**.
- If in **Prevote**, cast a timeout vote and move to **Precommit**.
- If in **Precommit**, cast a timeout vote; if a precommit quorum for a block formed, commit; otherwise advance to the next round's **Propose**.

The timeout vote is only broadcast when the round is at or above the emergency rotation threshold (`EMERGENCY_ROTATION_ROUNDS`), because a certificate composed of timeout votes from below that threshold is not useful for emergency rotation.

### Round skipping

A validator that receives a valid proposal for a round much higher than its current round can skip forward. The mechanism is the **round hint**: each vote carries its `(height, round)`, and a validator that observes `f+1` distinct validators at a round higher than its own advances its own round to match.

The rule is: if `f+1` validators (of which at least one is honest) have signed votes at round R' > R, then the network is at least at round R', and a validator stuck at R can safely skip to R'. The skip is bounded: an attacker cannot induce a validator to skip to a very high round, because the votes must be signed by distinct validators in the committed set.

When a skip happens, the validator clears its round hints, updates its `consecutive_timeouts_`, and enters the proposer for the target round. This is what makes the network resilient to a validator that falls behind: rather than waiting for its own timer, it catches up to wherever the majority is.

## Commit failure handling

### Retry in place

When the precommit quorum forms for a block, the engine calls `on_block_committed(block)`. The callback returns a `bool` indicating whether the apply succeeded. If it returns `true`, the engine advances to the next height. If it returns `false`, the engine does **not** advance.

Instead, it retries the apply in place, with a linear backoff:

1. `commit_attempts_` is incremented.
2. `next_commit_attempt_ms_` is set to `now + backoff * commit_attempts_`.
3. The engine returns to its normal poll loop.
4. On the next `pollTimers()` past `next_commit_attempt_ms_`, it calls `tryApplyCommit()` again.

The retry continues up to `max_commit_retries` times.

The reason for retrying rather than advancing the round: the block already has `2f+1` precommits. It is the decided block at this height, and re-proposing it or a different block would violate the safety of the commit. Retrying the apply is the only correct response to a local apply failure.

Advancing the round would also push a validator with a persistent apply failure toward emergency rotation, which is the worst possible response to a local disk problem. The chain's problem is at this node, not at the protocol level; the correct response is to keep trying this node's apply, not to change what block is being applied.

### Halt

If every retry fails, the engine calls `haltConsensus(reason)`:

- `running_` becomes false.
- `halted_` becomes true.
- The round timer is stopped.
- `on_consensus_halt(reason)` is called exactly once.
- `on_height_advanced` does **not** fire.
- The WAL is **not** truncated.
- `pending_height_` is **not** set.

The engine stays halted until the node calls `start()` again. `halted()` is a public accessor that returns the flag.

The halt is deliberately loud. An operator who sees a node halt with the reason "committed block at height H could not be applied after N retries" knows the problem is local storage, not consensus. The node is not making progress, but it's also not corrupting state or losing the block — it's parked on the block it can't apply, waiting for the operator to fix the underlying issue.

### noteChainHead

The other way out of a commit retry loop is for the chain to advance externally. If a relay or sync path applies the block while consensus is retrying — for example, because the node is syncing and another node sent it the block — the node tells the consensus engine.

`BftConsensus::noteChainHead(applied_height)` is lock-free and safe to call from inside any callback. It stores `applied_height + 1` in an atomic. On the next `pollTimers()`, the engine observes that `external_next_height_` is greater than its own target and:

1. Resets `commit_block_`, `commit_attempts_`, and `pending_height_`.
2. Clears the pacing timer.
3. Truncates the WAL to `external_next_height_ - 1`.
4. Enters the new height directly.

This is what makes a node recover gracefully from a stall caused by an external event (a sync that applied the block out-of-band) rather than requiring operator intervention.

## The active set

### Size bounds

The active set is bounded between `ACTIVE_SET_MIN` and `ACTIVE_SET_MAX`, which are 11 and 100 respectively. Below 11, a chain cannot tolerate meaningful Byzantine fault; above 100, consensus message complexity and per-block signature verification costs become prohibitive.

The bounds are enforced at genesis and during every rotation. A rotation that would drop the set below 11 is not applied; a registration that would push the set above 100 is queued in the pool rather than adding to the active set.

### Traffic-responsive sizing

The target size of the active set scales with traffic. `computeTargetActiveSetSize(avg_tx_per_block)` linearly interpolates from `ACTIVE_SET_MIN` at zero traffic to `ACTIVE_SET_MAX` at `TRAFFIC_SATURATION_TX` (1000 tx/block):

```
target = ACTIVE_SET_MIN + (avg_tx * (MAX - MIN)) / SATURATION
```

The interpolation is clamped to `[ACTIVE_SET_MIN, ACTIVE_SET_MAX]`. A chain with heavy traffic has a large active set; a chain with light traffic has a small one.

The reason for scaling: a large validator set gives a chain more fault tolerance, but it also costs more per block (more signatures to verify, more messages to broadcast). On a quiet chain, a large set is overkill; on a busy chain, a small set is under-provisioned. Scaling with traffic lets the chain pay for what it uses.

The average transactions per block is computed as an EMA with `TRAFFIC_EMA_ALPHA_BPS = 2000` (20%). The EMA is updated at every epoch boundary and stored in the global state.

### Rotation

The active set rotates at every epoch boundary (`height % ROTATION_INTERVAL == 0`, with `ROTATION_INTERVAL = 60`). The rotation is sized to `computeRotationCount(active_set_size)`:

```
count = min(ceil(n / TARGET_ROTATION_EPOCHS), n - bftQuorum(n))
```

The two bounds serve different purposes:

- **`ceil(n / TARGET_ROTATION_EPOCHS)`** is the epoch-proportional bound. It turns over the entire active set once every `TARGET_ROTATION_EPOCHS` (21) epochs. At n = 100, that's 5 validators per epoch.

- **`n - bftQuorum(n)`** is the BFT safety bound. Removing more than this many validators from the set at once can drop the remaining set below quorum, because the incoming validators aren't yet confirmed online. At n = 100, quorum is 67, so the safety cap is 33.

Both are computed and the smaller one is used. At n = 100, that's 5 (the epoch-proportional bound). At n = 4, quorum is 3 and the safety cap is 1; the epoch-proportional bound is `ceil(4/21) = 1`; the smaller is 1.

`computeRotationCount` deliberately does not floor the count at 1. If the safety margin is zero — which happens at set sizes where quorum equals the set size, i.e., n = 1, 2, or 3 — the count is 0, and rotation is legitimately impossible. The chain must grow the set before it can rotate.

The selection of who to remove and who to add is deterministic and based on uptime:

- **Remove** the active validators with the lowest `uptime_score`. Ties are broken by `became_active_at`, with earlier becoming-active losing first (old-timers are kept, newcomers are rotated).

- **Add** the waiting validators with the highest `uptime_score`. Ties are broken by `last_active_at`, with more-recently-active winning.

Seeds are never removed from the active set, regardless of uptime. They're excluded from the removable list before selection.

### Offline removal

Independently of normal rotation, the chain runs an **offline check** every `OFFLINE_CHECK_INTERVAL` (10) blocks. The check identifies active validators who have not been seen for at least `OFFLINE_KICK_BLOCKS` (20) consecutive blocks, and removes them.

"Not been seen" means their `last_seen_height` is more than 20 blocks behind the current height. A validator's `last_seen_height` is updated whenever the validator signs a proposal or vote; a validator that stops signing accumulates offline status.

When a validator is removed for being offline, its place is filled from the pool by the same selection rule as normal rotation (highest uptime, most recently active). If the pool is empty, the set shrinks — the chain would rather have a smaller active set than a set that can't produce blocks.

Offline removal does not delete the validator's record. It sets `is_active = false` and updates `last_active_at`, so the validator can re-register or be re-promoted from the pool later.

The grace period of 20 blocks is short enough to recover quickly from a real dropout but long enough to tolerate transient network blips. A validator with an intermittent network connection that's offline for 15 blocks and back for 5 will not be removed.

### Seed protection

The two seed validators declared at genesis are never removed by normal rotation, offline removal, or unhealthy culling. They are the trust anchor for bootstrap, and their removal would require a coordinated hard fork.

The only path that can remove a seed is emergency rotation (see below), and only when the chain is already stalled and the seed's liveness is the reason. This is the one case where a failed seed must be replaced, and the alternative — a chain that never progresses because its trust anchor is offline — is worse than the theoretical downside of a seed being removed.

## Emergency rotation

### When it triggers

Emergency rotation triggers when a validator has observed `EMERGENCY_ROTATION_ROUNDS` (30) consecutive round timeouts at the current height. The constant is set so that 30 rounds at ~5 seconds per round is about 2.5 minutes of stall — long enough that the stall is not a transient network issue, short enough that the chain doesn't wait indefinitely.

The threshold is observed by each validator independently. A validator that has been stalled for 30 rounds sets `consecutive_timeouts_ >= EMERGENCY_ROTATION_ROUNDS`, which makes `useEmergencySet()` return true. When the validator is the proposer, it proposes an emergency block; when it votes, it votes on the emergency set.

### The timeout certificate

An emergency block carries a **timeout certificate**: a set of `f+1` signed timeout votes from the committed set at rounds greater than or equal to `EMERGENCY_ROTATION_ROUNDS`. The certificate is what proves to a verifier that at least `f+1` validators in the committed set observed the stall, which is the threshold for "the committed set is genuinely unable to produce a block".

The certificate is included in the block header, hashed, and the hash is committed to (via the `timeout_certificate_hash` field, which is part of the block hash). A relaying peer cannot strip or swap the certificate without changing the block hash and thus invalidating every signature.

`f+1` is the threshold for "at least one honest validator observed the stall", because at most `f` validators are Byzantine. If `f+1` validators signed a timeout at a high round, then at least one honest validator did, which means the stall was not caused by the honest validators themselves.

### The emergency active set

The emergency active set is computed from the committed set and the validator registry, using the same predicate as offline removal:

```
emergency_set =
    (committed_set - validators_offline_at_current_height)
    + pool_promotions
```

A validator is "offline at current height" if its `last_seen_height` is more than `OFFLINE_KICK_BLOCKS` blocks behind the current height. Pool promotions are chosen by the same uptime-based ordering as normal rotation.

If the pool is empty, the set shrinks rather than the chain halting. A smaller set that can produce blocks is better than a larger set that can't.

Seeds are **not** protected in emergency rotation. A failed seed is exactly what emergency rotation is designed to replace, and the ordinary protections (which apply to normal rotation, offline removal, and unhealthy culling) are disabled here.

The emergency set is derived deterministically from the committed set, the validator registry, and the current height. Every honest node with the same inputs computes the same emergency set. This is what makes an emergency block verifiable by nodes that didn't propose it.

### Verification

A verifier that receives an emergency block checks:

1. The block's `emergency_rotation` field is greater than or equal to `EMERGENCY_ROTATION_ROUNDS`.
2. The block's `emergency_rotation` field is less than or equal to the proposal's round.
3. The `timeout_certificate` is non-empty.
4. `computeTimeoutCertificateHash(timeout_certificate)` matches `timeout_certificate_hash`.
5. The certificate contains `f+1` signed timeout votes from the committed set, all at rounds equal to `emergency_rotation`.
6. The proposal's signature is valid against the emergency active set (which the verifier computes independently).

If any check fails, the block is rejected. If all checks pass, the block is a valid candidate and goes through the normal vote path.

The key invariant is that the verifier's emergency set computation matches the proposer's. Since both are deterministic functions of (committed_set, registry, current_height), and every node reads the same committed_set from state and the same registry from state, the computations agree.

## Validator identity and key rotation

### The two keys

Every validator has two keys with independent lifecycles:

- **Reward address.** A user-facing Ed25519 public key, normally backed by a mnemonic keystore. Where the validator's block rewards are paid. Freely changeable via `UpdateRewardAddress`, with no effect on consensus participation.

- **Consensus key.** A 32-byte Ed25519 public key that signs proposals, prevotes, precommits, and timeout attestations. It is the validator's identity for BFT purposes. Mutable via `RotateConsensusKey`, but with restrictions (see below).

Both keys are 32-byte Ed25519 public keys. They can be the same value — a validator that registers with a single key uses it for both roles, which is the default for seeds — but the whole point of the split is that they don't have to be.

The daemon resolves the signing key via `ValidatorInfo::effectiveConsensusKey()`, which returns `consensus_key` when set and falls back to `reward_address` otherwise. The fallback preserves the pre-split convention: a validator registered before the split signs and verifies with its reward address. New registrations set `consensus_key = reward_address` explicitly, and the first `UpdateRewardAddress` on a legacy validator pins the current effective key so the reward address can move without rotating the signing key.

### Height-scoped verification

A vote or equivocation proof at height H verifies against the key that was **authoritative at H**, not against the validator's current key.

This is done via `validatorKeyAtHeight(validator_id, height)`, which resolves the validator's key history to find the entry that covers the given height. The history is a list of `(key, valid_from_height, valid_until_height)` entries, ordered by `valid_from_height`, with half-open intervals. The last entry has `valid_until_height == 0`, meaning "current". The ranges are gapless and non-overlapping by construction, so every height in a validator's life has exactly one authoritative key.

The reason for height-scoped verification is that it makes consensus-key rotation compatible with the slashing machinery. A validator that equivocates at height H is slashed by proving two conflicting votes at H. Those votes were signed with whatever key was authoritative at H, which may no longer be the validator's current key. If verification used the current key, the proof would fail — and a validator whose key was compromised could be slashed for votes the old key never signed.

The tight rule preserves the property: **you can only be slashed for votes you were authorized to cast**. The `signer_id` field in a vote or proof is stable across rotation; only the key resolution changes.

### Rotation and the history

`RotateConsensusKey` appends a new entry to the validator's history and seals the previous one:

1. Load the current history. If it doesn't exist — a validator registered before the feature — synthesize a single-entry history covering from `registered_at_height` to the current height, using the record's current key.
2. Set the last entry's `valid_until_height` to the rotation height.
3. Append a new entry with the new key, `valid_from_height = rotation_height`, `valid_until_height = 0`.
4. Write the updated history and update the record's cached `consensus_key`.

The rotation is rejected if:
- The new key equals the current effective key (a no-op is a user error).
- The caller is not the validator's `owner` (currently the reward address).
- The validator has a pending unbond in flight (a departing validator should not extend its signing window).

The rotation is immediate. The old key stops being valid for new signatures the moment the rotation commits. There is no grace period during which both keys could sign, because that would make the height-scoped lookup ambiguous: a vote at a height in the overlap window would need to be checked against both keys, and an equivocation proof would lose the property that a single key is authoritative at a single height.

## Slashing

### Equivocation

The only slashing offense in Clarity is **equivocation**: a validator signing two conflicting votes at the same `(height, round)`. This is a mathematical fact — two valid signatures over different block hashes (or one block hash and a nil) from the same key — and it is not subject to interpretation.

Byzantine behaviors other than equivocation (liveness failures, non-participation, malformed messages) are not slashed. A validator that is offline loses active-set membership through the offline-removal path, but its stake is not reduced. Downtime is often environmental; slashing for it would punish a validator for a datacenter outage rather than malice.

The threshold of "two valid signatures over conflicting values" is what makes equivocation provable. Any peer that observes both signatures can construct the proof and include it in a block. There is no ambiguity: the signatures either verify or they don't.

### Evidence handling

Equivocation evidence is collected by each validator as it receives votes. When a validator sees two conflicting votes from the same signer at the same `(height, round)`, it records an `EquivocationEvidence` entry.

The evidence is recorded **only if both signatures verify**. A forged conflict — two signatures where one or both fail verification — is dropped rather than stored, because unverifiable evidence poisons the proposer's buffer and blocks it from proposing. The validity check is `insertVote` in `BftConsensus`, which verifies both signatures against the signer's effective key at the vote's height.

The evidence is stored in memory. It survives across heights (a validator that equivocates at height 100 can be slashed in a block at height 105 if the evidence is still held), but it's bounded by `MAX_EQUIVOCATION_EVIDENCE` (a small constant) and by the rule that each `(signer, height, round)` produces at most one entry.

### The slash transaction

When a proposer builds a block and has pending equivocation evidence, it includes a `Slash` system transaction for each piece of evidence that verifies. The evidence is encoded as the payload of the transaction, and the transaction is added to the block.

The proposer checks each piece of evidence with `verifyEquivocationProof` before including it. Only verified proofs are included; unverifiable evidence is skipped. The proposer also deduplicates: it doesn't include two Slash transactions for the same `(signer, height, round)`.

When the block is applied, `executeSystemSlash` runs for each Slash transaction:

1. Look up the validator by id. If the validator is unregistered, no-op.
2. If the validator is a seed, no-op (seeds are slashing-exempt).
3. Reduce the validator's stake by `SLASH_AMOUNT_BPS` (5% of the current stake).
4. Apply the infraction penalty, which reduces the validator's `reward_multiplier` by `REWARD_MULTIPLIER_PENALTY` (down to a floor of `REWARD_MULTIPLIER_FLOOR`).
5. Add the slashed amount to the pot.

The slash is a no-op if the target is ineligible: unregistered, seed, or already at the multiplier floor. This is deliberate — the executor applies policy, not evidence validity, and a policy rejection is not a block rejection.

### Why slashing is automatic

Slashing is not subject to a vote. A proof of equivocation is a mathematical fact, and a Byzantine majority cannot forge a signature. If the majority could vote on whether to slash, it could vote to slash an honest validator — the signatures would be forged, but if the vote is the mechanism, the forgery is irrelevant.

Automatic application means the safety argument of BFT is economically enforced: a validator that equivocates loses stake and earnings regardless of what the other validators think about it. The only requirement is that some honest validator observes the equivocation and includes the evidence in a block.

### Evidence erasure

When a block containing a Slash transaction commits, **every node** scans the block's transactions, decodes each Slash, and erases matching evidence from its own pending list. Not just the proposer — every node.

The reason is that only the proposer knows what it *tried* to include; a non-proposer only sees the block. Reading the block as the source of truth is what keeps all nodes in sync: every node sees the same Slash transactions in the same block, and every node erases the same evidence.

The erasure happens in `tryApplyCommit` on the success path, after the block has been applied. It uses `decodeSlashEvidence` to extract the `(signer, height, round)` from each Slash and removes matching entries from `equivocations_`.

## The write-ahead log

### What the WAL holds

The consensus engine writes to a write-ahead log before it does anything that could cause a validator to sign a conflicting vote. The WAL holds three things:

- **Votes the validator has signed.** A `(height, round, is_precommit, block_hash, is_nil, signature)` entry. Before signing a vote, the engine appends it to the WAL. After signing, it broadcasts. If the validator crashes between append and broadcast, the vote is durably recorded and can be re-broadcast on restart.
- **Locks the validator has set.** A `(height, round, block_hash)` entry. Before setting a lock, the engine appends it to the WAL. The locked block itself is written to a separate part of the WAL (via `wal_append_locked_block`) so that on restart the validator can re-propose the locked block even if it no longer holds it in memory.
- **The votes the validator has seen.** Not stored in the WAL; the WAL is only for the validator's own actions.

The WAL is keyed by `(height, kind, round, signer_id)` for votes and `(height, kind, round)` for locks. Both use big-endian encoding for the height, so a scan for `height <= H` is a prefix scan that stops early.

### Replay on restart

On startup, `BftConsensus::start(height)` calls `replayWalForHeight(height)` before entering the propose step. The replay:

1. Reads all WAL entries for the given height.
2. For each vote, adds it to `signed_votes_` under the key `(height, round, is_precommit)`. The `emplace` keeps the first entry for each key, so a validator that signed two different votes at the same `(height, round, is_precommit)` — which would be an equivocation — uses the first one. This is a defensive measure: the WAL append happens before the vote is broadcast, so the first append is the binding one.
3. For each lock, restores `locked_`, `locked_hash_`, and `locked_round_`. If multiple locks are present, the one with the highest round wins.
4. If a lock exists, loads the locked block from the WAL, restores it in `proposals_by_hash_`, and sets `valid_set_`, `valid_hash_`, and `valid_round_` from the lock.
5. Re-broadcasts every signed vote. The vote is durable; a peer that never received it before the crash might receive it now.
6. Returns the highest round seen in the WAL, so the engine can resume at that round rather than starting from round 0.

The re-broadcast is what makes the WAL a *liveness* recovery mechanism as well as a safety mechanism. A validator that crashed after signing a prevote but before broadcasting it would, without the WAL, lose the vote. With the WAL, the vote is re-broadcast on restart, and the network can still reach quorum.

### The fresh-genesis wipe

`Node::initGenesis` calls `state_db_->wipeConsensusWal()` after writing genesis on a fresh-DB path. A fresh DB is a fresh chain; WAL entries from a previous life reference blocks whose height and hash no longer correspond to anything on the current chain. If they survived, the consensus engine would replay its own votes for a chain that no longer exists and force the validator to be loyal to a block that no other node recognizes.

On an existing DB, the WAL survives a restart. That's the case the WAL exists for: a validator that crashes mid-round and comes back should resume with the votes it already cast, not forget them and risk signing conflicting votes.

## The liveness guarantee

Clarity's consensus guarantees liveness under the following assumptions:

- **Quorum of honest validators are online.** At least `2f+1` validators of the active set are reachable and honest.
- **Messages eventually arrive.** The network is not permanently partitioned; a message sent by an honest validator eventually reaches its destination.
- **Timeouts are bounded.** A validator's local clock advances; the timeouts eventually fire.

Under these assumptions, the chain produces blocks. The mechanism is the round-advancement rule: if a round fails to reach quorum, the round number increments, and a new proposer takes over. Eventually a round will have a live proposer and reach quorum, and a block will commit.

The `EMERGENCY_ROTATION_ROUNDS` threshold provides a fallback for the case where the committed active set is unable to produce blocks — say, because a majority of it is offline. When 30 consecutive rounds time out, a validator proposes an emergency block with a timeout certificate, and the emergency set replaces the offline members.

The emergency rotation is a *liveness* mechanism, not a safety mechanism. It changes which validators are in the active set, but it doesn't change the safety rules — an emergency block still requires a quorum of the emergency set to precommit, and the precommit rules are the same.

## The safety argument

The safety claim is: **two honest validators never commit different blocks at the same height.**

The proof reduces to three lemmas:

1. **A validator casts at most one prevote and one precommit per round.** The engine's step transitions enforce this. A validator in Prevote has already cast its prevote; a validator in Precommit has already cast its precommit. The engine never transitions backward.

2. **A precommit quorum on a block X implies that every honest validator that later precommits has seen a polka for X or has X as its lock or valid value.** This follows from the precommit rules: a validator precommits X only if it saw a polka for X this round, or if X is its lock.

3. **An honest validator's lock is only superseded by a polka in a strictly higher round.** This follows from the lock rules: the lock is set at precommit time, and it's only replaced when a new polka (from a round strictly greater than the lock round) is observed.

Combining the lemmas: suppose A commits X at round R and B commits Y at round S, with X ≠ Y and R ≤ S.

If R = S, the two precommit quorums intersect in an honest validator. That validator precommitted both X and Y in the same round, contradicting lemma 1.

If R < S, then the precommit quorum for X implies that every honest validator that saw it locked on X (or had X as its valid value). For B to precommit Y at round S, it must have seen a polka for Y in a round greater than R (lemma 2 applied to B). But a polka for Y in a round greater than R requires `2f+1` prevotes for Y in that round, and by the lock rules (lemma 3), no honest validator that had a lock on X (or valid value for X from round R) can prevote Y in a round greater than R unless it saw a polka for Y in a round greater than R — which is circular, and the base case is that no such polka exists at round R or below. The induction holds.

The full proof is the standard Tendermint safety proof. It relies on the standard assumption `f = (n-1)/3` and on the fact that honest validators follow the locking rules.

The pieces of the code that implement the safety argument are:
- The step transition rules in `enterPrevote`, `enterPrecommit`, and `enterCommit`.
- The lock and valid-value updates in `enterPrecommit` and `checkPrevoteQuorum`.
- The prevote selection rule in `selectPrevoteHash`.
- The vote signature verification in `verifyVoteSignature`, which binds each vote to the signer's authoritative key at the vote's height.

## What consensus does not do

- **It does not choose between competing chains.** There are no competing chains. One block commits per height, final.
- **It does not handle long partitions.** A partition that lasts longer than `EMERGENCY_ROTATION_ROUNDS` triggers emergency rotation, but a partition that lasts for many hours or days will eventually run out of pool candidates and leave the chain with a small active set. This is a liveness limitation, not a safety one.
- **It does not perform dynamic quorum adjustment mid-round.** The quorum threshold is fixed at the start of each round and doesn't change when a validator is removed for being offline. The offline removal happens at the offline-check boundary, not mid-round.
- **It does not vote on slashing.** Slashing is automatic; there is no governance mechanism for it.
- **It does not have a fork choice rule.** There is no "pick the longest chain" or "pick the heaviest chain". There is one chain, and the block that committed is the block that committed.
- **It does not retroactively invalidate blocks.** Once a block commits, it's final. A validator that commits a block and later equivocates doesn't invalidate the block; it slashes the validator. The block stays.
- **It does not have a slashing mechanism for liveness failures.** Offline validators lose active-set membership, but their stake is not reduced. Only equivocation is slashed.