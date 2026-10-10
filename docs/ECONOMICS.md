# Economics

## Overview

Clarity's economic model has four moving parts:

1. **A fixed block reward** issued every block, split between validators and stakers.
2. **A validator pool** distributed across the active set, weighted by uptime and penalized by infractions.
3. **A staker pool** that accumulates in a pot and is distributed at epoch boundaries.
4. **A slashing and penalty system** that reduces both stake and future earnings for provable misbehavior.

The design goal is a chain where block production is a scheduled service, rewards are predictable enough to plan around, and validator misbehavior is economically punished without requiring a vote.

## Block reward

Every block issues a fixed reward in CLRTY. The reward is constant regardless of the block's contents — empty blocks and full blocks pay the same. This is deliberate: the reward compensates validators for being *available* to produce blocks, not for the specific work of any one block. A validator that is in the active set during an idle period has already done the work that matters (registered, staked, stayed online), and the protocol has no other way to compensate that ongoing service.

The reward splits immediately into two pools:

| Pool | Share | Purpose |
|---|---|---|
| Validator pool | 60% | Compensates the active set for producing blocks |
| Staker pool | 40% | Compensates stakers for locking value |

At the current block reward of 10 CLRTY:

| Pool | Amount |
|---|---|
| Validator pool | 6 CLRTY |
| Staker pool | 4 CLRTY |

## Validator pool

The validator pool splits into two further components:

| Component | Share of validator pool | Amount at 10 CLRTY block reward | Recipient |
|---|---|---|---|
| Producer bonus | 20% | 1.2 CLRTY | The block's proposer |
| Set share | 80% | 4.8 CLRTY | Split across the active set |

The producer bonus rewards the validator whose turn it was to propose. The set share rewards everyone who was in the active set for that block, whether or not they were the proposer.

## Validator rewards

Under the normal path (a mixed active set — at least one non-seed validator):

- The producer bonus goes to the block's proposer.
- The set share is split evenly across the active set, weighted by each validator's `reward_multiplier`.
- A validator with a penalized multiplier receives less; the difference routes to the pot.
- Any validator ID in the active set with no corresponding validator record has its share routed to the pot. This shouldn't happen in practice; it's a defensive path.

Rewards are paid to each validator's **reward address**, not its consensus key. Moving the reward address redirects future rewards without affecting the validator's ability to sign consensus messages.

### Uptime and reward multiplier

Each validator starts with a `reward_multiplier` of 100% (10,000 basis points). Two things reduce it:

- **Proven infractions** (equivocation, verified by an on-chain proof) reduce the multiplier by `REWARD_MULTIPLIER_PENALTY` per infraction.
- The multiplier has a **floor of 20%** (2,000 bps). It never goes below this.

There is **no automatic recovery** from a multiplier penalty. A validator that equivocates and later behaves correctly continues to earn at the reduced rate indefinitely. The only way to reset the multiplier is to unregister, wait out the unbonding period, and re-register — which forfeits uptime history and the stake that was locked during the unbonding window.

### Uptime score

Each validator has an uptime score, tracked as an exponential moving average updated based on how many pings they respond to during each epoch. The score determines eligibility for the active set:

| Threshold | Effect |
|---|---|
| Below `UPTIME_REMOVAL_THRESHOLD_BPS` (25%) | Removed from the validator pool entirely |
| Below `UPTIME_ACTIVE_MIN_BPS` (90%) | Removed from the active set, but stays in the pool |

A validator that's removed from the active set for low uptime can be re-promoted by rotation if its uptime score recovers.

## Seed-only reward policy

When **every** validator in the active set is a seed, the normal reward split is replaced by a stipend model:

- The **producer bonus** is split evenly across all seeds. The producing seed earns no more than any other seed — seeds are operated as a single entity, and the distinction between producing and signing is bookkeeping noise.
- The **set share** (80% of the validator pool) is routed to the pot, along with the staker pool.

The rationale is twofold:

1. **Concentration avoidance.** Paying two seeds the full validator pool on a chain with no other validators would concentrate wealth in two operator addresses.
2. **Registration incentive.** A new validator looking at the reward math sees a clear benefit to joining: the moment a non-seed enters the active set, normal distribution resumes, and the seeds stop absorbing the pool.

The policy fires only when *every* active validator is a seed. A single non-seed in the set resumes normal distribution immediately.

**Degenerate case: one seed.** If the active set is a single seed, the seed earns the full producer bonus, and the set share plus staker pool route to the pot.

**Invariant.** The identity `validator_earnings + pot_earnings == block_reward` holds in every case. No CLRTY is created or destroyed by the split.

## Staker rewards

The staker pool does not pay out per block. Instead, it accumulates in a **pot** on a per-block basis, and the pot is drained at each epoch boundary to pay stakers.

### Auto-staking

Staking is automatic and liquid. An account with balance ≥ `AUTO_STAKE_THRESHOLD` is enrolled in auto-staking unless it has opted out via `OptOutStaking`. Opting out disables rewards but does not lock or withdraw funds; the account can opt back in at any time. Seed addresses, by default, are automatically opted out for concentration avoidance.

### Epoch boundary distribution

At every epoch boundary (every 60 blocks), the protocol attempts to pay stakers a target APY. The distribution follows these rules:

- **Stakers are weighted** by their staked balance.
- **Large balances receive a bonus weight** (see below).
- **Time-weighting** scales each staker's share by the fraction of the epoch they were staked for. A staker who joined mid-epoch receives a partial share.
- **If the pot can cover the target**, everyone receives their full share and the pot is drawn down.
- **If the pot can't cover the target**, everyone receives a proportional share of what's available, and the pot drains to zero.
- **If the epoch's contribution to the pool (this epoch's 40% of block reward) exceeds the target**, the excess flows back to the pot for future epochs.
- **If the pot exceeds its maximum**, the excess is burned.

### Balance bonus

Stakers with a balance at or above `BALANCE_BONUS_THRESHOLD` receive an additional weight bonus of `BALANCE_BONUS_BPS` when their reward share is computed. The bonus is applied to the weight, not the payout — it's a way of scaling rewards up for larger stakers without a separate reward pool.

## APY mechanism

The target APY at any epoch is composed of three parts:

```
effective_apy = min(
  APY_BASE_BPS + activity_bonus + pot_bonus,
  APY_MAX_BPS
)
```

| Component | Constant | Maximum |
|---|---|---|
| Base | `APY_BASE_BPS` | 5.00% |
| Activity | `APY_ACTIVITY_MAX_BPS` | +5.00% |
| Pot bonus | `APY_POT_BONUS_MAX_BPS` | +3.00% |
| **Cap** | `APY_MAX_BPS` | **13.00%** |

### Base rate

5% flat, applied regardless of chain activity. This is the "baseline return for staking" — it's what a staker earns just for participating in the staking pool, without any additional incentive.

### Activity bonus

Scales with recent transaction throughput, up to +5%. The metric is the epoch's transaction count divided by the number of blocks in the epoch. Higher throughput means a higher bonus, which pulls more stake into the pool during busy periods.

The activity metric uses two counters stored in the node's meta table:

- `tx_counter` — the chain-lifetime transaction count, incremented on every applied block.
- `tx_counter_at_epoch_start` — a snapshot of `tx_counter` taken at the previous epoch boundary.

The delta between them is the epoch's contribution. This is measured *before* any early-return paths in the epoch boundary processing, so it's updated once per epoch unconditionally. A regression that placed the snapshot inside a conditional path would cause the activity reading to drift.

### Pot bonus

Scales with how full the pot is, up to +3%. The bonus begins above `POT_HIGH` and ramps linearly to `APY_POT_BONUS_MAX_BPS` at `POT_MAX`. Above `POT_MAX`, the bonus is capped, and the excess pot is burned.

The pot bonus is a release valve: when the pot grows past its high threshold, the protocol incentivizes stakers to draw it down. This prevents the pot from accumulating indefinitely on chains where staker participation is low relative to the rate at which the pool fills.

### Cap

The effective APY is capped at 13%. This is a policy limit, not a promise — the target is what the protocol *tries* to pay, and the actual distribution may be lower if the pot is empty.

The payout is computed deterministically from the state at the epoch boundary, so the exact number a staker receives is knowable in advance of the boundary being processed.

## Pot mechanics

The pot is the accumulation account for every unallocated reward in the system. It fills from:

1. **The 40% staker pool** — every block contributes 40% of the block reward to the pot.
2. **The set share during seed-only blocks** — 80% of the validator pool routes to the pot when the active set contains only seeds.
3. **Validator reward multiplier penalties** — the difference between a penalized validator's reduced share and the full share routes to the pot.
4. **Slash proceeds** — stake slashed from an equivocating validator is credited to the pot.
5. **Unknown validator IDs in the active set** — an active validator ID with no record gets its share routed to the pot.

The pot drains from:

1. **Epoch boundary distributions** — the target staker payout draws from the pot each epoch.
2. **Burns** — when the pot exceeds `POT_MAX`, the excess is destroyed.

### Pot thresholds

The thresholds are expressed in terms of epochs' worth of staker pool:

| Threshold | Constant | Approximate duration at 60-second blocks |
|---|---|---|
| `POT_LOW` | 1 week of undistributed rewards | 168 hours |
| `POT_HIGH` | 1 month | ~720 hours |
| `POT_MAX` | 3 months | ~2,160 hours |

These are modeled on the chain's nominal block time assumption (`NOMINAL_BLOCK_SECONDS`). If blocks are produced faster than nominal, the thresholds are reached in less wall-clock time; if slower, more. The thresholds are best understood as "number of epochs' worth of staker pool," not as fixed durations.

The `POT_MAX` value is intentionally large. On a chain with low staked value, the burn threshold may never be reached, and the pot simply accumulates. The burn path exists to bound the pot's growth, not to actively police it.

## Total supply

Genesis has an initial supply of **100,000 CLRTY** on mainnet, allocated as follows:

| Allocation | Amount | Purpose |
|---|---|---|
| Treasury | 58,000 CLRTY | Project operations, seed validator funding |
| Community | 40,000 CLRTY | Community distribution, ecosystem grants |
| Seed validator 1 | 1,000 CLRTY | Bootstrap the first seed validator |
| Seed validator 2 | 1,000 CLRTY | Bootstrap the second seed validator |

Total supply **increases by the block reward each block**. There is no hard cap. The growth rate is bounded by the block reward, which is a fixed constant. At one block per minute and a 10 CLRTY reward, the annualized issuance rate is roughly 5.256 million CLRTY per year, which is large relative to the genesis supply.

The issuance rate is a policy parameter. If the emission needs to slow, the lever is the block reward amount, not the block interval. Halving `BLOCK_REWARD` halves the emission without changing the reward split, the validator economics, or the staking APY formula.

## Slashing

Slashing is the economic enforcement of BFT safety. A validator that equivocates — signs two conflicting votes at the same `(height, round)` — loses a portion of its stake and a portion of its future earnings.

### Amount

| Parameter | Constant | Value |
|---|---|---|
| Stake reduction | `SLASH_AMOUNT_BPS` | 5% |
| Reward multiplier reduction | `REWARD_MULTIPLIER_PENALTY` | 20 percentage points |
| Seed exemption | `SEED_SLASH_EXEMPT` | true |

The slashed stake is credited to the pot. The reward multiplier reduction is applied on top, so the validator's economic cost is both:

1. **A one-time loss of principal** — 5% of the validator's stake is gone.
2. **A persistent reduction in future earnings** — the multiplier drop persists indefinitely.

Seed validators are exempt from slashing. This is a deliberate choice: the trust anchor that bootstrap relies on must not be slashable, or a governance attack could remove it.

### Detection

Nodes detect conflicting votes during the prevote phase. Both votes' signatures are verified before the conflict is recorded as evidence. A forged conflict — a second vote from a known signer with a garbage signature — is rejected rather than stored, because an unverifiable conflict would poison the proposer's evidence buffer and prevent it from proposing.

Evidence survives round and height transitions, bounded by `MAX_EQUIVOCATION_EVIDENCE` (256 entries). The proposer includes a `Slash` transaction carrying the proof in the next block it builds. Every node independently verifies the proof during block application. A block containing an invalid Slash proof is rejected.

Once a Slash transaction commits, every node scans the block's transactions, decodes each Slash, and erases matching evidence from its own pending list. Not just the proposer — every node. Reading the block as the source of truth is what keeps all nodes in sync.

### Slashing is automatic, not voted

A proof of equivocation is a mathematical fact — two valid signatures over conflicting values at the same `(height, round)`. It isn't subject to a vote, because a Byzantine majority could vote to slash an honest validator but cannot forge a signature. Automatic application means the safety argument of BFT is economically enforced: a validator that equivocates loses stake and earnings regardless of what the other validators think about it.

### Policy rejection is not a block-level error

A Slash transaction whose target is ineligible — a seed, an unregistered validator, or a validator with nothing left to slash — is a no-op at the executor level. `executeSystemSlash` returns `Success` with a zero receipt, and the block is accepted.

The distinction is load-bearing. If ineligibility rejected the block, a proposer could halt the chain by including a Slash against a seed in every block it produces. Validity of the *evidence* is enforced upstream by `verifyEquivocationProof`; the executor only applies policy.

### Slashing during unbonding

A validator that has requested unregistration remains slashable for the full unbonding window. Its record, address index, and stake persist for `UNBONDING_PERIOD` (120 blocks, two rotation intervals) before the stake is returned. A proof that lands during the window is applied as normal, and the stake return at expiry is the *post-slash* amount.

This closes a specific attack: a validator that equivocates and immediately unregisters cannot escape slashing by racing the proof.

## Validator set and rotation

The active set is bounded between `ACTIVE_SET_MIN` and `ACTIVE_SET_MAX`. It rotates at epoch boundaries (every `ROTATION_INTERVAL` blocks).

### Rotation size

The rotation is sized to:

```
min(ceil(n / 21), n - bftQuorum(n))
```

where `bftQuorum(n) = (2n / 3) + 1` (integer division).

The `n - bftQuorum(n)` bound is a safety cap: rotation can never remove so many validators that the remaining set falls below quorum. The `ceil(n / 21)` bound is an epoch-proportional cap: no more than 1/21st of the set rotates per epoch, so a full set turnover takes at least 21 epochs.

The smaller of the two bounds wins. At n=100:

- Safety cap: `100 - 67 = 33`
- Epoch-proportional cap: `ceil(100 / 21) = 5`

The rotation removes at most 5 validators per epoch at n=100. A full turn of the set takes 20 epochs.

### Rotation eligibility

A validator is eligible to be promoted into the active set if:

- It has no pending unbond (`pending_unbond_height == 0`).
- Its uptime score is above `UPTIME_ACTIVE_MIN_BPS`.
- Its stake meets `VALIDATOR_MIN_STAKE`.

Seeds are always eligible and are never removed by normal rotation, offline removal, or unhealthy-culling. This is the bootstrap trust anchor: as long as the seeds are running, the chain has a stable core that can't be rotated out by a coalition.

### The degenerate seed-only case

On a chain with no non-seed validators, the active set is the seeds. Rotation has nothing to rotate, so it does nothing. The chain runs on the seeds until a new validator registers.

## Reward multiplier penalties

A validator's `reward_multiplier` affects the reward it earns for every block it participates in. The multiplier is applied to:

- The validator's share of the **set share**.
- The validator's **producer bonus** when it's the proposer.

The difference between the unpenalized share and the penalized share routes to the pot.

Because the multiplier applies to every block, its effect compounds over time. A validator with a 50% multiplier earns half the normal reward for every block in the set. Over a long period, the cumulative loss from a penalty can exceed the immediate stake loss from the infraction itself. This is intentional: the persistent penalty is what makes equivocation economically unattractive beyond the one-time cost.

## Unbonding

A validator that wants to leave the active set submits an `UnregisterValidator` transaction. This:

1. **Removes the validator from the active set immediately.**
2. **Retains the validator record, address index, and stake** for `UNBONDING_PERIOD` (120 blocks).
3. **Blocks re-promotion** into the active set until the unbond expires.
4. **Keeps the stake slashable** for the entire window.

When the unbond expires, `BlockProcessor::processUnbondExpiries`:

1. Returns the stake to the validator's owner address.
2. Removes the validator-by-address index.
3. Deletes the validator record.

The purpose of the delay is twofold:

- **Slashability window.** An equivocation proof has a bounded observation-to-inclusion window. Without the delay, a validator could unregister immediately after equivocating and escape slashing. The 120-block window ensures any proof landing during the window is applied.
- **Prevents flash exits.** A validator cannot leave the active set and immediately rejoin to reset its rotation position or its uptime history.

A validator cannot re-register while a pending unbond is in flight.

## Design notes

**The reward is uniform, not work-based.** A block that contains a thousand transactions pays the same reward as an empty block. This is a deliberate design choice: the reward compensates for availability, not for computational work. The alternative — a reward that depends on transaction contents — introduces a consensus-level rule that every verifier must reproduce, and creates perverse incentives around block production during idle periods.

**The rotation distributes the emission over time.** Because the active set rotates, the emission is spread across the entire pool of validators who have registered, not concentrated in a fixed set. A non-seed validator in a pool of 100 earns for the epochs it's selected for, not for every epoch. The maximum share any single validator can capture is bounded by the rotation rate.

**Validator and staker rewards are decoupled.** Validators are paid every block; stakers are paid every epoch. This keeps the per-block state transition cheap and defers the more expensive staker iteration to the epoch boundary. It also means the two compensation models can be tuned independently — the validator pool size, the producer bonus share, and the staker APY target are all separate policy parameters.

**The pot is a smoothing buffer, not an accumulator.** The pot exists to decouple the staker payout from the current epoch's activity. When activity is low, the pot fills; when activity is high, the pot drains to pay the higher activity bonus. Over a long period, the pot's balance trends toward a level proportional to the reward rate, not toward infinity. The `POT_MAX` burn is the upper bound that enforces this.

**Slashing is a principal loss *and* an income loss.** The 5% stake reduction is the immediate cost of equivocation. The reward multiplier reduction is the persistent cost. Both are necessary: the stake reduction makes the immediate cost of a single attack high, and the multiplier reduction makes the long-term cost of repeated attacks (or of a validator that keeps running after a single attack) higher still.

**Seed rewards are stipend-based, not fee-based.** The seed-only policy routes the bulk of the reward to the pot rather than paying it to the seeds. This is what allows the seeds to be the long-term trust anchor while still preserving an incentive for new validators to register: the moment a non-seed enters the set, the normal distribution resumes and the seed stipend stops absorbing the pool.

**The unbonding window is a policy choice, not a safety requirement.** 120 blocks is enough for any honest proposer to include a proof that any peer has observed. A longer delay is strictly safer and only costs the departing validator liquidity. A shorter delay risks a proof landing after the validator's record has been deleted, which would let the validator escape slashing. The current value is the minimum that maintains the slashing property under reasonable network conditions.

**Rewards are deterministic from state.** Nothing inside the reward calculation reads wall-clock time, local peer state, or hardware entropy. Given the same block and the same pre-state, every node computes the same reward distribution. This is what makes the reward math reproducible across the network and verifiable by any node.