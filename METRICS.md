# Clarity Metrics Reference

> Prometheus-compatible metrics for a Clarity node

Clarity exposes a Prometheus text-format metrics endpoint on a separate port from the RPC endpoint. This document describes every metric the endpoint emits, what each one means, and what it's useful for.

If you're looking for how to *enable*, *bind*, or *disable* the endpoint, see the [Metrics section](https://github.com/nullcryptodev/Clarity/blob/main/README.md#metrics-how-operators-watch-the-node) of the README. This document is the reference; the README is the configuration guide.

## Endpoint

**Default bind:** `127.0.0.1:9100`
**Content type:** `text/plain; version=0.0.4; charset=utf-8`
**Path:** `/metrics` (the only path this endpoint serves)
**Method:** `GET`

A Prometheus scrape config that works against a default-configured regtest node:

```yaml
scrape_configs:
  - job_name: clarity
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:9100']
```

For a two-validator network on one host, the second node's metrics port must be moved:

```yaml
scrape_configs:
  - job_name: clarity
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:9100']
        labels:
          node: 'validator-1'
      - targets: ['127.0.0.1:9101']
        labels:
          node: 'validator-2'
```

The `node` label is not emitted by the exporter itself; Prometheus adds it from the scrape config. It's the standard way to tell two instances apart on the same dashboard.

## Conventions

**Prefix.** Every metric name begins with `clrty_`. This namespaces the metric set against every other exporter Prometheus might scrape, so `clrty_height` doesn't collide with a metric called `height` from some other source.

**Units.** Metric names carry their units as a suffix where the value has a unit:

- `_seconds` for durations
- `_bytes` for sizes
- `_bps` for basis points (1/100 of a percent; `10000` = 100%)
- `_ratio` for dimensionless fractions in `[0, 1]`
- No suffix for pure counts

**Counters vs. gauges.** Metrics that only increase are typed `counter` and named with the suffix `_total` per Prometheus convention. Metrics that describe current state, or that can go up or down, are typed `gauge`. Every counter resets to zero when the process restarts; Prometheus's `rate()` and `increase()` functions handle the reset.

**CLRTY units.** Amounts are in **atomic units**, not whole CLRTY. Clarity uses `ATOMIC_UNITS_PER_COIN = 100000` (5 decimal places, same as Bitcoin's satoshi model but with 5 decimals instead of 8). So `100000` in a `_stake` metric means 1.0 CLRTY. If you want to display human amounts, divide by 100000 in your dashboard — or use a Prometheus recording rule.

## Metric inventory

### Node

| Metric | Type | Meaning |
|---|---|---|
| `clrty_height` | gauge | Current chain height. The number of blocks applied since genesis. |
| `clrty_running` | gauge | `1` if the node's event loop is running, `0` otherwise. Always `1` when scrapable, since a stopped node doesn't serve requests — useful only as a "was the last scrape successful" indicator. |
| `clrty_chain_id` | gauge | The chain ID the node is configured for. Regtest is `1129075271` (`0x434C5247`). Useful when a single Prometheus scrapes multiple networks. |
| `clrty_uptime_seconds` | counter | Seconds since the metrics endpoint was constructed, which is when `RpcServer::start()` completed. Resets on daemon restart. |

**`clrty_height` is the load-bearing node metric.** Every dashboard has it. A flat line where the chain is expected to be producing blocks is the single most useful alert.

### P2P

| Metric | Type | Meaning |
|---|---|---|
| `clrty_p2p_peers` | gauge | Total number of peers known, in any state. |
| `clrty_p2p_peers_inbound` | gauge | Peers that dialed us. |
| `clrty_p2p_peers_outbound` | gauge | Peers we dialed. |
| `clrty_p2p_peers_established` | gauge | Peers that have completed the full handshake (Version, Verack, Auth, AuthReady) and can exchange application messages. |
| `clrty_p2p_peers_banned` | gauge | Entries in the ban list. |
| `clrty_p2p_addresses_known` | gauge | Addresses in the persistent address book. |
| `clrty_p2p_aggregate_burst` | gauge | Configured burst size of the node-wide rate limiter, in tokens. Constant unless the config changes. |
| `clrty_p2p_aggregate_per_second` | gauge | Configured refill rate of the node-wide rate limiter. |
| `clrty_p2p_aggregate_enabled` | gauge | `1` if the aggregate rate limiter is enabled, `0` if disabled. |

**The interesting ones for a validator are `clrty_p2p_peers_established` and `clrty_p2p_peers_banned`.**

- `clrty_p2p_peers_established` should be non-zero on a healthy node. On a two-validator regtest, it's `1` on both nodes. On a larger network, it should be somewhere between `target_outbound` (default 8) and `max_peers` (default 128). A sudden drop to zero means the node has lost all peers and can no longer participate in consensus.
- `clrty_p2p_peers_banned` should normally be `0`. A growing ban count means either an active attack or a bug in your own misbehavior logic. Worth alerting on if it exceeds a small threshold.

**`clrty_p2p_peers_inbound` and `clrty_p2p_peers_outbound` together tell you whether you're a leaf or a hub.** A node that only ever receives inbound connections is either well-connected or behind a load of dialers; a node that only ever makes outbound connections is behind a firewall and other nodes can't reach it. Neither is wrong; both are worth knowing.

**`clrty_p2p_addresses_known` being zero is not necessarily a problem.** A node launched with no `--seed` flags and never sent a `GetPeers` request will have an empty address book until it learns addresses. This is expected for a manual regtest setup.

### Mempool

| Metric | Type | Meaning |
|---|---|---|
| `clrty_mempool_txs` | gauge | Number of transactions currently in the mempool. |
| `clrty_mempool_bytes` | gauge | Total serialized size of mempool transactions, in bytes. |
| `clrty_mempool_priority_txs` | gauge | Transactions at the Priority fee tier. |
| `clrty_mempool_standard_txs` | gauge | Transactions at the Standard fee tier. |
| `clrty_mempool_min_fee_rate` | gauge | Lowest fee rate among pending transactions, in atomic units per byte. |
| `clrty_mempool_max_fee_rate` | gauge | Highest fee rate among pending transactions. |
| `clrty_mempool_avg_fee_rate` | gauge | Mean fee rate across pending transactions. |
| `clrty_mempool_added_total` | counter | Transactions accepted into the mempool since process start. |
| `clrty_mempool_rejected_total{reason="..."}` | counter | Transactions rejected since process start, by reason. |

**`clrty_mempool_txs` and `clrty_mempool_bytes` are the two worth graphing.** On a chain with steady traffic, they'll fluctuate around a baseline. A sustained rise means blocks are being produced slower than transactions are arriving; a sustained fall to zero means the chain is idle.

**`clrty_mempool_priority_txs` vs. `clrty_mempool_standard_txs`** tells you about fee pressure. A mempool dominated by priority transactions means users are paying for prompt inclusion; a mempool dominated by standard transactions means the base fee is sufficient.

**`clrty_mempool_min_fee_rate`** is useful as a "is this transaction going to be included" threshold. If you submit a transaction with a fee rate below `min_fee_rate`, it will likely stay in the pool longer than the current pool contents.

**A note on `clrty_mempool_added_total` after a restart.** `Mempool::load()` re-adds persisted entries through the same `add()` path that the counters are updated in, so a node that restarts with entries already in its persistent mempool will show a one-time spike in `clrty_mempool_added_total` immediately after startup. That's the honest reading — those transactions went through validation again — and a `rate()` over a multi-minute window sees it as a spike that flattens. On a node that starts with an empty mempool, the counter starts at zero and only moves when transactions arrive.

**The `reason` label on `clrty_mempool_rejected_total`** takes one of eleven values, matching the rejection codes in `MempoolAddResult`:

| Reason | Meaning |
|---|---|
| `malformed` | The transaction's structure is invalid (missing fields, wrong length, etc.). |
| `too-large` | The serialized transaction exceeds 1 MiB. |
| `bad-signature` | The Ed25519 signature doesn't verify against the claimed sender. |
| `wrong-chain` | The transaction's `chain_id` doesn't match this node's. |
| `expired` | The transaction's `valid_until_height` has passed. |
| `nonce-too-low` | The transaction's nonce is below the sender's current on-chain nonce. |
| `nonce-conflict` | A transaction with the same `(sender, nonce)` is already in the pool, and the new one isn't a strict improvement. |
| `low-fee` | The fee rate is below `MIN_FEE_PER_BYTE` (1 atomic unit per byte). |
| `high-fee` | The fee rate is above `MAX_FEE_RATE` (1000 atomic units per byte). |
| `insufficient-funds` | The sender's balance can't cover the amount plus fee, or (for token transfers) the token balance can't cover the amount. |
| `pool-full` | The mempool is at capacity and the new transaction doesn't outrank the lowest-priority entry. |

**A high `bad-signature` count is worth investigating.** It usually means a buggy or malicious peer is sending malformed transactions; the mempool rejects them cleanly, but the volume tells you something is off.

### Storage

| Metric | Type | Meaning |
|---|---|---|
| `clrty_storage_db_bytes` | gauge | On-disk size of the node's MDBX database, in bytes. |
| `clrty_storage_block_count` | gauge | Number of blocks stored. Should equal `clrty_height + 1`. |
| `clrty_storage_smt_nodes` | gauge | Number of SMT internal nodes in current-state storage. |
| `clrty_storage_smt_leaves` | gauge | Number of SMT leaves in current-state storage. |

**`clrty_storage_db_bytes` is the "is my disk filling up" metric.** On a long-running node, the rate of growth tells you how many weeks you have before the disk fills. A Prometheus alert on `predict_linear(clrty_storage_db_bytes[7d], 30*86400) > <disk_free>` is the standard pattern.

**Two things to know about this metric.**

First, all of the node's persistent data lives in a single MDBX file at `<data_dir>/state`. Chain data, state data, receipts, the transaction index, and the mempool persistence table all share it. There is no separate chain DB directory and therefore no separate chain-bytes metric. The name reflects the single file, not a two-file model.

Second, MDBX pre-allocates the database file to the configured map size (16 GiB by default), so the file's *logical* size is much larger than the amount of data actually written to it. The metric reports the logical size — `ls -l` on the file matches, `du -h` would show something smaller because the file is sparse. For "will this fill my disk," the logical size is the number that matters, because the file will eventually consume it as data is written.

**`clrty_storage_block_count`** grows by one per committed block. A flat value while `clrty_height` is rising would mean the block storage path is broken independently of the state path — unlikely, but the two metrics together catch it.

**`clrty_storage_smt_nodes` and `clrty_storage_smt_leaves`** count the current-state SMT. They grow with state changes (new accounts, updated balances), not with block count. A chain that produces many empty blocks grows the SMT count slowly; a chain with many distinct state writes grows it quickly.

### Rewards and economics

| Metric | Type | Meaning |
|---|---|---|
| `clrty_pot` | gauge | Current balance of the staker reward pot, in atomic CLRTY. |
| `clrty_total_supply` | gauge | Total CLRTY in circulation, in atomic units. |
| `clrty_total_staked` | gauge | Total CLRTY currently staked, in atomic units. |
| `clrty_staker_count` | gauge | Number of accounts with a non-zero staked balance. |
| `clrty_last_effective_apy_bps` | gauge | APY applied at the last epoch boundary, in basis points. `0` until the first epoch closes (height < 60). |
| `clrty_current_epoch` | gauge | Current epoch number. `height / ROTATION_INTERVAL`, so it increments once per 60 blocks. |
| `clrty_blocks_until_epoch` | gauge | Blocks remaining until the next epoch boundary. Counts down from 60 to 1, then resets. |

**`clrty_total_supply` grows by the block reward each block.** The slope of `rate(clrty_total_supply[1h])` is the emission rate. On a chain that's expecting to be deflationary at some point, this metric is where you'd verify that.

**`clrty_pot` is the smoothing buffer.** It rises when the staker pool has more than the target payout can absorb, and falls when stakers are underpaid for an epoch. On a chain with active stakers, it fluctuates. On a chain with no stakers (the current regtest state), it grows monotonically because there's nothing to drain it.

**`clrty_last_effective_apy_bps` reads `0` until the first epoch boundary at height 60.** This is correct — no APY has been applied yet. Once the first boundary closes, the metric reports the rate that was actually used at that boundary, which is `min(base + activity_bonus + pot_bonus, 1300)` computed from the state at that moment. On a chain with no stakers and no activity, the applied rate may still be `0` if the protocol chooses not to record a value when there are no stakers to pay. `0` is a valid reading, not an error.

**`clrty_total_staked` and `clrty_staker_count` measure different things and can legitimately disagree.** `total_staked` is the sum of every account's staked balance, including accounts that are staked but not indexed as stakers. `staker_count` is the number of accounts in the staker index. On a chain where the only staked accounts are seed validators whose rewards are configured to route to the pot, `total_staked` may be non-zero while `staker_count` reflects only the funded genesis accounts. A large gap between the two is worth investigating, but a small gap on a young chain is expected.

**`clrty_blocks_until_epoch` resets from `60` at each boundary.** If you see it stuck at a value and not counting down, the chain has stalled.

### Consensus

| Metric | Type | Meaning |
|---|---|---|
| `clrty_consensus_height` | gauge | Height the consensus engine is working on. `0` on a non-validator node. This is one ahead of `clrty_height` when the engine is proposing the next block. |
| `clrty_consensus_round` | gauge | Current round within the consensus height. Round 0 is the normal case; higher rounds mean the previous round timed out. |
| `clrty_consensus_step` | gauge | Step ordinal: `0`=NewHeight `1`=Propose `2`=Prevote `3`=Precommit `4`=Commit. |
| `clrty_consensus_is_proposer` | gauge | `1` if this node is the proposer for the current round, `0` otherwise. Flips as the proposer rotates. |
| `clrty_consensus_prevotes` | gauge | Prevotes recorded for the current round. Resets to `0` at the start of each round. |
| `clrty_consensus_precommits` | gauge | Precommits recorded for the current round. Resets to `0` at the start of each round. |
| `clrty_consensus_consecutive_timeouts` | gauge | Rounds at the current height that ended without a commit. Resets to `0` on a successful commit. Reaches `30` to trigger emergency rotation. |
| `clrty_consensus_emergency_rotation` | gauge | `1` if the engine has entered emergency rotation mode, `0` otherwise. |
| `clrty_active_set_size` | gauge | Number of validators in the active set. |
| `clrty_consensus_quorum` | gauge | Precommit quorum threshold for the current active set. Computed as `bftQuorum(active_set_size) = 2n/3 + 1`. |

**`clrty_consensus_step` is the metric that shows what the node is doing right now.** On a healthy chain it cycles `1 → 2 → 3 → 4 → 1 → ...` once per block. If it sits at any value for longer than a block interval, the round is stalled.

**`clrty_consensus_consecutive_timeouts` is the alerting metric.** It should be `0` on a healthy chain. It rises on a stalled network and reaches `30` (the emergency threshold) after roughly 2.5 minutes of continuous stall. Anything above `0` sustained for more than a minute is worth investigating.

**`clrty_consensus_emergency_rotation` at `1` means the chain has entered the emergency path.** The next proposal will carry a timeout certificate and a derived emergency set. This should be rare. If it fires repeatedly, the active set has a systemic availability problem.

**`clrty_consensus_prevotes` and `clrty_consensus_precommits`** should each climb to `clrty_consensus_quorum` once per round and then reset. If they're stuck below quorum for more than one block interval, some validators aren't seeing each other's votes — likely a network partition or a misconfigured validator set.

**`clrty_consensus_is_proposer` flips between validators.** On a two-validator network it alternates every round. Over a long window, each validator should be proposer roughly 50% of the time; a validator that's never proposer is a sign the proposer-selection formula is wrong or the active set is wrong.

### Per-validator (opt-in)

Enabled by `--metrics-include-validators`. Off by default. When on, emits six metrics per active validator, each labelled by `validator_id`.

| Metric | Type | Meaning |
|---|---|---|
| `clrty_validator_stake{validator_id="N"}` | gauge | The validator's current stake, in atomic CLRTY. |
| `clrty_validator_uptime_bps{validator_id="N"}` | gauge | Uptime EMA in basis points. `10000` is perfect; `0` is fully offline. |
| `clrty_validator_reward_multiplier{validator_id="N"}` | gauge | Reward multiplier in basis points. `10000` is unpenalized; floor is `2000` after repeated infractions. |
| `clrty_validator_total_rewards_earned{validator_id="N"}` | gauge | Cumulative rewards earned by the validator since registration. |
| `clrty_validator_blocks_produced{validator_id="N"}` | gauge | Cumulative blocks produced by the validator since registration. |
| `clrty_validator_pending_unbond_height{validator_id="N"}` | gauge | Height at which the validator's unbonding completes, or `0` if not unbonding. |

**Cardinality.** Each active validator adds six series. On a 100-validator chain that's 600 series per node. Off by default for this reason; enable if you're running a validator and want to alert on your own uptime, or if you're running a monitoring stack for the whole network.

**`clrty_validator_stake` drops on a slash.** A validator that equivocates loses `SLASH_AMOUNT_BPS` (500 bps = 5%) of its stake. The metric drops by 5% in a single scrape, which is the fastest way to notice a slash happened.

**`clrty_validator_reward_multiplier` also drops on a slash.** It decreases by `REWARD_MULTIPLIER_PENALTY` (2000 bps = 20%) per infraction, down to the floor at 2000. A validator that stays below 10000 permanently has been penalized. The metric never recovers — this is by design.

**`clrty_validator_uptime_bps`** is the EMA of the validator's responsiveness to pings. It trends down when a validator is missing pings, up when it responds. A validator that drops below `UPTIME_ACTIVE_MIN_BPS` (9000) is removed from the active set at the next rotation; below `UPTIME_REMOVAL_THRESHOLD_BPS` (2500), it's removed from the pool entirely.

**`clrty_validator_pending_unbond_height` at a non-zero value means the validator is leaving.** The metric reports the height at which the unbonding window closes. At that height, the record is deleted and the metric stops being emitted — which is the correct reading for "the validator no longer exists."

## Alerts worth setting

These are suggestions, not prescriptions. An operator's monitoring stack knows more about their deployment than a reference document does.

**Chain has stalled.**

```promql
rate(clrty_height[5m]) == 0
```

Fires when the chain hasn't advanced in 5 minutes. Almost always worth paging on.

**Node has no peers.**

```promql
clrty_p2p_peers_established == 0
```

Fires when a node can't talk to anyone. On a validator this means it can't participate in consensus.

**Consensus is stuck in a round.**

```promql
clrty_consensus_consecutive_timeouts > 5
```

Fires after roughly 25 seconds of round timeouts. The threshold is well below the emergency rotation trigger (30 rounds), so there's time to investigate before the chain falls into the emergency path.

**Mempool is full and rejecting.**

```promql
rate(clrty_mempool_rejected_total{reason="pool-full"}[5m]) > 0
```

Fires when the mempool is at capacity and turning away new transactions. On a busy chain this is expected under load; on an idle chain it means the pool isn't draining.

**Storage is filling up.**

```promql
predict_linear(clrty_storage_db_bytes[6h], 30*86400)
  > <bytes_free_on_disk>
```

Fires when the projected 30-day growth exceeds the remaining disk. Adjust the forecast window and the safety margin to taste. Remember that the reported size is the MDBX file's logical size, which is pre-allocated to the map size — so on a fresh node the metric will start large and grow slowly, not start small and grow fast.

**A validator has been slashed.**

```promql
clrty_validator_reward_multiplier{validator_id="$ID"} < 10000
```

Fires for any validator whose multiplier has dropped below the unpenalized value. Requires the per-validator block to be enabled.

**A validator's uptime is trending toward removal.**

```promql
clrty_validator_uptime_bps{validator_id="$ID"} < 9000
```

Fires when a validator is at risk of being removed from the active set at the next rotation.

## What is not exposed

Some things that a node operator might want to monitor are not in the metrics endpoint, either because the cost isn't worth the benefit or because the metric isn't actionable.

**Per-peer metrics.** The endpoint exposes aggregate peer counts but not per-peer bytes-sent/bytes-received, ping times, or misbehavior scores. The aggregate counts answer "do I have peers?"; per-peer details would need a label per peer, which grows the series set with every connection. For per-peer inspection, use the RPC `getPeers` method.

**Per-transaction metrics.** There's no per-transaction latency histogram, no per-type transaction counter, and no per-account activity metric. Those need either a table of counters or a histogram bucket set, both of which are better served by an external indexer reading the chain.

**Historical APY.** The `clrty_last_effective_apy_bps` metric reports the applied rate for the *most recent* epoch boundary. Historical values are the responsibility of the time series database — Prometheus retains them, and a Grafana panel can graph the history directly.

**Process metrics.** CPU usage, memory usage, open file descriptors, and thread counts are not exposed. `node_exporter` or your container runtime's metrics endpoint covers all of them, and duplicating them in the application would just create two sources of truth.

**Debug metrics.** Round timer state, WAL size, equivocation evidence count, and similar internal counters are not exposed. They're useful for development but not for a production monitoring stack, and adding them would mean adding a debugging flag that most operators don't want.

## Metric stability

The metric names and types in this document are part of the node's public interface. They are not expected to change without a documented reason. But the metric *set* will grow over time, and existing metrics may gain optional labels.

**What won't change:**

- Metric names, once published.
- Metric types, once published.
- The unit and semantics of a metric.

**What may change:**

- New metrics may be added. A scraper that doesn't know about `clrty_validator_stake` will simply ignore it.
- A metric may gain additional labels. A scraper that queries without those labels will still receive the base series.

**What would require a version bump:**

- Renaming an existing metric.
- Changing the semantics of an existing metric (e.g., changing `clrty_pot` from atomic units to whole CLRTY).
- Removing a metric.

Those changes would be documented in the release notes as a breaking change to the metrics interface, and would be avoided unless there's no alternative.

## Emitting metrics into a dashboard

A minimal Grafana dashboard for a Clarity validator has four panels:

1. **Chain height over time.** `clrty_height` as a time series. Should be a rising staircase.
2. **Peer count by direction.** `clrty_p2p_peers_inbound` and `clrty_p2p_peers_outbound` on one panel. Should be relatively stable.
3. **Consensus state.** `clrty_consensus_step` as a step chart, or `clrty_consensus_is_proposer` as a binary indicator. Shows the node participating in rounds.
4. **Per-validator stake and uptime.** `clrty_validator_stake` and `clrty_validator_uptime_bps` with `validator_id` as the label. One line per validator, showing the whole set.

A more complete dashboard adds panels for mempool state, storage growth, reward pool dynamics, and per-validator reward multipliers. But those four cover "is my node doing the right thing" for most operators, and they're the four I'd build first.

## Getting help

If a metric appears to be wrong, the first thing to do is check the corresponding RPC method. `Node::Status` populates several metrics, and the RPC `status` method returns the same fields as JSON. If the RPC field and the metric value agree, the source data is consistent and the discrepancy is somewhere between the state and the metric. If they disagree, the metric is reading from the wrong place.

Every metric in this document maps to a source that also appears in the RPC or in the node's logs. Cross-referencing those is the fastest way to localize a discrepancy.