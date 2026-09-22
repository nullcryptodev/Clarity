# Core Testing Notes

Core contains the state-machine logic that the rest of the codebase
either feeds (Consensus produces blocks) or consumes (Node applies
them). Tests here are the largest collection in the codebase.

### Data structures with serialization round-trips

- `Account`, `ValidatorInfo`, `TokenInfo` — full field-by-field
  round-trip, size constants verified, short-buffer rejection.
- `Block` and `BlockHeader` — structure, header checks, merkle roots.
- `Transaction` — full round-trip, signing-hash domain separation,
  real Ed25519 signature verification.

### Block processing (`BlockProcessorTests.cpp`, ~65 tests)

- Header checks: version, chain_id, height, parent, timestamp,
  tx_root, validator_set_root, active_validator_count.
- Quorum: insufficient, duplicates, out-of-range, invalid signer.
- Transaction application: transfers, multiple, failed tx
  rejection, system tx skipping.
- State root and receipts root verification.
- Reward distribution with conservation checks.
- Global state updates.
- Rotation boundary behavior, order expiry, participants liveness.

### Transaction execution (`TransactionExecutorTests.cpp`, ~85 tests)

Per-`TxType` coverage:
- Common validation: signature, chain_id, nonce (low/high), fee,
  expiry, malformed.
- Transfers, staking opt-in/opt-out, validator registration, token
  creation, mint, burn, AMM, orders, claim rewards, unregister,
  update reward address, update token meta.
- Supply-based mint cap (`MintAfterTransferRespectsMaxSupply`),
  which is the test that exposed a balance-based check that allowed
  minting past the cap after tokens were transferred.
- Index maintenance: LP position index, validator address index,
  order expiry index.

### Reward math (`RewardCalculatorTests.cpp`, ~70 tests)

Pure functions, extensively boundary-tested:
- `applyBps`, `applyBpsRound`.
- `computeBlockReward` — pool shares, remainder distribution order,
  per-validator amounts sum to pool.
- `computeEffectiveApy` — component caps, uint16 overflow.
- `computeTargetStakerPayout` — scales with stake, time, APY;
  no overflow at uint64 max.
- `applyPotMechanics` — pool covers/short, drain, burn.
- `computeActivityBps`, `computePotBonusBps` — linear interpolation,
  caps, monotonicity.

### Rotation math (`ValidatorRotationTests.cpp`, ~70 tests)

- `bftQuorum` pinned at specific values (4→3, 7→5, 11→8, 21→15,
  100→67).
- `computeRotationCount` never exceeds `n - bftQuorum(n)`.
- `planRotation` same-size, grow, shrink, insufficient candidates.
- Seeds never removed regardless of uptime or last-seen.
- `applyRotation` updates flags and target size, keeps set sorted.
- `planOfflineRemoval` and `applyOfflineRemoval`.
- `updateUptimeScore` EMA smoothing, clamping.
- `applyInfractionPenalty` — reduces multiplier, floors at
  `REWARD_MULTIPLIER_FLOOR`, records infraction count.

### Chain storage and validation

- `ChainDBTests.cpp` — block storage by hash/height, receipts,
  chain head, metadata, persistence across reopen.
- `ChainTests.cpp` — genesis append, sequential append, height
  ordering, unknown parent, fork rejection, head persistence,
  sync state, 100-block chain integrity.

### Mempool (`MempoolTests.cpp`, ~36 tests)

- Acceptance, idempotency, malformed rejection.
- Chain ID mismatch, bad signature, fee (low/high), nonce (low),
  insufficient funds, expiry.
- Nonce conflict handling: fee rate improves, priority tier
  replaces.
- Block selection: byte limit, count limit, nonce ordering,
  nonce gap skipping, priority tier first.
- Removal, expiry purge, stats.

## The boundary this module has

`Core` produces the artifacts (`Block`, `Transaction`, `Receipt`)
that `Consensus` and `Node` consume. Any bug that lives at the
interface — a field consensus sets that the block processor
doesn't expect, a validation the block processor performs that
consensus hasn't satisfied yet — is invisible to Core tests. The
end-to-end daemon tests in `Node/Tests/NodeEndToEndTests.cpp` are
the guard against that class of bug.

When adding tests to Core, prefer ones that verify a property that
*other* modules rely on. The header validation tests, the state
root checks, and the reward conservation tests are examples.