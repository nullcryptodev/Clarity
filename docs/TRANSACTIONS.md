# Transactions

Every transaction type in Clarity: what it does, what its payload looks like, what it changes in state, and what can go wrong.

This document is a reference for wallet implementers, integrators, and auditors. It describes the wire format, the validation rules, and the state effects of every transaction type. It does not describe the consensus protocol that commits blocks; for that, see [CONSENSUS.md](CONSENSUS.md). It does not describe the RPC surface that submits transactions; for that, see [RPC.md](RPC.md).

## Table of contents

- [The transaction envelope](#the-transaction-envelope)
  - [Fields](#fields)
  - [Signing hash](#signing-hash)
  - [Wire format](#wire-format)
- [Transaction types](#transaction-types)
  - [Native transfer](#native-transfer)
  - [Staking](#staking)
  - [Validator operations](#validator-operations)
  - [Token operations](#token-operations)
  - [AMM operations](#amm-operations)
  - [Order operations](#order-operations)
  - [NFT operations](#nft-operations)
  - [System transactions](#system-transactions)
- [The execution pipeline](#the-execution-pipeline)
  - [Validation stages](#validation-stages)
  - [Fee handling](#fee-handling)
  - [Nonce handling](#nonce-handling)
- [Receipts](#receipts)
  - [The receipt format](#the-receipt-format)
  - [Fill records](#fill-records)
- [Payload encoding conventions](#payload-encoding-conventions)
- [What a transaction cannot do](#what-a-transaction-cannot-do)

## The transaction envelope

### Fields

Every transaction carries the following fields, regardless of type:

| Field | Type | Notes |
| --- | --- | --- |
| `version` | `u16` | Current is 1. Bumped when the wire format changes. |
| `chain_id` | `u64` | Identifies the network. A transaction signed for one chain cannot be replayed on another. |
| `tx_type` | `u8` | The transaction type. See the table below. |
| `nonce` | `u64` | Replay protection. Must equal the sender's current nonce. Increments by 1 on success. |
| `valid_until_height` | `u64` | Expiry height. 0 means "no expiry". A transaction with `valid_until_height < current_height` is rejected. |
| `from` | `Address` (32 bytes) | Sender. Must match the signature. |
| `to` | `Address` (32 bytes) | Recipient. Meaningful for types that move value. Zero for types that don't. |
| `token_id` | `u32` | Token id. 0 is native CLRTY. |
| `amount` | `u64` | Amount in atomic units. Meaning depends on type. |
| `fee` | `u64` | Fee in atomic CLRTY. Charged on every transaction, success or failure. |
| `payload` | `bytes` | Type-specific data. May be empty. |
| `signature` | `Signature` (64 bytes) | Ed25519 signature over the signing hash. |

The `version`, `chain_id`, `tx_type`, `nonce`, `valid_until_height`, `from`, `to`, `token_id`, `amount`, `fee`, and `payload` fields are all covered by the signature. The `signature` field is not — it's the signature.

### Signing hash

The signing hash is `Blake2b(serializeForSigning())`. The `serializeForSigning` function produces the same bytes as `serialize` except for the signature, which is omitted.

The signing hash **equals the transaction id** (txid). A client can compute the txid from an unsigned transaction; it doesn't need the signature to know the txid.

The signing hash is computed fresh on every call to `signingHash()`. There is no cache. A cache over a struct with public fields cannot be kept coherent: a caller that mutates a field and then calls `signingHash()` would get a stale value.

### Wire format

The serialized transaction is:

```
[2]  version (LE)
[8]  chain_id (LE)
[1]  tx_type
[8]  nonce (LE)
[8]  valid_until_height (LE)
[32] from
[32] to
[4]  token_id (LE)
[8]  amount (LE)
[8]  fee (LE)
[4]  payload_size (LE)
[N]  payload
[64] signature
```

All multi-byte integers are little-endian. The `serializeForSigning` variant is the same bytes without the trailing 64-byte signature.

The wire format is a **codec, not a validator**. Deserializing a transaction produces a `Transaction` struct; it does not check that the fields are semantically valid. The `isWellFormed()` method is a separate step that checks structural constraints (types, sizes). The mempool and executor run both.

## Transaction types

The `TxType` enum groups types by category so related types share a byte range. The ranges are:

| Range | Category |
| --- | --- |
| `0x00–0x0F` | Core (transfers) |
| `0x10–0x1F` | Staking |
| `0x20–0x2F` | Validator |
| `0x30–0x3F` | AMM |
| `0x40–0x4F` | DEX / Orders / NFTs |
| `0x50–0x5F` | Token management |
| `0x60–0x6F` | Governance (reserved) |
| `0x70–0x7F` | Cross-chain (reserved) |
| `0xF0–0xFE` | System (implicit) |
| `0xFF` | Invalid sentinel |

Values are never reused. If a type is removed, its value stays reserved.

### Native transfer

**`Transfer = 0x00`**

Sends CLRTY (native) or a custom token from `from` to `to`. The amount goes in `amount`; the token id in `token_id` (0 for native).

**Payload**: empty.

**Validation**:
- `amount != 0`
- `to` is not the null address
- Sender has at least `amount + fee` (native) or `amount` (custom token)
- Fee is charged separately from the amount

**State changes**:
- If native: sender's balance decreases by `amount`, recipient's balance increases by `amount`. If the recipient's account was empty, its `created_at_height` is set to the current height.
- If custom: sender's `token_balance(token_id)` decreases by `amount`, recipient's increases by `amount`.

**Receipt**: success or failure, no fills.

### Staking

Staking operations don't move funds; they toggle a flag on the account and recompute the staked amount.

**`OptInStaking = 0x10`**

Re-enables auto-staking for the sender's account. If the account was previously opted out, this clears the flag.

**Payload**: empty.

**Validation**:
- Sender's account exists (implicit: any sender with a nonce has an account)

**State changes**:
- Sender's `staking_opted_out` is set to false
- Sender's `staked` is recomputed via `recalculateStaked()`, which sets it to `balance - AUTO_STAKE_THRESHOLD` if balance exceeds the threshold, or 0 otherwise
- If the sender became a staker (staked was 0, now > 0), it's added to the staker index and `staker_count` is incremented
- `total_staked` is adjusted by the change

**`OptOutStaking = 0x11`**

Disables auto-staking for the sender's account.

**Payload**: empty.

**State changes**: mirror of opt-in. `staking_opted_out` is set to true; staked is recomputed (now 0); if the sender was a staker, it's removed from the index and `staker_count` is decremented.

**`ClaimRewards = 0x12`**

Moves the sender's `pending_rewards` into their `balance`. This is the single claim path for both staking rewards and NFT rewards: NFT reward claims land in the same `pending_rewards` bucket, so one `ClaimRewards` claims both.

**Payload**: empty.

**State changes**:
- Sender's `balance` increases by `pending_rewards`
- `pending_rewards` is reset to 0
- `staked` is recomputed (since the balance changed)

### Validator operations

**`RegisterValidator = 0x20`**

Registers the sender as a validator. The sender's entire balance becomes the validator's stake; the validator is placed in the pool (not the active set) and can be promoted at the next rotation.

**Payload**: 32 bytes — the validator's P2P node public key.

**Validation**:
- Payload is exactly 32 bytes
- Sender's balance is at least `VALIDATOR_MIN_STAKE`
- Sender is not already registered (checked via the validator-by-address index)

**State changes**:
- New `ValidatorInfo` record with `id = next_validator_id`, `reward_address = from`, `owner = from`, `stake = balance`, `registered_at_height = current_height`, `uptime_score = 10000`, `is_active = false`, `consensus_key = payload`
- The `next_validator_id` global is incremented
- A validator-by-address index entry is written
- A single-entry consensus-key history is initialized covering from `current_height` onward

**`UnregisterValidator = 0x21`**

Begins the validator's unbonding. The validator is removed from the active set immediately; its record, address index, key history, and stake persist for `UNBONDING_PERIOD` (120 blocks) before the stake is released to the owner.

**Payload**: empty.

**Validation**:
- Sender is a registered validator
- Validator is not a seed (seeds cannot unregister)
- If the validator is currently active, removing it would not drop the active set below `ACTIVE_SET_MIN`
- The validator does not already have a pending unbond

**State changes**:
- If the validator was active: the active set is updated (the validator is removed)
- Validator's `is_active` is set to false; `last_active_at` is set to current height
- Validator's `pending_unbond_height` is set to `current_height + UNBONDING_PERIOD`

After `UNBONDING_PERIOD` blocks, the block processor's `processUnbondExpiries` refunds the stake to the owner, deletes the validator record, deletes the address index, and deletes the key history.

**`UpdateRewardAddress = 0x22`**

Changes the validator's reward address. This is the address where block rewards are paid. It's freely changeable, with no effect on consensus participation.

**Payload**: 32 bytes — the new reward address.

**Validation**:
- Payload is exactly 32 bytes
- Sender is a registered validator (looked up by the current reward address)
- New address is not the null address
- New address is not already used as a reward address by a different validator

**State changes**:
- The old validator-by-address index entry is deleted
- A new validator-by-address index entry is written for the new address
- Validator's `reward_address` and `owner` are set to the new address
- **If the validator's `consensus_key` was null** (a pre-split validator), it's set to the current effective key before the update. This pins the signing key so the reward address can move without affecting consensus.

**`RotateConsensusKey = 0x23`**

Rotates the validator's consensus signing key. The old key stops being valid for new signatures the moment the rotation commits.

**Payload**: 32 bytes — the new consensus public key.

**Validation**:
- Payload is exactly 32 bytes
- Sender is a registered validator (looked up by the current reward address)
- Sender is the validator's owner (currently the reward address)
- New key is not equal to the current effective key
- Validator does not have a pending unbond in flight

**State changes**:
- Load the validator's key history. If it doesn't exist (a pre-feature validator), synthesize a single-entry history from `registered_at_height` to now, using the record's current effective key.
- Seal the last entry: set its `valid_until_height` to the current height.
- Append a new entry with the new key, `valid_from_height = current_height`, `valid_until_height = 0`.
- Write the updated history.
- Update the validator's cached `consensus_key`.

### Token operations

**`CreateToken = 0x50`**

Creates a new fungible token. The sender is the creator.

**Payload**:

```
[1]  decimals
[1]  backing (0 = unbacked, 1 = bridged)
[1]  name_len
[N]  name (up to TOKEN_NAME_MAX)
[1]  symbol_len
[M]  symbol (up to TOKEN_SYMBOL_MAX)
[8]  max_supply (LE) — 0 means unlimited
[2]  royalty_bps (LE)
[1]  has_fingerprint (0 or 1)
[32] fingerprint (only if has_fingerprint)
```

**Validation**:
- `name` is non-empty and within `TOKEN_NAME_MAX`
- `symbol` is between `TOKEN_SYMBOL_MIN` and `TOKEN_SYMBOL_MAX`
- `decimals <= 18`
- `backing <= 1`
- `royalty_bps <= 10000`
- The token's `isValid()` returns true

**State changes**:
- New `TokenInfo` record with `id = next_token_id`, the payload's metadata, and `creator = from`
- A token-supply entry with initial supply 0
- The `next_token_id` global is incremented

**`MintToken = 0x51`**

Mints new units of a token. Only the creator can mint.

**Payload**: empty. The token id is in `token_id`, the recipient in `to`, the amount in `amount`.

**Validation**:
- `amount != 0`
- `token_id != NATIVE_TOKEN_ID`
- Token exists
- Sender is the token's creator
- If `max_supply > 0`, `current_supply + amount <= max_supply`

**State changes**:
- Recipient's `token_balance(token_id)` increases by `amount`
- `token_supply(token_id)` increases by `amount`

**`BurnToken = 0x52`**

Burns units of a token the sender holds.

**Payload**: empty.

**Validation**:
- `amount != 0`
- `token_id != NATIVE_TOKEN_ID`
- Sender's `token_balance(token_id) >= amount`

**State changes**:
- Sender's `token_balance(token_id)` decreases by `amount`
- `token_supply(token_id)` decreases by `amount` (floors at 0)

**`UpdateTokenMeta = 0x53`**

Changes a token's metadata. Only the creator can call this. An empty field means "leave unchanged".

**Payload**:

```
[1]  name_len
[N]  name
[1]  symbol_len
[M]  symbol
[2]  royalty_bps (LE)
```

**Validation**:
- `token_id != NATIVE_TOKEN_ID`
- Token exists
- Sender is the token's creator
- If `name_len > 0`, name is within `TOKEN_NAME_MAX`
- If `symbol_len > 0`, symbol is between `TOKEN_SYMBOL_MIN` and `TOKEN_SYMBOL_MAX`
- If `royalty_bps != 0`, it's within 10000
- The updated token's `isValid()` returns true

**State changes**:
- Token's `name` (if `name_len > 0`), `symbol` (if `symbol_len > 0`), and `royalty_bps` (if `royalty_bps != 0`) are updated
- `max_supply` and `decimals` cannot be changed

### AMM operations

**`CreatePool = 0x30`**

Creates a constant-product AMM pool. The transaction's `token_id` and `amount` carry one side of the initial deposit; the payload carries the other side.

**Payload**:

```
[4]  token_b (LE)
[8]  amount_b (LE)
[2]  fee_bps (LE)
```

**Validation**:
- `token_id != token_b` (the two sides must differ)
- Both amounts non-zero
- `fee_bps <= AMM_MAX_FEE_BPS`
- If either side is CLRTY, that side's amount is at least `MIN_POOL_LIQUIDITY`
- Sender has enough balance on both sides

**State changes**:
- Sender's balance on both sides decreases by the respective amounts
- New `AmmPool` record with canonicalized `token_a = min(token_id, token_b)`, `token_b = max(...)`, corresponding reserves, `total_liquidity = sqrt(amount_a * amount_b)`, `fee_bps`
- New `AmmPosition` record with `liquidity = total_liquidity`, `owner = from`
- The position index is written (`(owner, pool_id) -> position_id`)
- `next_pool_id` and `next_position_id` globals are incremented

**`AddLiquidity = 0x31`**

Adds liquidity to an existing pool.

**Payload**:

```
[8]  pool_id (LE)
[8]  amount_other (LE)
```

The transaction's `token_id` and `amount` carry one side; the payload carries the pool id and the other side.

**Validation**:
- Pool exists and is active
- `token_id` is one of the pool's two tokens
- Both reserves non-zero
- Sender has enough balance on both sides

**State changes**:
- Sender's balance on both sides decreases
- The pool's reserves on both sides increase
- `total_liquidity` increases by `min(share_a, share_b)`, where `share_a = amount_a * total_liquidity / reserve_a` and `share_b = amount_b * total_liquidity / reserve_b`
- If the sender already has a position in this pool, its `liquidity` is incremented; otherwise a new position is created and indexed

**`RemoveLiquidity = 0x32`**

Removes liquidity from an LP position.

**Payload**:

```
[8]  position_id (LE)
[8]  amount (LE) — 0 means remove the entire position
```

**Validation**:
- Position exists
- Sender is the position's owner
- Position's liquidity is non-zero
- If `amount > 0`, it's at most the position's liquidity

**State changes**:
- The LP's pro-rata share of both reserves is credited to the sender: `share = amount * reserve / total_liquidity`, with 128-bit intermediates to avoid overflow
- If the removal is the last of the pool's liquidity (`amount == total_liquidity`), the LP gets the entire remaining reserves regardless of rounding
- The pool's reserves and `total_liquidity` decrease
- If `amount == total_liquidity`, the position's liquidity is zeroed and the position index is deleted
- Otherwise the position's liquidity is decremented and the index is kept
- If the pool is now drained (both reserves are zero), the pool record is deleted

**`Swap = 0x33`**

Swaps one token for the other side of a pool.

**Payload**:

```
[8]  pool_id (LE)
[8]  min_amount_out (LE)
```

The transaction's `token_id` and `amount` carry the input side; the recipient is in `to`.

**Validation**:
- Pool exists and is active
- `token_id` is one of the pool's two tokens
- Sender has enough balance of the input token
- Computed output is at least `min_amount_out`

**State changes**:
- Sender's balance of the input token decreases by `amount_in`
- Recipient's balance of the output token increases by `amount_out`
- The output is computed via the constant-product formula with the pool's fee: `amount_in_with_fee = amount_in * (10000 - fee_bps) / 10000`; `amount_out = reserve_out * amount_in_with_fee / (reserve_in + amount_in_with_fee)`
- The pool's reserves are updated
- The pool's volume window is updated: if the window has expired, the current volume rolls to last; otherwise the current volume is incremented by the CLRTY-equivalent of the input (computed against pre-swap reserves)

### Order operations

**`CreateOrder = 0x40`**

Places a limit order. The order may be Passive (rests in the price-time book) or Active (routes against an AMM pool).

**Payload**:

```
[4]  buy_token (LE)
[8]  min_buy_amount (LE)
[1]  mode (0 = Passive, 1 = Active)
[4]  pool_id (LE) — meaningful only for Active
[8]  expires_at_height (LE) — 0 means no expiry
[1]  condition_count
[N]  conditions (each 13 bytes)
```

The transaction's `token_id` is the sell token; `amount` is the sell amount.

**Order condition layout** (13 bytes each):

```
[1]  type
[8]  param1 (LE)
[4]  param2 (LE)
```

Condition types:
- `ExpiresAtHeight = 0x01` — condition is automatically failed at this height
- `PriceAbove = 0x02` — fails if the pool's price rises above `param1`
- `PriceBelow = 0x03` — fails if the pool's price falls below `param1`
- `VolumeBelow = 0x04` — fails if the pool's 24h volume falls below `param1`
- `BalanceBelow = 0x05` — fails if the owner's balance of `param2` falls below `param1`

**Validation**:
- `token_id != buy_token`
- `amount != 0`
- `min_buy_amount != 0`
- `condition_count <= ORDER_MAX_CONDITIONS` (8)
- For Active orders: `pool_id != 0`
- For Passive orders: `pool_id == 0`
- For Passive orders: canonical price doesn't overflow
- For Active orders with no conditions: the pool exists, is active, contains both tokens, and has non-zero reserves
- All conditions are individually valid
- Sender has enough balance of the sell token

**State changes**:
- Sender's sell-token balance decreases by `sell_amount` (the lock)
- The order record is written with `id = next_order_id`
- The order is added to the owner, pair, and pool indexes
- If Passive: the matcher runs (see below)
- If Active with no conditions: the router runs (see below)
- If Active with conditions: the order rests until the epoch boundary
- If the order still exists after execution and `expires_at_height != 0`, it's added to the expiry index
- `next_order_id` global is incremented

**Passive matching (during the transaction)**:
- The taker's sell-token lock is taken and the order record is written
- The matcher walks the opposite side of the book, best price first
- For each crossing order: the maker's record is authoritative for its price, the fill is `min(maker.remaining, taker.remaining)` converted to base units at the maker's price, and the fill is executed
- Self-trades: the maker is cancelled (charging `ORDER_CANCEL_FEE_ATOMIC`), the taker continues
- Stale book rows are rejected
- The book index is written once when the order first rests, and removed when the order leaves
- Partial fills do not move the book row
- The taker's remainder rests with a fresh sequence if not fully filled

**Active routing (during the transaction, no conditions)**:
- The router computes the maximum input that satisfies the order's limit
- If the pool's current price allows a fill: the fill is executed against the pool, reserves are updated, the counterparty's balance is credited, the fill is recorded
- If the pool's price is unfavorable: the order rests
- If the pool is unroutable (missing, closed, wrong pair, zero reserves): the transaction fails (the pre-route check catches this before the lock is taken)

**Receipt**: carries the fills produced by the matcher or the router in execution order.

**`CancelOrder = 0x41`**

Cancels a resting or unfulfilled order.

**Payload**: 8 bytes — the order id (LE).

**Validation**:
- Order exists
- Sender is the order's owner

**State changes**:
- The order's remaining sell-token lock is refunded to the owner (minus `ORDER_CANCEL_FEE_ATOMIC`)
- The order is removed from every index (owner, pair, pool, expiry)
- The order is removed from the book
- The order record is deleted

### NFT operations

Clarity's NFT system has nine transaction types. An NFT is a state record plus a shadow token (a `TokenInfo` with `maxSupply = 1` and `decimals = 0`). Wrapped NFTs hold an underlying balance at a virtual address derived from the NFT's id.

**`CreateNftCollection = 0x42`**

Creates an NFT collection. May optionally carry a reward schedule.

**Payload**:

```
[1]  name_len
[N]  name (up to NFT_COLLECTION_NAME_MAX)
[1]  symbol_len
[M]  symbol (up to NFT_COLLECTION_SYMBOL_MAX)
[2]  base_uri_len (LE)
[K]  base_uri (up to NFT_URI_MAX)
[4]  reward_token_id (LE) — 0 = no schedule
[8]  reward_rate_per_epoch (LE)
[8]  reward_escrow_amount (LE)
```

**Validation**:
- `name` non-empty and within `NFT_COLLECTION_NAME_MAX`
- `symbol` within `NFT_COLLECTION_SYMBOL_MAX`
- `base_uri` within `NFT_URI_MAX`
- If `reward_token_id == 0`: `reward_rate_per_epoch == 0` and `reward_escrow_amount == 0`
- If `reward_token_id != 0`: `reward_rate_per_epoch > 0`
- Sender has enough balance of the reward token to fund the escrow

**State changes**:
- New `NftCollection` record with `id = next_collection_id`
- If `reward_escrow_amount > 0`: sender's balance of the reward token decreases, the collection's virtual escrow address is credited, and `reward_escrow_remaining` is set
- `next_collection_id` global is incremented

**`MintNft = 0x43`**

Mints a standalone NFT. Creates a shadow token, mints it to the creator, and writes the `NftInfo` record.

**Payload**:

```
[8]  collection_id (LE) — 0 = no collection
[32] metadata_hash
[1]  has_hash (0 or 1)
[2]  uri_len (LE)
[N]  metadata_uri
```

**Validation**:
- If `has_hash == 0`, the hash must be zero
- `metadata_uri` within `NFT_URI_MAX`
- If `collection_id != 0`: collection exists

**State changes**:
- New `TokenInfo` shadow with `id = next_token_id`, `maxSupply = 1`, `decimals = 0`, name and symbol inherited from the collection (or defaulted)
- Shadow minted to the creator: `token_supply(shadow_id) = 1`, creator's `token_balance(shadow_id) = 1`
- New `NftInfo` record with `owner = creator`, `shadow_token_id = shadow_id`, `metadata_hash`, `metadata_uri`, `collection_id`
- If `collection_id != 0`, the collection's `minted_count` is incremented
- `next_token_id` global is incremented

**`WrapNft = 0x44`**

Mints a wrapped NFT. Takes `wrapped_amount` of the underlying token from the creator and holds it at the NFT's virtual custody address.

**Payload**:

```
[4]  underlying_token_id (LE)
[8]  wrapped_amount (LE)
[8]  collection_id (LE)
[32] metadata_hash
[1]  has_hash
[2]  uri_len (LE)
[N]  metadata_uri
```

**Validation**:
- `underlying_token_id != 0`
- `wrapped_amount != 0`
- Sender has enough balance of the underlying token
- The underlying cannot be the NFT's own shadow token (checked after the shadow id is allocated)
- Same collection and metadata checks as MintNft

**State changes**:
- Sender's balance of the underlying token decreases by `wrapped_amount`
- The NFT's virtual custody address (`Blake2b("nfa " || LE(nft_id))`) is credited with `wrapped_amount`
- New shadow token and `NftInfo` record as in MintNft, with `underlying_token_id` and `wrapped_amount` set

**`TransferNft = 0x45`**

Transfers an NFT to a new owner.

**Payload**:

```
[8]  nft_id (LE)
[32] new_owner
```

**Validation**:
- NFT exists
- Sender is the NFT's current owner
- `new_owner != sender`

**State changes**:
- If the NFT is in a collection with a reward schedule: accrued rewards since `last_accrual_height` are credited to the seller's `pending_rewards`
- The shadow token's balance is moved from seller to buyer
- The old owner's index row is removed (via `unindexNft`)
- The `NftInfo` record's `owner` is updated; `last_accrual_height` is reset to the current height; `accrued_owed` is cleared
- The new owner's index row is written
- **Custody does not move**: it stays at the NFT's virtual address. Only the right to control it moves.

**`BurnNft = 0x46`**

Burns an NFT. If wrapped, the custody is released to the owner.

**Payload**: 8 bytes — the NFT id.

**Validation**:
- NFT exists
- Sender is the NFT's current owner

**State changes**:
- If the NFT is in a collection with a reward schedule: accrued rewards are credited to the owner
- The shadow token balance is zeroed and the shadow token's supply is set to 0
- If wrapped: the custody balance is debited and the owner is credited
- The `NftInfo` record and its indexes are deleted
- If the NFT was in a collection, the collection's `minted_count` is decremented

**`UpdateNftMetadata = 0x47`**

Changes an NFT's metadata. Owner-only. A `freeze` flag can be set on the same transaction, after which no further metadata changes are possible.

**Payload**:

```
[8]  nft_id (LE)
[32] metadata_hash
[1]  has_hash
[2]  uri_len (LE)
[N]  metadata_uri
[1]  freeze
```

**Validation**:
- NFT exists
- Sender is the owner
- NFT is not frozen
- Same hash and URI checks as MintNft

**State changes**:
- NFT's `metadata_hash` and `metadata_uri` are updated
- If `freeze == 1`, `frozen` is set to true (one-way)

**`TopUpNft = 0x48`**

Credits additional underlying to a wrapped NFT's custody.

**Payload**:

```
[8]  nft_id (LE)
[4]  token_id (LE)
[8]  amount (LE)
```

**Validation**:
- NFT exists
- `amount != 0`
- If the NFT is wrapped: `token_id == underlying_token_id`
- Sender has enough balance

**State changes**:
- Sender's balance decreases by `amount`
- Custody address is credited by `amount`
- If the NFT is wrapped and `token_id == underlying_token_id`: `wrapped_amount` is incremented on the `NftInfo` record

**`ClaimNftReward = 0x49`**

Settles every NFT reward the caller has accrued into `pending_rewards`.

**Payload**: empty.

**State changes**:
- The caller's NFTs are enumerated via the owner index
- For each NFT in a reward-bearing collection, the accrual since `last_accrual_height` is computed and added to a running total
- Each settled NFT's `last_accrual_height` is reset and `accrued_owed` is cleared
- The running total is added to the caller's `pending_rewards`

The caller must subsequently call `ClaimRewards` (or include it as a following transaction) to move the pending rewards into their balance.

**`RefillCollectionReward = 0x4A`**

Creator-only. Adds to a collection's reward escrow and un-pauses it if it was drained.

**Payload**:

```
[8]  collection_id (LE)
[8]  amount (LE)
```

**Validation**:
- Collection exists
- Collection has a reward schedule
- Sender is the collection's creator
- `amount != 0`
- Sender has enough balance of the reward token

**State changes**:
- Sender's balance of the reward token decreases by `amount`
- The collection's virtual escrow address is credited by `amount`
- `reward_escrow_remaining` is incremented
- If the collection was paused and the escrow is now positive, `reward_paused` is set to false

### System transactions

System transactions are generated by the chain itself, not submitted by users. They are included in blocks by the block processor and have `tx_type >= 0xF0`.

**`BlockReward = 0xF0`**

Records the block's reward distribution. Emitted by the block processor for every block. Its state effects (validator rewards, pot updates) are applied by the reward distribution path, not by the executor.

**`OrderExpired = 0xF1`**

Records an order's expiration. Emitted by the block processor when an order's `expires_at_height` has passed. Its state effects (refund, delete) are applied by the expiry path.

**`Slash = 0xF2`**

Records a validator's equivocation. Emitted by the proposer when it has verified equivocation evidence. The payload carries the two conflicting votes.

**Payload**:

```
[4]  len_a (LE)
[N]  vote_a (encoded Vote)
[4]  len_b (LE)
[M]  vote_b (encoded Vote)
```

**Validation**: the two votes are verified against the validator's effective consensus key at the vote's height. Both signatures must verify, and the two votes must conflict.

**State changes**:
- The target validator's stake is reduced by `SLASH_AMOUNT_BPS` (5%)
- The validator's `reward_multiplier` is reduced by `REWARD_MULTIPLIER_PENALTY` (2000 bps, down to a floor of 2000)
- The slashed amount is added to the pot
- The validator's `infraction_count` is incremented
- The validator's `last_infraction_height` is set

**Policy exceptions** (no-op, not failures):
- The target is a seed
- The target is not a registered validator
- The target's stake is 0

These are no-ops rather than block rejections. If ineligibility rejected the block, a proposer could halt the chain by including one such transaction in every block.

## The execution pipeline

Every transaction passes through the same pipeline in `TransactionExecutor::execute`. The stages are:

### Validation stages

1. **Structural validation.** `tx.isWellFormed()` checks that the fields have plausible types and sizes (chain_id non-zero, from non-null, etc.). This is the same check the mempool runs on admission.

2. **Chain ID.** `tx.chain_id == ctx.chain_id`. A transaction signed for a different network is rejected.

3. **Expiry.** If `tx.valid_until_height != 0` and `ctx.current_height > tx.valid_until_height`, the transaction is rejected.

4. **Signature.** The signing hash is recomputed and verified against `tx.from`. A bad signature is rejected.

5. **Nonce.** `account(from).nonce == tx.nonce`. A nonce too high or too low is rejected.

6. **Fee charge.** The sender's balance must cover `tx.fee`. If it doesn't, the transaction is rejected **before** the type-specific dispatch.

7. **Dispatch.** The type-specific handler runs. If it returns `Success`, the nonce is bumped. If it returns `Failure`, the nonce is **not** bumped (but the fee was already charged).

The order matters. The fee is charged before the dispatch, so a failed transaction still pays its fee. The nonce is bumped only on success, so a failed transaction can be retried with the same nonce (as long as the failure wasn't nonce-related).

### Fee handling

The fee is charged in every transaction, success or failure, as long as the earlier stages (structural, chain ID, expiry, signature, nonce) pass. If any of the earlier stages fails, the fee is **not** charged — the transaction never entered the executor's state-changing path.

This is a deliberate design. A transaction that fails structurally or has a bad signature is discarded by the mempool before it ever reaches the block processor, so the fee is not a concern. A transaction that fails semantically (insufficient balance for the amount, invalid condition, etc.) is a real attempt to do something and pays its fee, which is the standard economic model.

The fee is denominated in atomic CLRTY (the native token). Token transactions pay their fee in CLRTY, not in the token being moved.

### Nonce handling

The nonce must exactly equal the sender's current nonce. A transaction with a nonce greater than the current nonce is rejected by the mempool (the mempool enforces sequential nonces); a transaction with a nonce lower than the current nonce is rejected as stale.

On success, the nonce is incremented by 1. On failure, the nonce is not changed.

There is no nonce gap allowance. A sender that wants to submit two transactions in a batch must submit them with consecutive nonces, and the mempool will hold them in the correct order. If the first fails (say, insufficient balance), the second is stuck behind it — the mempool does not skip ahead.

## Receipts

### The receipt format

Every transaction that succeeds or fails produces a receipt. The receipt is written to the state (`Keys::receipt(txid)`) and to the RPC-facing index.

**Receipt fields**:

| Field | Type | Notes |
| --- | --- | --- |
| `status` | u8 | 0 = Success, 1 = Failure |
| `fee_paid` | u64 | The fee that was charged |
| `fills` | `Fill[]` | Fills produced by this transaction |

The fill list is empty for every transaction type except `CreateOrder`, and even for `CreateOrder` it's empty unless the order crossed. The fills are in execution order.

### Fill records

A fill has a maker side and a taker side for a Passive order, or just a taker side for an Active order (the "maker" is the pool).

**Fill fields**:

| Field | Type | Notes |
| --- | --- | --- |
| `source` | u8 | 0 = Limit (book match), 1 = Amm (pool route) |
| `maker_order_id` | u64 | The maker's order id. Zero for an AMM fill. |
| `taker_order_id` | u64 | The taker's order id. |
| `pool_id` | u32 | The pool id for an AMM fill. Zero for a limit fill. |
| `qty_base` | u64 | Quantity in base units (`min(sell, buy)`). |
| `qty_quote` | u64 | Quantity in quote units (`max(sell, buy)`). |
| `price` | u64 | Effective price, canonical frame, scaled by `BOOK_PRICE_SCALE`. |
| `base_token` | u32 | The base token's id. |
| `quote_token` | u32 | The quote token's id. |

The canonical frame means every fill has a consistent shape regardless of the direction of the underlying trade. A client that wants to know whether a fill was a book match or an AMM route reads `source`.

## Payload encoding conventions

Payloads are little-endian. Multi-byte integers are encoded least-significant byte first. This matches the rest of the codebase's on-disk convention.

Strings are **not** null-terminated. A length-prefixed string carries its length as a 1-byte or 2-byte integer immediately preceding the bytes. The `TransactionBuilder.cpp` code uses `appendLenString` for this; the `TransactionExecutor.cpp` code reads the length first, then the bytes.

Addresses and hashes are **fixed-width**. A 32-byte address is exactly 32 bytes; a 32-byte hash is exactly 32 bytes. There is no length prefix on fixed-width values.

**Optional fields** are represented by a **has-flag**. A `has_hash` byte precedes the hash; if the flag is 0, the hash bytes are still written (as 32 zero bytes) but are not meaningful. This keeps the layout fixed.

Some payloads have no fixed layout and are validated by a dedicated structural check. `CreateOrder` is the canonical example: its payload has a variable number of conditions, each of which has its own layout, and the total size depends on the count. The executor calls `validateCreateOrderStructure` before parsing, so a malformed payload is rejected before any field is read.

## What a transaction cannot do

- **Cannot specify an arbitrary recipient for the fee.** The fee is always charged to the sender's balance in CLRTY.
- **Cannot retry a failed transaction without re-signing.** A failed transaction's nonce is not bumped, but the fee is charged. A retry must be a new transaction with a new signature (and a higher fee to account for the first one's cost, or the same fee if the failure was due to a race).
- **Cannot exceed `TX_MAX_PAYLOAD_SIZE`.** The payload is capped at 64 KiB.
- **Cannot be larger than 1 MiB total.** The mempool enforces a 1 MiB hard cap per transaction.
- **Cannot target a different chain.** The chain id is signed over.
- **Cannot be replayed.** The nonce prevents it.
- **Cannot sign on behalf of someone else.** The signature must verify against `tx.from`.
- **Cannot bypass the mempool for the current block.** A transaction must be in the mempool to be included in a block. There is no "direct block inclusion" path for users.
- **Cannot pay fees in a non-native token.** Fees are always CLRTY.
- **Cannot have a fee of zero.** The mempool rejects zero-fee transactions.
- **Cannot use a nonce that hasn't been reached.** The mempool enforces sequential nonces.