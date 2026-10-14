# Clarity DEX and AMM

Clarity has two on-chain trading mechanisms, both native to the
protocol — they are not smart contracts:

- **An automated market maker (AMM).** Constant-product pools
  (`x * y = k`) with a creator-set fee. Anyone can create a pool,
  add liquidity, remove liquidity, and swap.
- **A price-time-priority order book.** Limit orders rest in a
  sorted book and are matched by an in-process engine. Orders can
  be **Passive** (rest in the book and wait) or **Active** (route
  against a specific AMM pool).

There is no VM, no contract language, and no gas metering. Every
operation is a typed transaction with an executor handler. This
makes the system cheap, deterministic, and easy to reason about,
at the cost of flexibility: adding a new pool type, a new curve, or
a new order mode requires a hard fork.

This document is for integrators. It describes what the two
mechanisms do, how they interact, and how to talk to them over RPC
and by submitting transactions.

---

## Table of contents

- [The AMM](#the-amm)
  - [The pool](#the-pool)
  - [Pool creation](#pool-creation)
  - [Adding liquidity](#adding-liquidity)
  - [Removing liquidity](#removing-liquidity)
  - [The swap formula](#the-swap-formula)
  - [The fee](#the-fee)
  - [Pool closure](#pool-closure)
  - [Volume tracking](#volume-tracking)
  - [LP positions](#lp-positions)
- [The order book](#the-order-book)
  - [The canonical frame](#the-canonical-frame)
  - [Passive orders](#passive-orders)
  - [Active orders](#active-orders)
  - [Order conditions](#order-conditions)
  - [Fills](#fills)
  - [The matching process](#the-matching-process)
  - [Self-trade](#self-trade)
  - [Cancellation and expiry](#cancellation-and-expiry)
- [How the two interact](#how-the-two-interact)
- [Transaction reference](#transaction-reference)
- [RPC reference](#rpc-reference)
- [Known limitations](#known-limitations)
- [Integration patterns](#integration-patterns)

---

## The AMM

### The pool

A pool is a record in the state SMT, keyed by `H("pool" || pool_id)`.
It holds:

| Field | Meaning |
|---|---|
| `id` | The pool's id, allocated from a monotonic counter |
| `creator` | The address that created the pool |
| `token_a`, `token_b` | The two token ids, with `token_a < token_b` (canonical) |
| `reserve_a`, `reserve_b` | The current reserves of each token |
| `total_liquidity` | The total LP token supply |
| `fee_bps` | The swap fee in basis points |
| `created_at_height` | The height the pool was created at |
| `active` | Whether the pool is active (currently always `true`) |
| `volume_window_height`, `volume_current`, `volume_last` | Rolling volume tracking (see below) |

The canonical ordering (`token_a < token_b`) is enforced by
`AmmPool::isValid()`. This means a pool for the pair (A, B) and a
pool for the pair (B, A) are the same pool: both would have
`token_a = min(A, B)` and `token_b = max(A, B)`. There is **no**
per-creator directionality.

There is **no uniqueness constraint** on pairs. A pair can have
multiple pools, distinguished by fee tier or by creator. Clients
that want "the pool for a pair" should either pick the one with
the most liquidity, or let the user choose.

### Pool creation

A pool is created by a `CreatePool` transaction. The transaction's
`token_id` and `amount` fields carry one side of the initial
liquidity; the payload carries the other:

```
payload layout:
  [4]  token_b (LE)
  [8]  amount_b (LE)
  [2]  fee_bps (LE)
```

The transaction's `token_id` and `amount` are `token_a` and
`amount_a`. If `token_a > token_b`, the executor swaps them so the
pool ends up canonical, taking `amount_a` from `token_b`'s field
and vice versa. The user's debit is always the sum of the two
amounts they specified, regardless of which side ends up as A.

**Fee constraints.** `fee_bps` must be at most `AMM_MAX_FEE_BPS`
(1000 = 10%). The default, if a client doesn't specify, is
`AMM_DEFAULT_FEE_BPS` (30 = 0.3%). The fee is per-pool and cannot
be changed after creation.

**Minimum liquidity.** Both initial reserves must be at least
`MIN_POOL_LIQUIDITY` (1000 whole CLRTY equivalent, i.e.
`1000 * ATOMIC_UNITS_PER_COIN`). A pool whose initial reserves are
below the floor is rejected. This prevents a class of griefing
pools whose price is trivially manipulable for a few atomic units
and which have no economic function.

The floor is denominated in atomic units of the native token and
applies to both sides regardless of the tokens' own decimals. A
token with `decimals = 0` therefore needs the equivalent of 1000
whole CLRTY of its own units on each side to be poolable. That is
a deliberate "you must be serious about this" floor for a chain
where the native unit is the reference.

**Initial liquidity.** The pool's `total_liquidity` is set to the
integer square root of `amount_a * amount_b`, computed in 128-bit
arithmetic. This is the Uniswap V2 convention: it gives the
initial LP a share proportional to the geometric mean of the two
deposits, so an LP who deposits unbalanced amounts is not unfairly
rewarded.

**No uniqueness constraint.** Two pools can exist for the same
pair with different fee tiers or different creators. The executor
does not check for a duplicate pair.

### Adding liquidity

An `AddLiquidity` transaction adds liquidity to an existing pool.
The transaction's `token_id` and `amount` carry one side; the
payload carries the other:

```
payload layout:
  [8]  pool_id (LE)
  [8]  amount_b (LE)
```

The side that goes in `token_id`/`amount` is the "input" side; the
side in the payload is the "other" side. Which is which doesn't
matter to the executor — it reads both, checks both balances, and
computes the LP tokens minted.

**LP minting.** The LP tokens minted is the minimum of:

```
share_a = amount_a * total_liquidity / reserve_a
share_b = amount_b * total_liquidity / reserve_b
```

Both products are computed in 128-bit arithmetic to avoid overflow
on realistic pool sizes.

This means an LP who provides unbalanced amounts is credited at the
lesser ratio, effectively donating the excess to the pool. The
convention is: **provide amounts proportional to the current
reserves**, or accept a small loss.

**Position handling.** If the caller already has a position in this
pool, the newly minted LP tokens are added to it. Otherwise a new
position is created. There is exactly **one position per (owner,
pool)**, which the `getPositionByOwner` RPC method relies on.

**Prerequisites.** The pool must exist and be active, and its
reserves must be non-zero on both sides. A drained pool (both
reserves zero, no LP shares) cannot have liquidity added — see
[Pool closure](#pool-closure).

### Removing liquidity

A `RemoveLiquidity` transaction removes a portion of an LP
position:

```
payload layout:
  [8]  position_id (LE)
  [8]  amount (LE)           — 0 = remove the whole position
```

If `amount` is zero, the entire position is removed. If
`amount > 0`, the executor removes that many LP tokens' worth of
reserves and leaves the rest in the position.

**Partial removal.** The LP receives:

```
share_a = amount * reserve_a / total_liquidity
share_b = amount * reserve_b / total_liquidity
```

Both products are computed in 128-bit arithmetic. The pool's
reserves are decremented by those amounts, `total_liquidity` is
decremented by `amount`, and the position's `liquidity` is
decremented by `amount`. The position index entry is kept.

**Full removal.** If `amount` equals the position's full liquidity,
the position's `liquidity` is set to zero and the position index
entry is deleted. The position record itself is left in place with
`liquidity = 0` and no index entry — invisible to any indexed
query, but present in state. See
[Known limitations](#known-limitations).

**Last LP drain.** If the removal empties the pool's entire LP
supply (i.e. `amount == pool.total_liquidity`), the executor
credits the LP with the *full* reserves rather than the pro-rated
share. This special case exists because integer rounding can leave
dust in the reserves on a pro-rata removal, and a pool with `1`
unit on each side and no LP shares is not `isClosed()` (which
requires both reserves to be exactly zero) and cannot be drained
or added to. The special case makes "the last LP gets everything"
an explicit contract rather than a rounding-dependent accident.

After the removal, if the pool's reserves are both zero and
`total_liquidity` is zero, the pool record is deleted.

### The swap formula

A `Swap` transaction swaps one token for the other in a pool:

```
payload layout:
  [8]  pool_id (LE)
  [8]  min_amount_out (LE)
```

The transaction's `token_id` and `amount` are the input token and
amount; `to` is the recipient of the output. The swap formula is
the standard constant-product-with-fee:

```
amount_in_with_fee = amount_in * (10000 - fee_bps) / 10000
amount_out = reserve_out * amount_in_with_fee
           / (reserve_in + amount_in_with_fee)
```

All arithmetic is integer, with 128-bit intermediates used
throughout. The result is floored, which favors the pool slightly
(the trader gets a tiny bit less than the exact rational).

**Slippage protection.** `min_amount_out` is the minimum the trader
will accept. If the computed `amount_out` is less, the swap fails
and the fee is charged but no tokens move. This is what protects
the trader from a sandwich: a front-runner who moves the price
between the trader's submission and their inclusion causes the
swap to revert rather than execute at a worse price.

### The fee

The fee is charged on the input side:

```
amount_in_with_fee = amount_in * (10000 - fee_bps) / 10000
```

The difference (`amount_in - amount_in_with_fee`) stays in the
pool as additional reserve. It is not distributed to LPs
explicitly; instead, the pool's reserves grow, and each LP's share
of the pool is worth more when they eventually remove liquidity.
This is the standard Uniswap V2 model.

**Implication for LPs.** The fee accrues to the pool's reserves.
An LP who never removes liquidity never realizes the fee; an LP
who removes realizes their pro-rata share of the accumulated fees
at that moment. There is no separate "claim fees" operation.

**Implication for traders.** The effective price includes the fee.
The `min_amount_out` field should be computed against the
fee-inclusive output, not the raw constant-product output.

### Pool closure

A pool is **closed** when:

```
total_liquidity == 0 && reserve_a == 0 && reserve_b == 0
```

That's `AmmPool::isClosed()`. When a `RemoveLiquidity` transaction
brings a pool to this state, the executor calls
`state.deleteAmmPool(pool.id)` and the pool record is removed. The
pool no longer exists for subsequent `Swap`, `AddLiquidity`, or
`RemoveLiquidity` transactions, and `getPool` returns
`PoolNotFound`.

The last-LP drain special case above guarantees that the final
removal of a position always brings the pool to exactly this
state, regardless of integer rounding.

### Volume tracking

Each pool tracks a rolling volume for `OrderConditionType::VolumeBelow`.
The window is a **tumbling window** of `ROTATION_INTERVAL` blocks
(60 blocks, ~1 minute at 1-second block times). The fields are:

- `volume_window_height`: the height the current window started at.
- `volume_current`: the volume accumulated in the current window.
- `volume_last`: the volume accumulated in the previous complete window.

The roll happens lazily, on the next swap after a window ends. If a
condition reads the volume between the window boundary and the next
swap, `AmmPool::reportedVolume()` returns `volume_current` as if it
were the previous window's total.

**Volume is denominated in CLRTY.** For a swap where one side is
CLRTY, the volume contribution is the CLRTY-equivalent of the input
amount, computed against the *pre-swap* reserves. For a swap in a
pool with **no CLRTY side**, the contribution is zero — there is no
oracle to convert token/token trades into CLRTY terms.

**Implication.** `VolumeBelow` conditions are meaningful only for
pools with a CLRTY side. For token/token pools, they are always
"below" whatever threshold is set, or never, depending on how the
condition's comparator is defined. Clients that place Active orders
with `VolumeBelow` conditions against token/token pools should
warn the user.

### LP positions

An LP position is an `AmmPosition` record, keyed by `H("pos " ||
position_id)`. It holds:

| Field | Meaning |
|---|---|
| `id` | The position id, allocated from a monotonic counter |
| `owner` | The address that owns the position |
| `pool_id` | The pool the position is in |
| `liquidity` | The LP token amount held |
| `created_at_height` | The height the position was created at |

There is **one position per (owner, pool)**. A second `AddLiquidity`
from the same owner to the same pool adds to the existing position
rather than creating a second one. This is enforced by the
`(owner, pool_id) -> position_id` index that `AddLiquidity` maintains.

**LP tokens are not transferable.** They are an accounting unit
internal to the position, not a separate token. To change ownership
of an LP position, the owner must remove liquidity and re-add it
from a different address. There is no `TransferLp` transaction and
no shadow token for LP positions.

**Positions are not deleted on removal.** When a position's
liquidity is fully removed, the position record stays with
`liquidity = 0` and its index entry is deleted. The record is
invisible to any caller that goes through the index, but it is
still in state.

---

## The order book

### The canonical frame

Orders are created directionally: "sell A, buy B, receive at least
M of B for N of A." That gives a rational limit price `M/N` in
B-per-A. Two orders on opposite sides of the same pair — one
selling A, one selling B — are the same market with reciprocal
prices.

To avoid dealing with two frames, the book **canonicalizes** to a
single direction:

```
base   = min(sell_token, buy_token)
quote  = max(sell_token, buy_token)
price  = quote per base
```

The canonical price is stored scaled by `BOOK_PRICE_SCALE = 10^10`,
so integer arithmetic can represent prices with 10 decimal places
of precision.

**Rounding.** When computing the canonical price:

- A **seller** (selling the base) floors: `floor(min_buy * SCALE / sell_amount)`.
- A **buyer** (selling the quote) ceils: `ceil(sell_amount * SCALE / min_buy)`.

Both round toward "harder to cross", so rounding never invents a
fill that the exact rationals would have forbidden. The
intermediate product `min_buy_amount * BOOK_PRICE_SCALE` is
computed in 128-bit arithmetic and checked against `UINT64_MAX`
before narrowing; an order whose canonical price would overflow is
rejected at creation.

**Side byte.** The book key includes a side byte:

- Side 0: the order sells the base (so it's an ask).
- Side 1: the order sells the quote (so it's a bid).

The `~canonical_price` is stored in the key, so ascending key order
yields best-price-first on both sides.

### Passive orders

A `Passive` order rests in the book and waits for a taker. Its
`pool_id` field must be zero.

When a `CreateOrder` transaction creates a Passive order, the
executor:

1. Takes the sell-token lock (debits the seller's balance by
   `sell_amount`).
2. Persists the order record.
3. Calls the matching engine, which crosses the order against any
   resting orders on the opposite side at a compatible price.
4. If the order rests (either because it didn't cross, or because
   it crossed partially and has a remainder), adds it to the book
   index with a fresh sequence number.
5. If the order fully filled, deletes the record and does not add a
   book row.

The matching engine fills against resting orders at the **maker's**
price. Partial fills are supported; the taker's remainder either
rests or continues crossing, depending on the price.

### Active orders

An `Active` order routes against a specific AMM pool, identified by
`pool_id`. Its `pool_id` field must be non-zero.

An Active order is executed at one of two points:

- **On creation**, if it has no conditions. The executor calls the
  router immediately, after the sell-token lock is taken. The
  router either fills the order against the pool or leaves it
  resting.
- **At the epoch boundary**, if it has conditions. The condition
  evaluator runs at the end of each epoch; if the conditions hold,
  the order is routed; if they don't, the order is cancelled.

A partially filled Active order rests in state and is re-tried at
the next epoch boundary.

### Order conditions

An order can carry up to 8 conditions. A condition is a
`(type, param1, param2)` tuple:

| Type | Meaning | Valid params |
|---|---|---|
| `ExpiresAtHeight` | Cancel when height >= param1 | `param1 != 0`, `param2 == 0` |
| `PriceAbove` | Cancel if the pool price exceeds `param1 / 10^10` | `param1 != 0`, `param2 != 0` |
| `PriceBelow` | Cancel if the pool price falls below `param1 / 10^10` | `param1 != 0`, `param2 != 0` |
| `VolumeBelow` | Cancel if the pool's 24h volume is below `param1` | `param1 != 0`, `param2 != 0` |
| `BalanceBelow` | Cancel if the owner's balance of `param1` is below `param2` | `param1 != 0`, `param2 == 0` |

`param2` is meaningful only for `PriceAbove`, `PriceBelow`, and
`VolumeBelow`, where it disambiguates the condition's frame (e.g.
which pool the price is checked against). The executor's condition
evaluator is the authority on what `param2` means for each type.

A condition that fails at the epoch boundary causes the order to be
**cancelled**, refunding the remaining lock minus
`ORDER_CANCEL_FEE_ATOMIC` (1 atomic unit).

### Fills

A `Fill` is a record of a partial or complete match. It appears in
two places:

- In a `Receipt`, in the `fills` vector, when a `CreateOrder`
  crossed one or more resting orders.
- In a **fill history** index, keyed by pair and by order id, which
  the `getOrderFills` and `getPairTrades` RPC methods scan.

A fill has:

| Field | Meaning |
|---|---|
| `source` | `Limit` for a matcher fill, `Amm` for a router fill |
| `maker_order_id` | The resting order's id (0 for an AMM fill) |
| `taker_order_id` | The taker's id |
| `pool_id` | The pool's id (0 for a limit fill) |
| `base_token`, `quote_token` | The canonical pair |
| `qty_base`, `qty_quote` | The amounts in canonical frame |
| `price` | The effective price in `quote per base`, scaled |

A fill produced by the router (an AMM fill) has
`maker_order_id == 0` and `source == Amm`. A client that wants to
know whether a fill was a book match or an AMM route reads
`source`, not the presence or absence of a maker id.

### The matching process

The matching engine processes a Passive taker as follows:

1. Canonicalize the taker.
2. Compute the taker's canonical limit price.
3. Collect candidate resting orders from the opposite side of the
   book, best-price-first, capped at `MAX_BOOK_LEVELS_PER_TAKER`
   (256).
4. Process candidates in order. Because the book is price-sorted
   and the crossing check is monotone in price, the loop stops at
   the first candidate that doesn't cross.
5. For each crossing candidate:
   - Reject stale rows (rows whose order has been deleted or
     filled).
   - Handle self-trades (see below).
   - Compute the fill quantity as the minimum of the two sides'
     remainders, converted to base units at the maker's price.
   - Execute the fill: move tokens between the maker and the
     taker, update both orders' `filled_amount`, write fill
     history.
6. Persist the taker: delete it if fully filled, otherwise
   re-write it and add a book row with a fresh sequence number.

The execution price is the resting order's price. This is the
standard price-time priority convention: the maker gets the price
they asked for, and the taker pays it.

### Self-trade

If the taker's owner matches the maker's owner, the resting maker
is **cancelled** and the taker continues to the next resting order.

The maker is refunded their remaining lock **in full**; no cancel
fee is charged. This is deliberate: the maker posted a resting
order in good faith and did not choose to cancel it. Charging the
maker a fee for a cancellation triggered by someone else's taker
would be a griefing vector — a taker could force every maker in the
book to pay the cancel fee at no cost to themselves.

The taker's cost for triggering the cancel is their own transaction
fee, which the executor already charged at dispatch. There is no
separate self-trade fee on the taker side.

### Cancellation and expiry

An order is removed from the book in three cases:

- **Explicit `CancelOrder`.** The owner submits a `CancelOrder`
  transaction with the order id in the payload. The remaining lock
  is refunded minus `ORDER_CANCEL_FEE_ATOMIC`. The order is
  removed from every index: owner, pair, pool, expiry, and book.
- **Expiry.** If `order_expires_at_height != 0` and the height
  reaches it, the order is cancelled by the expiry path. Same
  refund, same index cleanup.
- **Condition failure.** At the epoch boundary, if an order's
  conditions don't hold, the order is cancelled. Same refund, same
  index cleanup.

All three go through the same internal path, so a cancellation
cannot leave a book row behind.

---

## How the two interact

The two mechanisms are **separate markets**. A user chooses one
mechanism per order:

- A **Passive** order rests in the book and is filled by takers
  who cross it.
- An **Active** order routes against a specific AMM pool.

There is **no atomic cross-mechanism routing**. A taker cannot
"fill this book order against that pool" in a single transaction.
This is a deliberate design choice: it keeps the matching engine
and the AMM router independent, and it avoids the complexity of
deciding which mechanism gets priority when both could fill.

**In practice**, this means:

- If a Passive order is mispriced relative to the AMM, someone can
  take it via the matcher for a small profit.
- If an Active order is mispriced, it either routes at the pool's
  current price (if the price is favorable) or rests until the
  next epoch.
- A trader who wants the best available price should compare the
  book's best bid/ask to the pool's effective price, and choose
  the mechanism that's better.

The client library should expose both markets and let the user
decide. A future feature could add an aggregator that picks the
better venue automatically, but that's not in v1.

---

## Transaction reference

### `CreatePool` (0x30)

```
token_id:  one side's token id (amount_a's token)
amount:    one side's amount
payload:
  [4]  token_b (LE)
  [8]  amount_b (LE)
  [2]  fee_bps (LE)
```

The executor canonicalizes the pair (`token_a < token_b`), checks
both amounts against `MIN_POOL_LIQUIDITY`, debits both amounts from
`tx.from`, credits both to the pool's reserves, and mints an
initial LP position to `tx.from` with `floor(sqrt(amount_a * amount_b))`
LP tokens.

### `AddLiquidity` (0x31)

```
token_id:  one side's token id (amount_a's token)
amount:    one side's amount
payload:
  [8]  pool_id (LE)
  [8]  amount_b (LE)
```

Debits both amounts from `tx.from`, credits both to the pool's
reserves, and mints LP tokens to `tx.from`'s existing position (or
creates a new one).

### `RemoveLiquidity` (0x32)

```
payload:
  [8]  position_id (LE)
  [8]  amount (LE)           — 0 = remove the whole position
```

Removes `amount` LP tokens' worth of reserves (or the whole
position if `amount == 0`), credits the pro-rata shares to
`tx.from`, and (if the pool is drained) deletes the pool.

### `Swap` (0x33)

```
token_id:  input token id
amount:    input amount
to:        recipient of the output
payload:
  [8]  pool_id (LE)
  [8]  min_amount_out (LE)
```

Computes `amount_out` from the constant-product formula, checks
that it's at least `min_amount_out`, debits the input from
`tx.from`, and credits the output to `tx.to`.

### `CreateOrder` (0x40)

```
token_id:  sell token id
amount:    sell amount
payload:
  [4]  buy_token (LE)
  [8]  min_buy_amount (LE)
  [1]  mode (0 = Passive, 1 = Active)
  [4]  pool_id (LE)         — 0 for Passive, non-zero for Active
  [8]  expires_at_height (LE)
  [1]  condition_count
  [N]  conditions (13 bytes each)
```

Takes the sell-token lock, persists the order record, and either
runs the matcher (Passive) or the router (Active, no conditions),
or leaves the order resting (Active with conditions).

### `CancelOrder` (0x41)

```
payload:
  [8]  order_id (LE)
```

Refunds the remaining lock minus `ORDER_CANCEL_FEE_ATOMIC`, removes
the order from every index, and deletes the record.

---

## RPC reference

### AMM

| Method | Params | Returns |
|---|---|---|
| `getPool` | `pool_id` | A pool object, or `PoolNotFound` |
| `getAllPools` | `limit`, `offset` | `{ pools, count, offset, limit }` |
| `getPoolsForToken` | `token_id` | `{ pools, count }` |
| `getPosition` | `position_id` | A position object, or `PoolNotFound` |
| `getPositionByOwner` | `address`, `pool_id` | A position object, or `PoolNotFound` |
| `getPositionsForPool` | `pool_id`, `limit`, `offset` | `{ positions, count, total }` |

### Order book

| Method | Params | Returns |
|---|---|---|
| `getOrder` | `order_id` | An order object, or `OrderNotFound` |
| `getAllOrders` | `limit`, `offset`, `include_filled` | `{ orders, count, ... }` |
| `getOrdersByPair` | `sell_token`, `buy_token`, `limit`, `offset` | `{ orders, count, ... }` |
| `getOrderBook` | `base_token`, `quote_token`, `depth` | `{ bids, asks, price_scale }` |
| `getOrderFills` | `order_id`, `limit` | `{ fills, count }` |
| `getPairTrades` | `base_token`, `quote_token`, `limit` | `{ trades, count }` |

**All numbers in responses are `"0x"`-prefixed hex strings.** The
`@claritychain/rpc` npm package provides a typed client that
handles this conversion internally; direct callers must parse
hex themselves.

### Encoder field notes

- `Pool.fee_bps` is a JSON number, not a hex string. It's the only
  numeric field in a pool that isn't hex-encoded.
- `Pool.k` is a 128-bit value, encoded as hex with no leading
  zeros.
- `Position.share_bps` is a JSON number computed from the pool's
  `total_liquidity`. It's omitted if the pool is unavailable.
- `OrderBook.bids` and `OrderBook.asks` are arrays of
  `{ price, total_base, order_count }`. `price` is in the canonical
  frame (`quote per base`), scaled by `BOOK_PRICE_SCALE`.

---

## Known limitations

These are behaviors that are correct but worth knowing. They are
design choices, not bugs.

**Volume is CLRTY-denominated.** `VolumeBelow` conditions are
meaningless for pools without a CLRTY side. A swap in a
token/token pool contributes zero to the pool's `volume_current`
and `volume_last` fields, because there is no oracle to convert
a token/token trade into CLRTY terms.

**No cross-mechanism routing.** A taker cannot fill a book order
against a pool atomically. The two mechanisms are separate
markets; a user picks one per order.

**LP tokens are not transferable.** Positions are tied to the
owning address. To change ownership, remove liquidity and re-add
from a different address. This is a v1 choice, not a permanent
one; a future `TransferLp` would introduce a shadow token for LP
positions the same way NFTs have shadow tokens.

**Fee is immutable per pool.** A pool's `fee_bps` cannot be
changed after creation. A creator who wants a different fee must
create a new pool. This is the Uniswap V2 model.

**The cancel fee is denominated in the order's sell token.** A
resting order that sells a non-native token pays its cancel fee
in that token, not in CLRTY. The fee is a single atomic unit, so
the denomination is a detail today; it would matter if the fee
were ever raised.

**Position records are not deleted on removal.** A fully-removed
position leaves a record in state with `liquidity = 0` and no
index entry. It is invisible to any indexed query, but it
occupies 64 bytes per position ever created. A future cleanup
pass would delete these; for now they are an accepted cost.

**No protocol fee.** All swap fees accrue to the pool's reserves
and are realized by LPs at removal time. There is no protocol
treasury take. A future fee split would be an additive change
to `executeSwap` and to the pool's `fee_bps` semantics.

**No pool deletion for drained-but-not-zero pools.** A pool whose
reserves reach exactly zero on both sides and whose `total_liquidity`
is zero is deleted. A pool that has somehow reached a non-zero
state with zero liquidity — which the current code paths cannot
produce, but which a future bug might — would remain in state
and be unusable. This is a defensive note, not an observed
behavior.

---

## Integration patterns

### Choosing a pool

A client that wants to swap token A for token B:

1. Call `getPoolsForToken(A)` and `getPoolsForToken(B)`, or
   `getAllPools` and filter.
2. For each pool that contains both A and B, get its reserves.
3. Compute the effective output for the desired input amount using
   the constant-product formula and the pool's fee.
4. Pick the pool with the best effective output.

A pool with only one of the two tokens is not usable for the swap.
A pool with zero reserves on one side is not usable.

### Computing a swap's output

Given a pool and an input amount, the output is:

```
fee_factor = 10000 - pool.fee_bps
in_with_fee = amount_in * fee_factor / 10000
out = pool.reserve_out * in_with_fee / (pool.reserve_in + in_with_fee)
```

`reserve_in` and `reserve_out` depend on which direction the swap
goes: if you're swapping `token_a` for `token_b`, then
`reserve_in = pool.reserve_a` and `reserve_out = pool.reserve_b`.
The reverse for the other direction.

The output is floored. Round down when computing an expected
output; round up when computing a minimum acceptable output (for
`min_amount_out`).

### Computing LP shares

Given a pool and the amounts you're adding:

```
share_a = amount_a * pool.total_liquidity / pool.reserve_a
share_b = amount_b * pool.total_liquidity / pool.reserve_b
minted = min(share_a, share_b)
```

To avoid donating to the pool, add amounts proportional to the
current reserves. The ratio `amount_a / amount_b` should equal
`pool.reserve_a / pool.reserve_b`, as closely as integer division
allows.

### Placing an order

A client that wants to place a limit order:

1. Decide Passive or Active.
2. For Passive: choose `sell_token`, `buy_token`, `sell_amount`,
   `min_buy_amount`, and optionally an expiry height.
3. For Active: additionally choose a `pool_id`, and decide whether
   to attach conditions (conditions delay execution to the epoch
   boundary).
4. Call `simulateTransaction` on the unsigned transaction to see
   the expected fills. This is the only way to know the fills
   before submitting, because the fills depend on the current
   book state.
5. Submit.

The `CreateOrder` receipt includes the fills. A client that submits
and waits for confirmation can read the fills from the receipt.

### Reading fills

Fills are available in three forms:

- **In the receipt** of a `CreateOrder` transaction, if the order
  crossed during creation.
- **Via `getOrderFills(order_id)`**, which returns all fills for a
  specific order (either as maker or taker).
- **Via `getPairTrades(base, quote)`**, which returns all fills
  for a pair.

The receipt form is the most direct, but it's only populated for
the taker. The RPC forms are indexed by order and by pair, so they
answer "what happened to this order" and "what happened on this
pair" respectively.