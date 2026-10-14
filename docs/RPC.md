# RPC

How clients talk to a Clarity node over JSON-RPC.

This document is a reference for wallet implementers, exchange integrators, block explorers, and operators. It covers the transport, the encoding conventions, the authentication model, the error codes, and every method the dispatcher registers.

## Table of contents

- [Transport](#transport)
  - [HTTP server](#http-server)
  - [JSON-RPC 2.0](#json-rpc-20)
  - [Batches and notifications](#batches-and-notifications)
- [Encoding conventions](#encoding-conventions)
  - [Numbers](#numbers)
  - [Addresses](#addresses)
  - [Hashes and public keys](#hashes-and-public-keys)
  - [Signatures](#signatures)
  - [Booleans and nulls](#booleans-and-nulls)
- [Authentication](#authentication)
  - [Read methods](#read-methods)
  - [Admin methods](#admin-methods)
- [Rate limiting](#rate-limiting)
- [Errors](#errors)
  - [JSON-RPC standard codes](#json-rpc-standard-codes)
  - [Application codes](#application-codes)
  - [Error object shape](#error-object-shape)
- [Method reference](#method-reference)
  - [Chain](#chain)
  - [State](#state)
  - [Tokens](#tokens)
  - [Transactions](#transactions)
  - [Mempool](#mempool)
  - [Consensus](#consensus)
  - [AMM](#amm)
  - [Orders](#orders)
  - [NFTs](#nfts)
  - [Metrics](#metrics)
  - [Node](#node)
- [Common patterns](#common-patterns)
  - [Pagination](#pagination)
  - [Polling for confirmation](#polling-for-confirmation)
  - [Submitting a transaction](#submitting-a-transaction)
  - [Verifying a balance](#verifying-a-balance)

## Transport

### HTTP server

The RPC server is an HTTP/1.1 server that listens on a configurable address and port. The defaults are:

```
--rpc               enable the endpoint (off unless passed)
--rpc-bind <addr>   bind address (default: 127.0.0.1)
--rpc-port <port>   listen port (default: 9633)
--rpc-cors <origin> CORS origin (default: none)
```

The server accepts `POST` requests with a JSON body. It rejects `GET` (except on the metrics endpoint, which is a separate handler on a separate port — see [METRICS.md](METRICS.md)).

The bind address defaults to loopback. If the RPC is meant to be reachable from the public internet, either bind to `0.0.0.0` and configure authentication (see below), or put a reverse proxy in front.

`--rpc-cors` controls the `Access-Control-Allow-Origin` header. The default is no header; passing `*` allows any origin. This matters for browser clients: without it, a web wallet can't call the RPC endpoint directly.

The HTTP server has a separate worker pool for request handling, a per-source-IP rate limiter, and a socket timeout. The defaults are tuned for a local client; a public endpoint should raise the worker count and lower the rate limit.

### JSON-RPC 2.0

The dispatcher implements JSON-RPC 2.0. A single request looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "getBalance",
  "params": {
    "address": "rclrty1..."
  }
}
```

The `id` is echoed back in the response. The `params` field can be an object or omitted entirely.

A single response looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "rclrty1...",
    "token_id": "0x0",
    "balance": "0x2540be400"
  }
}
```

An error response looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "field 'address' must be a valid address",
    "data": {
      "name": "InvalidParams",
      "field": "address",
      "value": "not-an-address"
    }
  }
}
```

### Batches and notifications

Batches are supported. A client can send an array of requests and receive an array of responses:

```json
[
  { "jsonrpc": "2.0", "id": 1, "method": "blockNumber", "params": {} },
  { "jsonrpc": "2.0", "id": 2, "method": "chainId", "params": {} }
]
```

Notifications (requests without an `id`) are supported but their responses are not returned. They are useful for fire-and-forget calls where the client doesn't need the result, but the application-level methods here all produce results, so notifications are rarely useful in practice.

## Encoding conventions

### Numbers

Every multi-byte number on the wire is a `"0x"`-prefixed hex string, not a JSON number. The reason is JavaScript: a JSON parser following the JavaScript convention (which is most of them) parses numbers as IEEE-754 doubles, and any integer above 2^53 loses precision. Atomic token amounts routinely exceed that range; a balance of 10^18 atomic units is a common value.

The hex string is **not zero-padded**. `1` is `"0x1"`, not `"0x0000000000000001"`. The `0x` prefix is required; a bare decimal number is rejected.

On input, both hex strings and JSON numbers are accepted. A `"0x..."` string is parsed as hex; a JSON number is parsed as a decimal integer. A `"26"` string is parsed as decimal 26, not hex 26. This lets a client pass either form; the encoder always emits hex.

The following fields are encoded as hex strings:

- Balances, amounts, fees, reserves, liquidity.
- Block heights, transaction counts, timestamps.
- Nonces, validator ids, pool ids, position ids, order ids, token ids.
- Basis points (uptime score, royalty bps, etc.).

### Addresses

Addresses are **bech32m** strings with distinct HRPs per network:

| Network | HRP | Example |
| --- | --- | --- |
| Mainnet | `clrty` | `clrty1qp...` |
| Testnet | `tclrty` | `tclrty1qp...` |
| Regtest | `rclrty` | `rclrty1qp...` |

A bech32m address encodes the same 32-byte Ed25519 public key on all three networks; only the HRP differs. A mainnet address used on testnet is rejected with an error that names both HRPs, so a client that pastes the wrong address gets a clear diagnosis rather than a silent failure.

On **input**, both bech32m and raw hex are accepted. A 64-character hex string is decoded as a raw 32-byte address. This is the format that appears in `ValidatorInfo::consensus_key` and in genesis configs; accepting it on input means a client that has a raw key from one query can use it directly in another without round-tripping.

On **output**, addresses are always bech32m. The one exception is the `consensus_key` field of a validator object, which is emitted as raw hex — it's a signing key, not an address, and a client that can't tell the two apart can't tell which to use for a given operation.

A null address is emitted as `null`, not as an empty string. Bech32m cannot represent the zero pubkey, and an empty string invites clients to try to parse it.

### Hashes and public keys

32-byte hashes are emitted as `"0x"`-prefixed hex, **fixed width**. Every byte is emitted, including leading zeros. A block hash is always 66 characters (`0x` + 64 hex digits).

32-byte public keys are emitted the same way. This includes:

- `consensus_key` on validator objects.
- `node_key` on validator objects.
- The `pubkey` field in P2P peer info.
- The `ephemeral_pubkey` in the Auth message (not exposed via RPC).

### Signatures

64-byte Ed25519 signatures are emitted as `"0x"`-prefixed hex, fixed width. A signature is always 130 characters (`0x` + 128 hex digits).

Arbitrary-length byte vectors (payloads, proofs, encoded transactions) are emitted as `"0x"`-prefixed hex with no fixed width. An empty vector is `"0x"`.

### Booleans and nulls

Booleans are JSON booleans (`true` / `false`). Nulls are JSON nulls. Neither is hex-encoded.

## Authentication

### Read methods

Read methods are **unauthenticated**. Anyone with network access to the RPC endpoint can query balances, blocks, transactions, state roots, and proofs.

This is the same model as Bitcoin Core, geth, and most public full nodes. The endpoint is meant to be reachable; the reads are meant to be public. An operator who wants to restrict access should bind the endpoint to loopback or put a reverse proxy in front.

### Admin methods

A subset of methods require a bearer token in the `Authorization` header:

```
Authorization: Bearer <admin-token>
```

The token is configured with `--admin-token <token>`. The admin methods are:

- `shutdown` — stop the daemon.
- `setLogLevel` — change the runtime log level (currently a no-op that always errors).

An empty `--admin-token` disables admin methods entirely. Attempting to call an admin method when the token is empty returns `MethodNotFound`, which is the correct response: the method doesn't exist for this endpoint.

The token comparison is **constant-time**. A timing attack that measures how many characters of the token match does not work.

## Rate limiting

The RPC layer has a per-source-IP token bucket. The bucket is applied at accept time, before the request is dispatched to a worker. The defaults are:

```
--rpc-rate-burst <n>        tokens (default: depends on config)
--rpc-rate-per-second <n>   refill rate (default: depends on config)
```

Both set to zero disables the limiter.

A request that exceeds the bucket is rejected with HTTP 429 (`Too Many Requests`). The response body is a standard JSON-RPC error with code `RateLimited`.

## Errors

### JSON-RPC standard codes

The dispatcher returns the standard JSON-RPC codes for protocol-level errors:

| Code | Meaning | When |
| --- | --- | --- |
| `-32700` | Parse error | The request body is not valid JSON. |
| `-32600` | Invalid request | The JSON is valid but not a valid Request object (missing `jsonrpc`, wrong version, etc.). |
| `-32601` | Method not found | The method name doesn't match any registered handler. |
| `-32602` | Invalid params | The method exists but the parameters don't match its schema. |
| `-32603` | Internal error | The handler threw an unexpected exception. |
| `-32000` | Server error | The server is shutting down or otherwise unable to process the request. |

### Application codes

Above the standard codes, the dispatcher has a project-specific range:

| Code | Name | Meaning |
| --- | --- | --- |
| `1000` | `TxMalformed` | The transaction's bytes or structure are invalid. |
| `1001` | `TxTooLarge` | The transaction exceeds the size cap. |
| `1002` | `TxBadSignature` | The transaction's signature doesn't verify. |
| `1003` | `TxWrongChain` | The transaction's chain id doesn't match the node's. |
| `1004` | `TxExpired` | The transaction's `valid_until_height` has passed. |
| `1005` | `TxNonceTooLow` | The transaction's nonce is below the sender's current nonce. |
| `1006` | `TxNonceConflict` | A different transaction with the same `(sender, nonce)` is already in the mempool and this one doesn't beat it on tier or fee rate. |
| `1007` | `TxFeeTooLow` | The transaction's fee rate is below the mempool minimum. |
| `1008` | `TxFeeTooHigh` | The transaction's fee rate exceeds the mempool maximum. |
| `1009` | `TxInsufficientFunds` | The sender's balance doesn't cover the amount + fee. |
| `1010` | `TxPoolFull` | The mempool is full and this transaction doesn't evict a higher-priority entry. |
| `1011` | `TxSubmitInternal` | An unclassified failure during submission. |
| `1012` | `TxPrecondition` | The transaction is well-formed and correctly signed, but its type-specific preconditions cannot be satisfied at the current tip (minting a nonexistent token, exceeding a supply cap, etc.). |
| `1050` | `AccountNotFound` | The requested account does not exist. |
| `1051` | `TokenNotFound` | The requested token does not exist. |
| `1052` | `ValidatorNotFound` | The requested validator does not exist. |
| `1053` | `PoolNotFound` | The requested pool or position does not exist. |
| `1054` | `OrderNotFound` | The requested order does not exist. |
| `1055` | `ReceiptNotFound` | The requested transaction is not confirmed, or its receipt is missing. |
| `1056` | `StateReadInternal` | An internal error while reading state. |
| `1057` | `ProofVersionUnavailable` | The requested version is outside the retention window. |
| `1058` | `ProofNotAvailable` | The requested key is not present at the requested version. |
| `1059` | `NftNotFound` | The requested NFT does not exist. |
| `1060` | `NftCollectionNotFound` | The requested NFT collection does not exist. |
| `1100` | `BlockNotFound` | The requested block (by height or hash) does not exist. |
| `1101` | `TransactionNotFound` | The requested transaction is neither in the mempool nor confirmed. |
| `1102` | `HistoricalQueryNotSupported` | The requested historical query is not supported. |
| `1103` | `ChainReadInternal` | An internal error while reading the chain database. |
| `1150` | `ConsensusReadInternal` | An internal error while reading consensus state. |
| `1200` | `AmmPoolEmpty` | The pool has zero reserves on one side. |
| `1201` | `AmmSlippageTooHigh` | The computed output is below the requested minimum. |
| `1250` | `Unauthorized` | The admin token is missing or invalid. |
| `1251` | `RateLimited` | The request was rate-limited. |

### Error object shape

An error response has the shape:

```json
{
  "code": 1050,
  "message": "no account with this address",
  "data": {
    "name": "AccountNotFound",
    "address": "rclrty1..."
  }
}
```

The `code` is a machine-readable integer. The `message` is a short human-readable string suitable for a log. The `data` object carries structured detail: the `name` field is a stable string identifier for the code (matching the table above), and the other fields are method-specific.

A client should switch on `code`, not on `message`. The message text may change; the code is stable.

## Method reference

Every method is registered with the dispatcher by one of the `register*Methods` functions. The groups below match the registration structure.

All method names are case-sensitive. The dispatcher routes by exact match; there is no fuzzy matching or aliasing.

### Chain

#### `chainId`

Returns the chain id.

```json
{}
```

Result:

```json
{ "chain_id": "0x434c5254594d4149" }
```

#### `blockNumber`

Returns the current chain height.

```json
{}
```

Result:

```json
{ "height": "0x1a4" }
```

#### `getBlockByNumber`

Returns a block by height.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `height` | hex or number | yes | The block height. |
| `full` | boolean | no | If true, include full transactions. If false, transactions are hashes. Default: false. |

Result: a block object. See [Block object](#block-object) below.

Errors: `BlockNotFound`.

#### `getBlockByHash`

Returns a block by hash.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `hash` | hex | yes | The block hash. |
| `full` | boolean | no | Same as `getBlockByNumber`. |

Result: a block object.

Errors: `BlockNotFound`.

#### `getBlockHeaderByNumber`

Returns just the header of a block.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `height` | hex or number | yes | The block height. |

Result: a block header object (see below).

Errors: `BlockNotFound`.

#### `getRecentBlocks`

Returns the N most recent block headers.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Number of blocks. Default 10, max 100. |

Result:

```json
{
  "count": "0xa",
  "blocks": [ /* block headers, newest first */ ]
}
```

Errors: `InvalidParams` if `limit` is 0 or > 100.

#### `getStateRoot`

Returns the state root at a specific height.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `height` | hex or number | yes | The block height. |

Result:

```json
{
  "height": "0x1a4",
  "state_root": "0x..."
}
```

Errors: `BlockNotFound`.

#### `getBlocksRange`

Returns a range of block headers.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `start` | hex or number | yes | The starting height. |
| `count` | hex or number | no | Number of blocks. Default 50, max 100. |
| `order` | string | no | `"asc"` or `"desc"`. Default `"desc"`. |

Result: a `{count, start, order, blocks}` object.

Errors: `InvalidParams` for bad count or order.

#### `getBlocksByProducer`

Returns the most recent blocks produced by a given proposer address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The proposer's address. |
| `limit` | hex or number | no | Default 50, max 100. |

Result: a `{proposer, count, blocks}` object where each block is `{height, block_hash}`.

Errors: `InvalidParams`.

#### `getBlockStats`

Returns aggregate stats over a range of heights.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `from_height` | hex or number | yes | The starting height. |
| `to_height` | hex or number | yes | The ending height. |

Result:

```json
{
  "from_height": "0x0",
  "to_height": "0x100",
  "block_count": "0x101",
  "total_transactions": "0x5a0",
  "total_fees": "0x..."
}
```

Errors: `InvalidParams` if the range exceeds 10,000 blocks.

#### `getChainStats`

Returns global chain statistics.

Parameters: none.

Result:

```json
{
  "height": "0x1a4",
  "chain_id": "0x434c5254594d4149",
  "epoch": "0x7",
  "total_transactions": "0x1234",
  "total_fees_lifetime": "0x...",
  "total_supply": "0x...",
  "total_staked": "0x...",
  "staker_count": "0x3",
  "current_pot": "0x...",
  "unique_addresses": "0x64",
  "unique_tokens": "0x5",
  "unique_validators": "0x2",
  "unique_pools": "0x1",
  "genesis_timestamp_ms": "0x..."
}
```

#### `getEpochInfo`

Returns the current epoch, its boundaries, and the number of blocks until the next epoch.

Parameters: none.

Result:

```json
{
  "epoch": "0x7",
  "epoch_start_height": "0x1a4",
  "next_epoch_height": "0x1e0",
  "current_height": "0x1a5",
  "blocks_until_next_epoch": "0x3b",
  "rotation_interval": "0x3c"
}
```

#### `getEpochSchedule`

Returns the epoch schedule constants.

Parameters: none.

Result:

```json
{
  "rotation_interval": "0x3c",
  "unbonding_period": "0x78",
  "emergency_rotation_rounds": "0x1e",
  "active_set_min": "0xb",
  "active_set_max": "0x64",
  "current_epoch": "0x7",
  "epoch_start_height": "0x1a4"
}
```

### State

#### `getBalance`

Returns an account's balance of a token.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |
| `token_id` | hex or number | no | Default: native CLRTY (id 0). |

Result:

```json
{
  "address": "rclrty1...",
  "token_id": "0x0",
  "balance": "0x..."
}
```

Errors: `InvalidParams`.

#### `getAccount`

Returns an account record.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |

Result: an account object (see below).

Errors: `InvalidParams`.

#### `getNonce`

Returns an account's current nonce.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |

Result:

```json
{
  "address": "rclrty1...",
  "nonce": "0x5"
}
```

#### `getProof`

Returns a Merkle proof for a state key at a version.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `key_type` | hex or number | yes | 0 = Account, 1 = TokenBalance, 2 = Validator, 3 = Global, 4 = AmmPool. |
| `key_bytes` | hex | yes | The key descriptor, layout per `key_type`. |
| `version` | string | no | A hex version or `"current"`. Default: `"current"`. |

Result on success:

```json
{
  "status": "ok",
  "state_root": "0x...",
  "version": "0x1a4",
  "proof": "0x..."
}
```

Errors: `ProofVersionUnavailable`, `ProofNotAvailable`, `InvalidParams`.

#### `getTokensForAddress`

Returns every token balance held by an address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |

Result: a `{address, count, tokens: [{token_id, balance}]}` object.

#### `getPositionsForAddress`

Returns every AMM position owned by an address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |

Result: a `{address, count, positions}` object.

#### `getOrdersForAddress`

Returns every order owned by an address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |
| `include_filled` | boolean | no | Default false. |

Result: a `{address, count, orders}` object.

#### `getTransactionsForAddress`

Returns the most recent transactions involving an address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |
| `limit` | hex or number | no | Default 50, max 100. |

Result: a `{address, count, transactions}` object where each transaction carries `tx`, `block_hash`, `block_height`, and `index`.

#### `getStakingInfo`

Returns the current staking state.

Parameters: none.

Result:

```json
{
  "last_effective_apy_bps": "0x...",
  "base_bps": "0x...",
  "activity_bonus_bps": "0x...",
  "pot_bonus_bps": "0x...",
  "total_staked": "0x...",
  "staker_count": "0x3",
  "current_pot": "0x...",
  "activity_txs_in_window": "0x...",
  "avg_tx_per_block": "0x...",
  "epoch": "0x7",
  "epoch_start_height": "0x1a4",
  "next_epoch_height": "0x1e0",
  "blocks_until_next_epoch": "0x3b"
}
```

#### `getAddressStats`

Returns per-address aggregate statistics.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The account. |

Result: an object with `balance`, `nonce`, `staked`, `pending_rewards`, `staking_opted_out`, `token_count`, `position_count`, `order_count`, `is_validator`, `validator_id`.

#### `getAddressList`

Returns a paginated list of accounts.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 50, max 100. |
| `offset` | hex or number | no | Default 0. |

Result: a `{count, offset, limit, addresses}` object.

### Tokens

#### `getTokenInfo`

Returns a token's metadata.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `token_id` | hex or number | yes | The token id. |

Result: a token object.

Errors: `TokenNotFound`.

#### `getTokenSupply`

Returns a token's current supply.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `token_id` | hex or number | yes | The token id. |

Result:

```json
{
  "token_id": "0x5",
  "supply": "0x..."
}
```

#### `getAllTokens`

Returns a paginated list of tokens.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: a `{count, offset, limit, tokens}` object.

#### `getTokenHolders`

Returns the top holders of a token, sorted by balance descending.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `token_id` | hex or number | yes | The token id. |
| `limit` | hex or number | no | Default 50, max 100. |

Result: a `{token_id, count, total_holders, holders}` object where each holder is `{address, balance}`.

#### `getTokenTransfers`

Returns the most recent transactions touching a token.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `token_id` | hex or number | yes | The token id. |
| `limit` | hex or number | no | Default 50, max 100. |

Result: a `{token_id, count, transfers}` object.

#### `getTokensByCreator`

Returns every token created by an address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The creator. |
| `limit` | hex or number | no | Default 50, max 500. |

Result: a `{creator, count, tokens}` object.

### Transactions

#### `sendRawTransaction`

Submits a signed transaction to the mempool.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `tx` | hex | yes | The serialized transaction, `0x`-prefixed. |

Result on success:

```json
{
  "tx_hash": "0x...",
  "accepted": true
}
```

Errors: any of the `Tx*` codes.

#### `getTransactionByHash`

Returns a transaction by hash. Checks the mempool first, then the chain.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `hash` | hex | yes | The transaction hash (txid). |

Result:

```json
{
  "tx": { /* transaction object */ },
  "status": "confirmed" | "pending",
  "block_hash": "0x..." | null,
  "block_height": "0x..." | null,
  "index": "0x..." | null
}
```

Errors: `TransactionNotFound`.

#### `getTransactionReceipt`

Returns a transaction's receipt.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `hash` | hex | yes | The transaction hash. |

Result: a receipt object with `status`, `status_code`, `fee_paid`, `fills`, plus `tx_hash`, `block_hash`, `block_height`, `index`.

Errors: `ReceiptNotFound`.

#### `simulateTransaction`

Runs a transaction against a hypothetical state at the current tip, without submitting it.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `tx` | hex | yes | The serialized transaction. |

Result: a receipt object. The simulation does not persist state; a second call with the same inputs produces the same result.

Errors: same as `sendRawTransaction`.

#### `getRecentTransactions`

Returns the most recent transactions in the chain.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 10, max 100. |
| `type_code` | hex or number | no | Filter to a specific `TxType`. |

Result: a `{count, transactions}` object.

#### `getAllTransactions`

Alias for `getRecentTransactions` with a default limit of 50.

#### `getTransactionsByType`

Alias for `getRecentTransactions` with a required `type_code`.

#### `getTxCount`

Returns the lifetime transaction count.

Parameters: none.

Result:

```json
{
  "total_transactions": "0x...",
  "epoch_transactions": "0x...",
  "current_epoch": "0x7"
}
```

### Mempool

#### `getMempoolStats`

Returns aggregate mempool statistics.

Parameters: none.

Result:

```json
{
  "total_txs": "0x5",
  "priority_txs": "0x1",
  "standard_txs": "0x4",
  "total_bytes": "0x...",
  "min_fee_rate": "0x...",
  "max_fee_rate": "0x...",
  "avg_fee_rate": "0x..."
}
```

#### `getMempoolTx`

Returns a single mempool transaction.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `hash` | hex | yes | The transaction hash. |

Result: the transaction object, or `null` if not in the mempool.

#### `getMempoolList`

Returns a paginated list of mempool transactions.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 50, max 500. |
| `order_by` | string | no | `"fee"` (descending) or `"time"` (newest first). Default `"fee"`. |

Result: a `{count, total, order_by, transactions}` object where each transaction carries `tx`, `fee_rate`, `added_ms`, `size`, `tier`.

### Consensus

#### `getValidators`

Returns a paginated list of validators.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `active_only` | boolean | no | Default false. |
| `limit` | hex or number | no | Default 50, max 1000. |
| `offset` | hex or number | no | Default 0. |

Result: a `{validators, count, total}` object.

#### `getValidator`

Returns a single validator by id.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | hex or number | yes | The validator id. |

Result: a validator object.

Errors: `ValidatorNotFound`.

#### `getValidatorByAddress`

Returns the validator whose reward address is the given address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The reward address. |

Result: a validator object.

Errors: `ValidatorNotFound`.

#### `getValidatorStats`

Returns a validator object plus its recent blocks.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | hex or number | yes | The validator id. |

Result: a validator object with an additional `recent_blocks` field.

#### `getActiveSet`

Returns the current active set.

Parameters: none.

Result:

```json
{
  "ids": [ "0x1", "0x2" ],
  "size": "0x2",
  "quorum": "0x2"
}
```

#### `getConsensusState`

Returns the current consensus engine state.

Parameters: none.

Result:

```json
{
  "height": "0x1a4",
  "round": "0x0",
  "step": "Commit",
  "is_validator": true,
  "validator_id": "0x1",
  "chain_height": "0x1a4",
  "best_peer_height": "0x1a4"
}
```

### AMM

#### `getPool`

Returns a single pool.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `pool_id` | hex or number | yes | The pool id. |

Result: a pool object.

Errors: `PoolNotFound`.

#### `getPosition`

Returns a single LP position.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `position_id` | hex or number | yes | The position id. |

Result: a position object.

Errors: `PoolNotFound`.

#### `getPositionByOwner`

Returns the position for a `(owner, pool_id)` pair.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The LP's address. |
| `pool_id` | hex or number | yes | The pool id. |

Result: a position object.

Errors: `PoolNotFound`.

#### `getAllPools`

Returns a paginated list of pools.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: a `{count, offset, limit, pools}` object.

#### `getPoolsForToken`

Returns every pool containing a given token.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `token_id` | hex or number | yes | The token id. |

Result: a `{count, pools}` object.

#### `getPositionsForPool`

Returns the top LP positions in a pool, sorted by liquidity descending.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `pool_id` | hex or number | yes | The pool id. |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: a `{pool_id, count, total, positions}` object.

### Orders

#### `getOrder`

Returns a single order.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `order_id` | hex or number | yes | The order id. |

Result: an order object.

Errors: `OrderNotFound`.

#### `getOrdersExpiringAt`

Returns the order ids expiring at a given height.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `height` | hex or number | yes | The expiry height. |

Result: a `{height, count, order_ids}` object.

#### `getAllOrders`

Returns a paginated list of orders.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |
| `include_filled` | boolean | no | Default false. |

Result: a `{count, offset, limit, orders}` object.

#### `getOrdersByPair`

Returns orders for a specific `(sell_token, buy_token)` pair.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `sell_token` | hex or number | yes | The sell token. |
| `buy_token` | hex or number | yes | The buy token. |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: a `{sell_token, buy_token, count, offset, limit, orders}` object.

#### `getOrderBook`

Returns the aggregated bids and asks for a pair, best-first.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `base_token` | hex or number | yes | The base token. |
| `quote_token` | hex or number | yes | The quote token. |
| `depth` | hex or number | no | Number of levels. Default 20, max 100. |

Result:

```json
{
  "base_token": "0x0",
  "quote_token": "0x5",
  "price_scale": "0x2540be400",
  "bids": [ { "price": "0x...", "total_base": "0x...", "order_count": "0x..." } ],
  "asks": [ { "price": "0x...", "total_base": "0x...", "order_count": "0x..." } ]
}
```

The `price` is in the canonical frame (`quote per base`), scaled by `BOOK_PRICE_SCALE = 10^10`.

#### `getOrderFills`

Returns the most recent fills for an order (either side).

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `order_id` | hex or number | yes | The order id. |
| `limit` | hex or number | no | Default 100, max 500. |

Result: an `{order_id, count, fills}` object.

#### `getPairTrades`

Returns the most recent fills for a pair.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `base_token` | hex or number | yes | The base token. |
| `quote_token` | hex or number | yes | The quote token. |
| `limit` | hex or number | no | Default 100, max 500. |

Result: a `{base_token, quote_token, count, trades}` object.

### NFTs

#### `getNft`

Returns a single NFT.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `nft_id` | hex or number | yes | The NFT id. |

Result: an NFT object. If the NFT is wrapped, the result carries a `custody_address` field.

Errors: `NftNotFound`.

#### `getNftsForOwner`

Returns a paginated list of NFTs held by an address.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | bech32m or hex | yes | The owner. |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: an `{address, count, offset, limit, nfts}` object.

#### `getNftsForCollection`

Returns a paginated list of NFTs in a collection.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `collection_id` | hex or number | yes | The collection id. |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: a `{collection_id, count, offset, limit, nfts}` object.

Errors: `NftCollectionNotFound` if the collection does not exist.

#### `getCollection`

Returns a single collection.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `collection_id` | hex or number | yes | The collection id. |

Result: a collection object. If the collection has a reward schedule, the result carries an `escrow_address` field.

Errors: `NftCollectionNotFound`.

#### `getAllCollections`

Returns a paginated list of collections.

Parameters:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | hex or number | no | Default 50, max 500. |
| `offset` | hex or number | no | Default 0. |

Result: a `{count, offset, limit, collections}` object.

### Metrics

#### `getFeeStats`

Returns aggregate fee statistics.

Parameters: none.

Result: an object with `total_fees_lifetime`, `fees_last_epoch`, `fees_last_24h`, `avg_fee_per_block`, `avg_fee_per_transaction`, `total_transactions`.

#### `getPotInfo`

Returns the current reward pot state.

Parameters: none.

Result: an object with `current_pot`, `pot_high_threshold`, `pot_fill_bps_of_high`, `total_to_pot`, `total_pot_distributed`, `last_effective_apy_bps`, `epoch`, `epoch_start_height`, `next_epoch_height`, `blocks_until_payout`.

### Node

#### `ping`

Returns `"pong"`.

#### `status`

Returns the node's aggregate status.

Parameters: none.

Result: an object with `height`, `best_peer_height`, `peer_count`, `mempool_size`, `mempool_bytes`, `is_validator`, `validator_id`, `consensus_height`, `consensus_round`, `consensus_step`, `network`, `chain_id`, `running`, `state_root`.

#### `health`

Returns a minimal health object.

Parameters: none.

Result:

```json
{
  "ok": true,
  "height": "0x1a4",
  "peers": "0x1",
  "is_validator": true
}
```

#### `getPeers`

Returns the list of connected peers.

Parameters: none.

Result: a `{count, peers}` object where each peer is `{id, ip, port, direction, state, best_height, agent, connected_at_ms, last_recv_ms, last_send_ms, misbehaviors}`.

#### `getConfig`

Returns the node's RPC configuration.

Parameters: none.

Result: an object with the RPC config fields (`enabled`, `bind_address`, `port`, `worker_threads`, `max_queued_connections`, `max_request_bytes`, `socket_timeout_seconds`, `rate_limit_burst`, `rate_limit_per_second`, `admin_enabled`, `verbose_errors`).

#### `getMethods`

Returns the method catalogue, grouped by category.

Parameters: none.

Result: an object where each key is a group name (`chain`, `state`, `tokens`, `transactions`, `mempool`, `consensus`, `amm`, `orders`, `nfts`, `metrics`, `node`) and each value is an array of method names.

#### `web3_clientVersion`

Returns the client version string.

#### `net_version`

Returns the chain id as a decimal string.

#### `net_peerCount`

Returns the peer count as a hex string.

#### `net_listening`

Returns `true` if there is at least one peer, `false` otherwise.

### Admin

The following methods require the admin bearer token.

#### `shutdown`

Stops the daemon. Returns `{"shutting_down": true}`. The stop is scheduled 100 ms in the future so the response can be sent before the process exits.

Errors: `Unauthorized` if the token is missing or invalid; `MethodNotFound` if no admin token is configured.

#### `setLogLevel`

Changes the runtime log level.

**Note**: this method currently always throws `InternalError` with the message "runtime log level changes are not yet supported". It exists as a placeholder for a future implementation.

## Common patterns

### Pagination

Methods that return lists accept `limit` and `offset` parameters. The result carries `count` (the number of items actually returned), `offset`, and `limit` (the requested values). To page through a large set:

```
GET list with limit=100, offset=0
GET list with limit=100, offset=100
GET list with limit=100, offset=200
... until count < limit
```

The pagination is **by offset**, not by cursor. This means a concurrent mutation of the underlying set can cause a client to see an item twice or miss one. For a chain's chain data this is rarely an issue (blocks are appended, not removed), but for mempool or order lists, it can be.

### Polling for confirmation

To wait for a transaction to confirm:

```json
// Loop:
{
  "method": "getTransactionByHash",
  "params": { "hash": "0x..." }
}
// Until the response has "status": "confirmed"
```

The `getTransactionByHash` method returns `status: "pending"` while the transaction is in the mempool, and `status: "confirmed"` (with a `block_hash` and `block_height`) once it's included in a block. Since Clarity commits blocks with immediate finality, a single confirmed observation is enough — there's no "wait for N confirmations".

If the transaction is dropped from the mempool (expired, or replaced by a higher-fee transaction with the same nonce), the method returns `TransactionNotFound`.

### Submitting a transaction

The standard client flow:

1. **Build an unsigned transaction.** Use the wallet's `TransactionBuilder` or a hand-written serialization.
2. **Sign it.** Compute the signing hash (`Blake2b` of the serialization without the signature), sign with the sender's Ed25519 key, and append the signature.
3. **Serialize the signed transaction** (with signature).
4. **Submit via `sendRawTransaction`.**
5. **Poll via `getTransactionByHash`** until confirmed.

If the submission fails, the response's `error.code` identifies the reason. Common codes:

- `1005` (`TxNonceTooLow`): the sender's nonce has already been consumed. Fetch the current nonce with `getNonce` and rebuild.
- `1006` (`TxNonceConflict`): a different transaction with the same `(sender, nonce)` is in the mempool. Increase the fee, or wait for the existing transaction to confirm or expire.
- `1009` (`TxInsufficientFunds`): the sender doesn't have enough balance. Check with `getBalance`.
- `1012` (`TxPrecondition`): the transaction's type-specific preconditions fail. Check with the relevant `get*` method.

### Verifying a balance

To verify a balance without trusting the RPC endpoint:

1. **Fetch the state root** with `getStateRoot` at the current height (or with `status`).
2. **Request a proof** with `getProof` for the `(Account, address)` or `(TokenBalance, address || token_id)` descriptor at `"current"`.
3. **Verify the proof locally** with the same `State::verifyProof` function the node uses. If the proof verifies against the root, the balance is real.

To verify against a second endpoint, connect to two RPC endpoints and require both to return the same root before accepting either. The wallet's `connect-peer` command is this pattern.

## Block object

A block object (returned by `getBlockByNumber`, `getBlockByHash`, `getRecentBlocks`, etc.) has the following shape:

```json
{
  "hash": "0x...",
  "version": "0x1",
  "chain_id": "0x...",
  "height": "0x1a4",
  "parent_hash": "0x...",
  "timestamp_ms": "0x...",
  "proposer": "rclrty1...",
  "epoch": "0x7",
  "rotation_index": "0x0",
  "commit_round": "0x0",
  "emergency_rotation": "0x0",
  "state_root": "0x...",
  "tx_root": "0x...",
  "receipts_root": "0x...",
  "validator_set_root": "0x...",
  "total_fees": "0x...",
  "tx_count": "0x2",
  "active_validator_count": "0x2",
  "transactions": [ /* tx objects or hashes */ ],
  "participants": [ "0x1", "0x2" ],
  "quorum_signatures": [
    { "signer_index": 0, "signature": "0x..." }
  ]
}
```

The header fields are encoded flat, not nested under a `header` key. This matches every block-explorer convention.

## Account object

```json
{
  "nonce": "0x5",
  "balance": "0x...",
  "staked": "0x...",
  "pending_rewards": "0x...",
  "last_reward_epoch": "0x7",
  "staker_since_height": "0x12c",
  "created_at_height": "0x0",
  "staking_opted_out": false,
  "is_empty": false,
  "total_value": "0x..."
}
```

## Token object

```json
{
  "id": "0x5",
  "name": "Gold",
  "symbol": "GLD",
  "decimals": 8,
  "creator": "rclrty1..." | null,
  "backing": "unbacked",
  "backing_code": 0,
  "max_supply": "0x...",
  "royalty_bps": 50,
  "fingerprint": "0x..." | null,
  "is_native": false,
  "is_bridged": false
}
```

The `creator` is `null` for the native token (id 0). The `fingerprint` is `null` unless the token declares one.

## Validator object

```json
{
  "id": "0x1",
  "reward_address": "rclrty1...",
  "consensus_key": "0x...",
  "node_key": "0x...",
  "owner": "rclrty1...",
  "registered_at_height": "0x0",
  "stake": "0x...",
  "uptime_score": 10000,
  "last_ping_height": "0x...",
  "last_seen_height": "0x...",
  "reward_multiplier": 10000,
  "infraction_count": 0,
  "last_infraction_height": "0x0",
  "total_blocks_produced": "0x...",
  "total_rewards_earned": "0x...",
  "epochs_active": "0x...",
  "is_seed": false,
  "is_active": true,
  "became_active_at": "0x0",
  "last_active_at": "0x0",
  "can_be_active": true,
  "meets_stake_req": true,
  "is_offline": false
}
```

The `consensus_key` and `node_key` fields are raw `0x`-prefixed hex, not bech32m. They are signing keys, not addresses. The `is_offline` field is computed against the node's current height at the time of the query.

## Order object

```json
{
  "id": "0x7",
  "owner": "rclrty1...",
  "mode": "passive",
  "mode_code": 0,
  "pool_id": "0x0",
  "sell_token": "0x0",
  "buy_token": "0x5",
  "sell_amount": "0x...",
  "min_buy_amount": "0x...",
  "filled_amount": "0x...",
  "remaining_amount": "0x...",
  "created_at_height": "0x1a4",
  "order_expires_at_height": "0x0",
  "is_fully_filled": false,
  "condition_count": 0,
  "conditions": []
}
```

Each condition in the `conditions` array is:

```json
{
  "type": "price_below",
  "type_code": 3,
  "param1": "0x...",
  "param2": "0x...",
  "description": "cancels if price below 0x..."
}
```

## Pool object

```json
{
  "id": "0x1",
  "creator": "rclrty1...",
  "token_a": "0x0",
  "token_b": "0x5",
  "reserve_a": "0x...",
  "reserve_b": "0x...",
  "total_liquidity": "0x...",
  "fee_bps": 30,
  "created_at_height": "0x1a4",
  "active": true,
  "k": "0x..."
}
```

The `k` field is `reserve_a * reserve_b` as a 128-bit hex string. It's the invariant the pool maintains (modulo fees).

## Position object

```json
{
  "id": "0x3",
  "owner": "rclrty1...",
  "pool_id": "0x1",
  "liquidity": "0x...",
  "created_at_height": "0x1a4",
  "share_bps": 10000
}
```

The `share_bps` field is present only when the pool is known; it's the LP's share of the pool in basis points.

## Fill object

```json
{
  "source": "limit",
  "source_code": 0,
  "maker_order_id": "0x7",
  "taker_order_id": "0x8",
  "pool_id": "0x0",
  "base_token": "0x0",
  "quote_token": "0x5",
  "qty_base": "0x...",
  "qty_quote": "0x...",
  "price": "0x...",
  "height": "0x1a4",
  "tx_index_in_block": 0
}
```

For an AMM fill, `source` is `"amm"`, `maker_order_id` is `"0x0"`, and `pool_id` is set.

## Receipt object

```json
{
  "status": "success",
  "status_code": 0,
  "fee_paid": "0x...",
  "fills": [ /* fill objects */ ]
}
```

A receipt returned by `getTransactionReceipt` also carries `tx_hash`, `block_hash`, `block_height`, and `index`.

## NFT object

```json
{
  "id": "0x2a",
  "owner": "rclrty1...",
  "creator": "rclrty1...",
  "shadow_token_id": "0x2a",
  "underlying_token_id": "0x5",
  "wrapped_amount": "0x...",
  "collection_id": "0x1",
  "metadata_hash": "0x..." | null,
  "metadata_uri": "ipfs://...",
  "frozen": false,
  "last_accrual_height": "0x1a4",
  "accrued_owed": "0x0",
  "created_at_height": "0x1a4",
  "custody_address": "rclrty1..."
}
```

The `custody_address` is present only for wrapped NFTs.

## Collection object

```json
{
  "id": "0x1",
  "creator": "rclrty1...",
  "name": "Gold Cards",
  "symbol": "GCARD",
  "base_uri": "ipfs://...",
  "reward_token_id": "0x5",
  "reward_rate_per_epoch": "0x...",
  "reward_escrow_remaining": "0x...",
  "reward_paused": false,
  "created_at_height": "0x1a4",
  "minted_count": "0x3",
  "escrow_address": "rclrty1..."
}
```

The `escrow_address` is present only for collections with a reward schedule.

## Transaction object

```json
{
  "hash": "0x...",
  "version": "0x1",
  "chain_id": "0x...",
  "type": "transfer",
  "type_code": 0,
  "nonce": "0x5",
  "valid_until_height": "0x0",
  "from": "rclrty1...",
  "to": "rclrty1..." | null,
  "token_id": "0x0",
  "amount": "0x...",
  "fee": "0x...",
  "payload": "0x...",
  "payload_size": 0,
  "signature": "0x..."
}
```

The `to` field is `null` for transaction types that don't use it (opt-in-staking, claim-rewards, etc.).