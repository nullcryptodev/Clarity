// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/Json.h"

#include "Core/Account.h"
#include "Core/AmmFarmTypes.h"
#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"
#include "Core/Block.h"
#include "Core/Order.h"
#include "Core/TokenTypes.h"
#include "Core/Receipt.h"
#include "Core/ValidatorTypes.h"
#include "Core/NftTypes.h"
#include "Core/BridgeTypes.h"

namespace Rpc
{
  //  Encoders
  //
  //  Convert Core types to Common::Json for RPC responses. These are
  //  presentation encoders, not wire codecs — they produce JSON with
  //  hex-formatted numbers and bech32m addresses, which is the format
  //  clients expect on the RPC surface.
  //
  //  All numbers on the wire are "0x"-prefixed hex strings, to avoid
  //  JS precision loss above 2^53. All addresses are bech32m with
  //  the caller-supplied HRP. All hashes and public keys are
  //  "0x"-prefixed hex. All signatures are "0x"-prefixed hex.
  //
  //  Fields marked "derived" are computed here from the struct plus
  //  (where noted) the current chain height. They are pure functions
  //  of the struct.

  //  Account -> JSON
  //
  //  Fields:
  //    nonce               (hex)
  //    balance             (hex)
  //    staked              (hex)
  //    pending_rewards     (hex)
  //    last_reward_epoch   (hex)
  //    staker_since_height (hex)
  //    created_at_height   (hex)
  //    staking_opted_out   (bool)
  //    is_empty            (bool; derived)
  //    total_value         (hex; balance + pending_rewards)
  Common::Json encodeAccount(const Core::Account &account);

  //  AmmPool -> JSON
  //
  //  Fields:
  //    id                (hex)
  //    creator           (Bech32m)
  //    token_a           (hex)
  //    token_b           (hex)
  //    reserve_a         (hex)
  //    reserve_b         (hex)
  //    total_liquidity   (hex)
  //    fee_bps           (number)
  //    created_at_height (hex)
  //    active            (bool)
  //    k                 (hex string; 128-bit; computed from reserves)
  //
  //  `k` is a 128-bit value (reserve_a * reserve_b). Encoded as a
  //  0x-prefixed hex string without leading zeros. It can exceed 2^53,
  //  so it cannot be a JSON number.
  //
  //  Note: previous versions of this encoder emitted approximate
  //  `price_a_per_b` and `price_b_per_a` fields as `double`-formatted
  //  strings. They were removed: a floating-point field in a chain
  //  where every other number is an exact hex string is more
  //  misleading than useful. Clients that need a price ratio can
  //  compute it from the reserves with whatever precision they want.
  Common::Json encodeAmmPool(const Core::AmmPool &pool, const std::string &hrp);

  //  AmmPosition -> JSON
  //
  //  Fields:
  //    id                (hex)
  //    owner             (Bech32m)
  //    pool_id           (hex)
  //    liquidity         (hex)
  //    created_at_height (hex)
  //    share_bps         (number; 0..10000; derived from pool if provided)
  //
  //  `share_bps` is the owner's share of the pool, in basis points.
  //  Computing it requires the pool's total_liquidity, so it is
  //  optional — if `pool` is null, `share_bps` is omitted.
  Common::Json encodeAmmPosition(const Core::AmmPosition &position,
                                 const Core::AmmPool *pool,
                                 const std::string &hrp);

  //  BlockHeader -> JSON
  //
  //  Fields:
  //    hash              (0x-prefixed; computed)
  //    version           (number)
  //    chain_id          (number, fits in uint32)
  //    height            (hex string)
  //    parent_hash       (0x-prefixed)
  //    timestamp_ms      (hex string)
  //    proposer          (Bech32m)
  //    epoch             (hex string)
  //    rotation_index    (hex string)
  //    commit_round      (hex string; NOT part of the hash)
  //    emergency_rotation (hex string; NOT part of the hash)
  //    state_root        (0x-prefixed)
  //    tx_root           (0x-prefixed)
  //    receipts_root     (0x-prefixed)
  //    validator_set_root(0x-prefixed)
  //    total_fees        (hex string)
  //    tx_count          (number)
  //    active_validator_count (number)
  Common::Json encodeBlockHeader(const Core::BlockHeader &header,
                                 const std::string &hrp);

  //  Block -> JSON
  //
  //  The header fields are encoded flat (not nested under a "header"
  //  key), because every client expects `block.height`, `block.hash`,
  //  etc. The transactions and participants are appended to the same
  //  object.
  //
  //  `include_transactions`:
  //    true  — block.transactions is an array of full tx objects
  //    false — block.transactions is an array of tx hashes
  //
  //  Additional fields beyond the header:
  //    transactions      (array; shape depends on include_transactions)
  //    participants      (array of hex-string validator ids)
  //    quorum_signatures (array of {signer_index, signature})
  Common::Json encodeBlock(const Core::Block &block,
                           bool include_transactions,
                           const std::string &hrp);

  //  Order -> JSON
  //
  //  Fields:
  //    id                    (hex)
  //    owner                 (Bech32m)
  //    mode                  (string: "passive" | "active")
  //    mode_code             (number)
  //    sell_token            (hex)
  //    buy_token             (hex)
  //    sell_amount           (hex)
  //    min_buy_amount        (hex)
  //    filled_amount         (hex)
  //    remaining_amount      (hex; derived)
  //    created_at_height     (hex)
  //    order_expires_at_height (hex)
  //    is_fully_filled       (bool; derived)
  //    condition_count       (number)
  //    conditions            (array of condition objects)
  //
  //  Condition objects:
  //    type                  (string)
  //    type_code             (number)
  //    param1                (hex)
  //    param2                (hex)
  //    description           (string; human-readable for common cases)
  Common::Json encodeOrder(const Core::Order &order, const std::string &hrp);

  //  TokenInfo -> JSON
  //
  //  Fields:
  //    id            (hex)
  //    name          (string)
  //    symbol        (string)
  //    decimals      (number)
  //    creator       (Bech32m; null for the native token)
  //    backing       (string: "unbacked" | "backed" | "hybrid")
  //    backing_code  (number)
  //    max_supply    (hex; 0 means unlimited)
  //    royalty_bps   (number)
  //    fingerprint   (0x-prefixed or null)
  //    is_native     (bool; derived)
  //    is_bridged    (bool; derived)
  //
  //  The `creator` field is null for the native token (id == 0).
  //  Bech32m cannot encode the null pubkey — encodeAddress returns
  //  an empty string for null addresses — so emit null rather than
  //  an empty string that a client might try to parse.
  Common::Json encodeToken(const Core::TokenInfo &token, const std::string &hrp);

  //  Transaction -> JSON
  //
  //  Fields:
  //    hash           (0x-prefixed; txid == signingHash)
  //    version        (number)
  //    chain_id       (hex string)
  //    type           (string name; "transfer", "swap", etc.)
  //    type_code      (number)
  //    nonce          (hex string)
  //    valid_until_height (hex string; 0 means "no expiry")
  //    from           (Bech32m)
  //    to             (Bech32m; may be null for txs that don't use it)
  //    token_id       (hex string)
  //    amount         (hex string)
  //    fee            (hex string)
  //    payload        (0x-prefixed hex)
  //    payload_size   (number; raw byte count)
  //    signature      (0x-prefixed hex)
  //
  //  `type_code` is included alongside the human-readable `type` so
  //  clients can switch on a stable numeric identifier without
  //  string-comparing. The two are always consistent.
  Common::Json encodeTransaction(const Core::Transaction &tx,
                                 const std::string &hrp);

  //  Receipt -> JSON
  //
  //  Fields:
  //    status      (string: "success" | "failure")
  //    status_code (number: 0 | 1)
  //    fee_paid    (hex string)
  Common::Json encodeReceipt(const Core::Receipt &r);

  //  ValidatorInfo -> JSON
  //
  //  Fields:
  //    id                    (hex)
  //    reward_address        (Bech32m)
  //    consensus_key         (0x-prefixed hex)
  //    node_key              (0x-prefixed hex)
  //    owner                 (Bech32m)
  //    registered_at_height  (hex)
  //    stake                 (hex)
  //    uptime_score          (number, bps)
  //    last_ping_height      (hex)
  //    last_seen_height      (hex)
  //    reward_multiplier     (number, bps)
  //    infraction_count      (number)
  //    last_infraction_height(hex)
  //    total_blocks_produced (hex)
  //    total_rewards_earned  (hex)
  //    epochs_active         (hex)
  //    is_seed               (bool)
  //    is_active             (bool)
  //    became_active_at      (hex)
  //    last_active_at        (hex)
  //    can_be_active         (bool; derived)
  //    meets_stake_req       (bool; derived)
  //    is_offline            (bool; derived; requires current height)
  //
  //  `consensus_key` is emitted as raw hex, not as a bech32m address.
  //  It is a signing key, not an address, and clients that distinguish
  //  the two must be able to tell them apart.
  //
  //  `current_height` is used for the derived `is_offline` field.
  Common::Json encodeValidator(const Core::ValidatorInfo &v,
                               uint64_t current_height,
                               const std::string &hrp);

  //  Validator list -> JSON array
  //
  //  Sorted by validator id for stable output. Clients can rely on
  //  the array order matching numeric id order.
  Common::Json encodeValidatorList(
      const std::vector<Core::ValidatorInfo> &validators,
      uint64_t current_height,
      const std::string &hrp);

  //  Fill -> JSON
  //
  //  Fields:
  //    maker_order_id      (hex)
  //    taker_order_id      (hex)
  //    base_token          (hex)
  //    quote_token         (hex)
  //    qty_base            (hex)
  //    qty_quote           (hex)
  //    price               (hex; canonical, quote per base, scaled
  //                         by OrderBook::BOOK_PRICE_SCALE)
  //    height              (hex; the block that produced the fill)
  //    tx_index_in_block   (number)
  //
  //  Height and tx_index are not fields of Fill; they are the
  //  identity of the transaction that produced the fill, passed
  //  alongside so the client can locate the receipt if it wants to.
  Common::Json encodeFill(const Core::Fill &fill,
                          uint64_t height,
                          uint32_t tx_index_in_block,
                          const std::string &hrp);

  Common::Json encodeNftInfo(const Core::NftInfo &nft,
                             const std::string &hrp);

  Common::Json encodeNftCollection(const Core::NftCollection &collection,
                                   const std::string &hrp);

  //  Bridge encoders. The JSON shape mirrors the C++ structs but
  //  follows the same conventions as the rest of the RPC surface:
  //  ids and amounts are 0x-prefixed hex strings, hashes are
  //  0x-prefixed 64-char hex, and addresses are bech32m for the
  //  node's network.
  Common::Json encodeBridgeChainRegistration(
      const Core::BridgeChainRegistration &reg,
      const std::string &hrp);

  //  BridgeWithdrawal -> JSON
  //
  //  Fields:
  //    withdrawal_id          (hex)
  //    source_chain_id        (hex)
  //    wrapped_token_id       (hex)
  //    burner                 (Bech32m)
  //    amount                 (hex)
  //    destination_blob       (0x-prefixed hex)
  //    destination_address    (string)
  //    created_at_height      (hex)
  //    well_formed            (bool; derived)
  //
  //  release audit fields:
  //    is_released              (bool; derived)
  //    release_tx_hash          (0x-prefixed hex; null if unreleased)
  //    release_height           (hex; 0 if unreleased)
  //    released_at_height       (hex; 0 if unreleased)
  //    released_by_validator_id (hex; 0 if unreleased)
  Common::Json encodeBridgeWithdrawal(
      const Core::BridgeWithdrawal &w,
      const std::string &hrp);

  //  BridgeAckAttestation -> JSON
  //
  //  Fields:
  //    signer_index        (number)
  //    signature           (0x-prefixed hex)
  //    attested_at_height  (hex)
  //
  //  The validator_id / withdrawal_id that key the record are NOT
  //  part of the encoded object: they are supplied by the caller
  //  (whoever enumerated the table) so the same encoder can be used
  //  whether the record is being returned from a per-withdrawal scan
  //  or a full-table dump.
  Common::Json encodeBridgeAckAttestation(
      const Core::BridgeAckAttestation &a);

  //  BridgeStats -> JSON
  //
  //  Fields:
  //    source_chain_id           (hex)
  //    total_minted              (hex)
  //    total_burned              (hex)
  //    total_released            (hex)
  //    deposit_count             (hex)
  //    withdrawal_count          (hex)
  //    released_withdrawal_count (hex)
  //    last_mint_height          (hex)
  //    last_burn_height          (hex)
  //    last_release_height       (hex)
  //    registered_at_height      (hex)
  //
  //  Derived:
  //    outstanding_liability     (hex; total_burned - total_released)
  //
  //  `outstanding_liability` is the amount of source-chain value the
  //  federation still owes to holders of the wrapped token. It is a
  //  pure function of the stored stats (total_burned minus
  //  total_released) and is included here so callers don't have to
  //  recompute the invariant themselves.
  Common::Json encodeBridgeStats(const Core::BridgeStats &stats);

  //  BridgeEvent -> JSON.
  //
  //  Fields:
  //    kind                  (string: "mint" | "burn" | "ack_attest" |
  //                           "ack_withdrawal")
  //    kind_code             (number)
  //    source_chain_id       (hex)
  //    block_height          (hex)
  //    tx_index_in_block     (number)
  //    tx_hash               (0x-prefixed hex)
  //    source_tx_hash        (0x-prefixed hex or null)
  //    source_output_index   (hex; 0 if has_source_hash is false)
  //    withdrawal_id         (hex)
  //    actor                 (Bech32m)
  //    amount                (hex)
  //    counterparty          (hex)
  Common::Json encodeBridgeEvent(const Core::BridgeEvent &evt,
                                 const std::string &hrp);

  //  AmmFarmSchedule -> JSON
  //
  //  Fields:
  //    pool_id                    (hex)
  //    creator                    (Bech32m)
  //    reward_token_id            (hex; 0 means CLRTY)
  //    reward_rate_per_epoch      (hex)
  //    reward_escrow_remaining    (hex; cache of the on-chain balance)
  //    reward_paused              (bool)
  //    rps_per_share              (hex; monotone accumulator)
  //    created_at_height          (hex)
  //
  //  Derived (require the pool and the escrow balance; passed in):
  //    reward_escrow_balance      (hex; authoritative on-chain balance
  //                                at Keys::ammFarmAddress(pool_id))
  //    pool_total_liquidity       (hex; 0 if the pool has been deleted)
  //    is_active                  (bool; farm.isActive())
  //    epochs_remaining           (hex; escrow_balance / rate, floored;
  //                                0 if rate == 0)
  //    escrow_address             (Bech32m; so a client can getBalance
  //                                against the custody address directly)
  //
  //  `escrow_balance` is passed in rather than read here so this
  //  encoder is a pure function of its arguments. It differs from
  //  `reward_escrow_remaining` only if the cache is stale, which
  //  should never happen on a healthy node but is worth surfacing.
  Common::Json encodeAmmFarm(const Core::AmmFarmSchedule &farm,
                             const Core::AmmPool *pool,
                             uint64_t escrow_balance,
                             const std::string &hrp);

  //  AmmPositionAccrual -> JSON
  //
  //  This encoder produces a *computed* accrual view, not just the
  //  stored companion record. It combines the farm, the position,
  //  and (optionally) the accrual companion into a single object:
  //
  //    pool_id                  (hex)
  //    position_id              (hex)
  //    position_liquidity       (hex)
  //    reward_token_id          (hex)
  //    exists                   (bool; true if the accrual companion
  //                              was present)
  //    last_rps                 (hex; 0 if `exists` is false)
  //    current_rps              (hex; farm.rps_per_share)
  //    accrued_unclaimed        (hex; (current - last) * liquidity /
  //                              FARM_RPS_SCALE; what a claim right
  //                              now would credit to pending_rewards)
  //    farm_paused              (bool)
  //
  //  `accrual` may be null. When it is, the encoder treats last_rps
  //  as 0, which is the correct semantic for a position that has
  //  never settled: the farm also started at rps_per_share = 0, so
  //  the position has been earning since the farm existed.
  Common::Json encodeAmmFarmAccrual(const Core::AmmFarmSchedule &farm,
                                    const Core::AmmPosition &position,
                                    const Core::AmmPositionAccrual *accrual,
                                    const std::string &hrp);
} // namespace Rpc