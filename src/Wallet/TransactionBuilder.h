// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "Core/Transaction.h"
#include "Core/AmmPool.h"
#include "Core/Order.h"
#include "Crypto/Types.h"
#include "GlobalConfig.h"
#include "HdPath.h"
#include "WalletError.h"

namespace Wallet
{
  class Signer;

  //  TransactionBuilder
  //
  //  Constructs Core::Transaction objects from typed parameters, and
  //  signs them. This is the layer between "the wallet knows the
  //  account address and has an unlocked signer" and "we have a
  //  serialized transaction to submit."
  //
  //  Design:
  //
  //    - Each build* function fills the transaction's fixed fields
  //      (version, chain_id, tx_type, nonce, fee, from, to) and the
  //      type-specific payload. It does NOT sign.
  //
  //    - signTransaction takes an unsigned transaction and a Signer,
  //      computes the signing hash, calls signAtPath, and copies the
  //      signature in. It's separated so callers can inspect or log
  //      the transaction before signing, and so a future hardware
  //      signer can be plugged in without changing the builders.
  //
  //    - Builders are pure functions: same inputs, same output. No
  //      global state, no clock reads, no chain queries. The chain_id
  //      and nonce are passed in by the caller, who is responsible
  //      for knowing them.
  //
  //  Amounts and fees are in atomic units. Callers that accept
  //  human-readable input should use Wallet::parseAmount() to convert
  //  before calling these functions.
  //
  //  Every builder returns std::nullopt on failure, populating
  //  error_out (if non-null) with a WalletError and a detail string.
  //  Failure modes are parameter validation (zero fee, null address,
  //  oversized payload) — never chain state (the builder doesn't
  //  know the chain).

  //  ---- Common parameters ----
  //
  //  The fields every user-submitted transaction shares. Bundling
  //  them keeps the per-type parameter structs small.

  struct TxCommonParams
  {
    uint64_t chain_id{0};
    uint64_t nonce{0};
    uint64_t fee{0};
    uint64_t valid_until_height{0}; // 0 = no expiry
  };

  //  ---- Transfer ----

  struct TransferParams
  {
    TxCommonParams common;
    Crypto::Address to{};
    Id token_id{NATIVE_TOKEN_ID}; // 0 = native CLRTY
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildTransfer(
      const Crypto::Address &from,
      const TransferParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Staking ----
  //
  //  Opt-in, opt-out, and claim-rewards share the same shape: an
  //  empty payload, no `to`, no `amount`. Only the tx_type differs.

  struct StakingParams
  {
    TxCommonParams common;
  };

  std::optional<Core::Transaction> buildOptInStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  std::optional<Core::Transaction> buildOptOutStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  std::optional<Core::Transaction> buildClaimRewards(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Register Validator ----
  //
  //  Payload is the validator's P2P node public key (32 bytes).
  //  The reward address is `from` — the account signing the
  //  registration becomes the validator's reward address.
  //
  //  The stake is `amount` in the transaction. It must be at least
  //  GlobalConfig::VALIDATOR_MIN_STAKE; the executor enforces this,
  //  but the builder checks it too so the caller gets an early error.

  struct RegisterValidatorParams
  {
    TxCommonParams common;
    Crypto::PublicKey node_key{};
    uint64_t stake{0};
  };

  std::optional<Core::Transaction> buildRegisterValidator(
      const Crypto::Address &from,
      const RegisterValidatorParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Unregister Validator ----
  //
  //  Empty payload. The executor looks up the validator by `from`.

  std::optional<Core::Transaction> buildUnregisterValidator(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Update Reward Address ----
  //
  //  Payload is the new reward address (32 bytes). The executor looks
  //  up the validator by `from` — the current reward address — and
  //  rewrites both `reward_address` and `owner` to the new value.
  //
  //  Note: after this transaction, the new address is the one that
  //  controls the validator. The old address can no longer update or
  //  unregister it. This is the current executor behavior and matches
  //  the model where reward_address == owner.

  struct UpdateRewardParams
  {
    TxCommonParams common;
    Crypto::Address new_reward_address{};
  };

  std::optional<Core::Transaction> buildUpdateRewardAddress(
      const Crypto::Address &from,
      const UpdateRewardParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Rotate Consensus Key ----
  //
  //  Payload is the new consensus key (32 bytes). The executor
  //  looks up the validator by `from` — the current owner — and
  //  rewrites consensus_key, appending the previous key to the
  //  validator's key history with the rotation height as the
  //  boundary.
  //
  //  The new key must differ from the current key; that check is
  //  in the executor, not the builder, because the builder doesn't
  //  have chain state.

  struct RotateConsensusParams
  {
    TxCommonParams common;
    Crypto::PublicKey new_consensus_key{};
  };

  std::optional<Core::Transaction> buildRotateConsensusKey(
      const Crypto::Address &from,
      const RotateConsensusParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Create Token ----
  //
  //  Creates a fungible token. The creator is the signer; only the
  //  creator can later mint, burn, or update metadata on this token.
  //
  //  `backing` selects the token's backing model:
  //    0 = unbacked (a free-standing token with no external claim)
  //    1 = bridged  (a token that represents an external asset,
  //                  identified by `fingerprint`)
  //
  //  `max_supply` is in atomic units and is a hard cap. Zero means
  //  no cap: the creator can mint without limit. The executor
  //  enforces the cap at mint time.
  //
  //  `royalty_bps` is a royalty hint in basis points (0-10000). The
  //  chain stores it and the RPC returns it; it is not enforced at
  //  the protocol level, the same as every other chain.
  //
  //  `fingerprint` is a 32-byte content hash, meaningful only for
  //  bridged tokens. It is optional for all tokens.

  struct CreateTokenParams
  {
    TxCommonParams common;
    std::string name;
    std::string symbol;
    uint8_t decimals{8};
    uint8_t backing{0};
    uint64_t max_supply{0};
    uint16_t royalty_bps{0};
    std::optional<Crypto::Hash> fingerprint;
  };

  std::optional<Core::Transaction> buildCreateToken(
      const Crypto::Address &from,
      const CreateTokenParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Mint Token ----
  //
  //  Mints units of an existing token. Only the token's creator can
  //  mint. The executor enforces the max-supply cap; the builder
  //  checks the parameters but not the supply (the builder has no
  //  chain state).
  //
  //  The amount goes in the transaction's `amount` field; the token
  //  id goes in `token_id`; the recipient goes in `to`.

  struct MintTokenParams
  {
    TxCommonParams common;
    Id token_id{0};
    Crypto::Address to{};
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildMintToken(
      const Crypto::Address &from,
      const MintTokenParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Burn Token ----
  //
  //  Burns units of a token the caller holds. The chain reduces the
  //  tracked supply by the same amount. Anyone can burn any token
  //  they hold; only tokens the caller holds can be burned, which
  //  the executor checks.

  struct BurnTokenParams
  {
    TxCommonParams common;
    Id token_id{0};
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildBurnToken(
      const Crypto::Address &from,
      const BurnTokenParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Update Token Meta ----
  //
  //  Changes a token's name, symbol, or royalty. Only the creator
  //  can call this. An empty field means "leave unchanged". The
  //  max-supply and decimals cannot be changed.
  //
  //  If all three fields are empty/default, the builder rejects the
  //  transaction: a no-op update is a user error and would burn a
  //  fee for nothing.

  struct UpdateTokenMetaParams
  {
    TxCommonParams common;
    Id token_id{0};
    std::string new_name;        // empty = no change
    std::string new_symbol;      // empty = no change
    uint16_t new_royalty_bps{0}; // 0 = no change
  };

  std::optional<Core::Transaction> buildUpdateTokenMeta(
      const Crypto::Address &from,
      const UpdateTokenMetaParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Create Collection ----
  //
  //  Creates a collection with an optional reward schedule. The
  //  reward escrow, if any, is funded from `from`'s balance of
  //  reward_token_id in the same transaction.
  //
  //  A collection with no reward schedule (reward_token_id == 0
  //  and reward_rate_per_epoch == 0) is a pure grouping: a name,
  //  a symbol, and an optional base URI.

  struct CreateNftCollectionParams
  {
    TxCommonParams common;

    std::string name;
    std::string symbol;
    std::string base_uri;

    //  Reward schedule. Zero reward_token_id means "no schedule";
    //  in that case reward_rate_per_epoch and escrow_amount must
    //  also be zero.
    Id reward_token_id{0};
    uint64_t reward_rate_per_epoch{0};
    uint64_t escrow_amount{0};
  };

  std::optional<Core::Transaction> buildCreateNftCollection(
      const Crypto::Address &from,
      const CreateNftCollectionParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Mint (standalone) ----
  //
  //  Mints one standalone NFT. The NFT is a shadow token with
  //  maxSupply = 1 and decimals = 0, plus an NftInfo record with
  //  the metadata.
  //
  //  collection_id == 0 means "no collection". A standalone NFT
  //  with no collection is the throwaway case: one record, one
  //  metadata blob, no grouping, no reward schedule.

  struct MintNftParams
  {
    TxCommonParams common;
    uint64_t collection_id{0};
    Crypto::Hash metadata_hash{};
    std::string metadata_uri;
  };

  std::optional<Core::Transaction> buildMintNft(
      const Crypto::Address &from,
      const MintNftParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Wrap ----
  //
  //  Mints a wrapped NFT. `wrapped_amount` of `underlying_token_id`
  //  is taken from `from` and locked at the NFT's virtual address.
  //  Transferring the NFT moves the whole lock; burning releases it.

  struct WrapNftParams
  {
    TxCommonParams common;
    Id underlying_token_id{0};
    uint64_t wrapped_amount{0};
    uint64_t collection_id{0};
    Crypto::Hash metadata_hash{};
    std::string metadata_uri;
  };

  std::optional<Core::Transaction> buildWrapNft(
      const Crypto::Address &from,
      const WrapNftParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Transfer ----

  struct TransferNftParams
  {
    TxCommonParams common;
    uint64_t nft_id{0};
    Crypto::Address new_owner{};
  };

  std::optional<Core::Transaction> buildTransferNft(
      const Crypto::Address &from,
      const TransferNftParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Burn ----

  struct BurnNftParams
  {
    TxCommonParams common;
    uint64_t nft_id{0};
  };

  std::optional<Core::Transaction> buildBurnNft(
      const Crypto::Address &from,
      const BurnNftParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Update Metadata ----
  //
  //  `freeze` is one-way. Once set, no further UpdateNftMetadata
  //  can touch this NFT. Burning and transferring are unaffected.

  struct UpdateNftMetadataParams
  {
    TxCommonParams common;
    uint64_t nft_id{0};
    Crypto::Hash metadata_hash{};
    std::string metadata_uri;
    bool freeze{false};
  };

  std::optional<Core::Transaction> buildUpdateNftMetadata(
      const Crypto::Address &from,
      const UpdateNftMetadataParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Top Up ----
  //
  //  Credits `amount` of `token_id` to the NFT's custody address.
  //  For a wrapped NFT, token_id must equal the NFT's underlying.
  //  For a standalone NFT, any token is accepted as a gift.

  struct TopUpNftParams
  {
    TxCommonParams common;
    uint64_t nft_id{0};
    Id token_id{0};
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildTopUpNft(
      const Crypto::Address &from,
      const TopUpNftParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Claim Reward ----
  //
  //  Settles every NFT reward the caller has accrued into the
  //  caller's pending_rewards, which ClaimRewards then moves to
  //  balance. Empty payload.

  struct ClaimNftRewardParams
  {
    TxCommonParams common;
  };

  std::optional<Core::Transaction> buildClaimNftReward(
      const Crypto::Address &from,
      const ClaimNftRewardParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Refill Collection Reward ----
  //
  //  Creator-only. Adds `amount` of the collection's reward token
  //  to the collection's escrow, un-pausing it if it was drained.

  struct RefillCollectionRewardParams
  {
    TxCommonParams common;
    uint64_t collection_id{0};
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildRefillCollectionReward(
      const Crypto::Address &from,
      const RefillCollectionRewardParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM: Create Pool ----
  //
  //  Creates a new constant-product pool. The transaction's
  //  `token_id` and `amount` carry one side of the initial
  //  deposit; the payload carries the other.
  //
  //  The pair is canonicalized by the executor: whichever of the
  //  two token ids is smaller becomes `token_a`, and the
  //  corresponding amount becomes `amount_a`. The user's debit is
  //  always the sum of the two amounts they specified, regardless
  //  of which side ends up as A.
  //
  //  `fee_bps` is per-pool and immutable after creation. It must be
  //  at most `AMM_MAX_FEE_BPS` (1000 = 10%). The default, if the
  //  caller leaves it at 0, is `AMM_DEFAULT_FEE_BPS` (30 = 0.3%).

  struct CreatePoolParams
  {
    TxCommonParams common;

    //  One side of the pair, in the transaction's fixed fields.
    Id token_a{0};
    uint64_t amount_a{0};

    //  The other side, written to the payload.
    Id token_b{0};
    uint64_t amount_b{0};

    uint16_t fee_bps{Core::AMM_DEFAULT_FEE_BPS};
  };

  std::optional<Core::Transaction> buildCreatePool(
      const Crypto::Address &from,
      const CreatePoolParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM: Add Liquidity ----
  //
  //  Adds liquidity to an existing pool. The transaction's
  //  `token_id` and `amount` carry one side; the payload carries
  //  the pool id and the other side's amount.
  //
  //  Which side goes in the fixed fields and which goes in the
  //  payload is a client choice: the executor checks both balances
  //  and computes the LP tokens minted from the pair, without
  //  caring which is "A" or "B".

  struct AddLiquidityParams
  {
    TxCommonParams common;

    uint64_t pool_id{0};

    Id token_in{0};
    uint64_t amount_in{0};

    uint64_t amount_other{0};
  };

  std::optional<Core::Transaction> buildAddLiquidity(
      const Crypto::Address &from,
      const AddLiquidityParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM: Remove Liquidity ----
  //
  //  Removes LP tokens from a position. `amount` is the number of
  //  LP tokens to remove; 0 means "remove the whole position". The
  //  executor enforces that `amount <= position.liquidity`.

  struct RemoveLiquidityParams
  {
    TxCommonParams common;
    uint64_t position_id{0};
    uint64_t amount{0}; // 0 = remove everything
  };

  std::optional<Core::Transaction> buildRemoveLiquidity(
      const Crypto::Address &from,
      const RemoveLiquidityParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM: Swap ----
  //
  //  Swaps `amount_in` of `token_in` for the other side of the
  //  pool, sending the output to `to`.
  //
  //  `min_amount_out` is slippage protection: if the computed
  //  output at execution time is less than this, the swap fails.
  //  A caller that wants no protection can pass 1 (or 0, but 1 is
  //  safer — the executor treats 0 as "no minimum" but a positive
  //  minimum is a stronger guarantee).

  struct SwapParams
  {
    TxCommonParams common;

    uint64_t pool_id{0};
    Id token_in{0};
    uint64_t amount_in{0};
    uint64_t min_amount_out{1};

    Crypto::Address to{};
  };

  std::optional<Core::Transaction> buildSwap(
      const Crypto::Address &from,
      const SwapParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Order Book: Create Order ----
  //
  //  Places a limit order. `mode` selects Passive (rest in the
  //  book) or Active (route against a pool). The `pool_id` is
  //  meaningful only for Active orders; the executor rejects a
  //  Passive order with a non-zero pool_id and an Active order with
  //  a zero pool_id.
  //
  //  `conditions` is optional. A Passive order with conditions is
  //  evaluated at the epoch boundary; an Active order with
  //  conditions is routed at the epoch boundary if the conditions
  //  hold, or cancelled if they don't. An Active order with no
  //  conditions routes immediately on creation.

  struct CreateOrderParams
  {
    TxCommonParams common;

    Id sell_token{0};
    Id buy_token{0};
    uint64_t sell_amount{0};
    uint64_t min_buy_amount{0};

    Core::OrderExecutionMode mode{Core::OrderExecutionMode::Passive};
    uint64_t pool_id{0}; // meaningful only for Active

    uint64_t expires_at_height{0};

    std::vector<Core::OrderCondition> conditions;
  };

  std::optional<Core::Transaction> buildCreateOrder(
      const Crypto::Address &from,
      const CreateOrderParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Order Book: Cancel Order ----
  //
  //  Cancels a resting or unfulfilled order. The remaining sell-
  //  token lock is refunded to the owner, minus the cancel fee.

  struct CancelOrderParams
  {
    TxCommonParams common;
    uint64_t order_id{0};
  };

  std::optional<Core::Transaction> buildCancelOrder(
      const Crypto::Address &from,
      const CancelOrderParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Sign ----

  //  Compute the transaction's signing hash, ask the signer to sign
  //  it at `path`, and write the signature into tx.signature.
  //
  //  Returns the signing hash on success — which equals the txid —
  //  so the caller can log it or use it to track the transaction.
  //
  //  Requires signer.isReady() to be true. Passes through the
  //  signer's error_out on failure.
  //
  //  Default path is the account-0 receive address at index 0, which
  //  is what the keystore's `address()` field corresponds to.
  std::optional<Crypto::Hash> signTransaction(
      Core::Transaction &tx,
      Signer &signer,
      const HdPath &path = clrtyPath(0, 0, 0),
      WalletStatus *error_out = nullptr);

} // namespace Wallet