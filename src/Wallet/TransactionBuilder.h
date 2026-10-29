// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
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

  //  (Header comment unchanged — see previous file.)

  //  ---- Common parameters ----

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

  std::optional<Core::Transaction> buildUnregisterValidator(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Update Reward Address ----

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

  struct CreateNftCollectionParams
  {
    TxCommonParams common;

    std::string name;
    std::string symbol;
    std::string base_uri;

    Id reward_token_id{0};
    uint64_t reward_rate_per_epoch{0};
    uint64_t escrow_amount{0};
  };

  std::optional<Core::Transaction> buildCreateNftCollection(
      const Crypto::Address &from,
      const CreateNftCollectionParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Mint (standalone) ----

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

  struct ClaimNftRewardParams
  {
    TxCommonParams common;
  };

  std::optional<Core::Transaction> buildClaimNftReward(
      const Crypto::Address &from,
      const ClaimNftRewardParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- NFT: Refill Collection Reward ----

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

  struct CreatePoolParams
  {
    TxCommonParams common;
    Id token_a{0};
    uint64_t amount_a{0};
    Id token_b{0};
    uint64_t amount_b{0};
    uint16_t fee_bps{Core::AMM_DEFAULT_FEE_BPS};
  };

  std::optional<Core::Transaction> buildCreatePool(
      const Crypto::Address &from,
      const CreatePoolParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM: Add Liquidity ----

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

  struct RemoveLiquidityParams
  {
    TxCommonParams common;
    uint64_t position_id{0};
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildRemoveLiquidity(
      const Crypto::Address &from,
      const RemoveLiquidityParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM: Swap ----

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

  struct CreateOrderParams
  {
    TxCommonParams common;
    Id sell_token{0};
    Id buy_token{0};
    uint64_t sell_amount{0};
    uint64_t min_buy_amount{0};
    Core::OrderExecutionMode mode{Core::OrderExecutionMode::Passive};
    uint64_t pool_id{0};
    uint64_t expires_at_height{0};
    std::vector<Core::OrderCondition> conditions;
  };

  std::optional<Core::Transaction> buildCreateOrder(
      const Crypto::Address &from,
      const CreateOrderParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Order Book: Cancel Order ----

  struct CancelOrderParams
  {
    TxCommonParams common;
    uint64_t order_id{0};
  };

  std::optional<Core::Transaction> buildCancelOrder(
      const Crypto::Address &from,
      const CancelOrderParams &params,
      WalletStatus *error_out = nullptr);

  //  =========================================================================
  //  AMM Farming
  //
  //  A farm is an escrow + a rate attached to one pool. These
  //  builders produce the transactions that the executor's
  //  executeAmm* handlers accept. The payload layouts match the
  //  parsers in TransactionExecutor.cpp byte-for-byte.
  //
  //  None of these builders set tx.to, tx.token_id, or tx.amount.
  //  All type-specific data lives in the payload, matching the
  //  pattern the NFT collection builders use. The fee is the only
  //  amount carried in the transaction record itself.
  //
  //  Escrow transfers (CreateAmmFarm, RefillAmmFarm) reference
  //  the reward token and the escrow amount from the payload, not
  //  from the transaction record. The executor's debitToken call
  //  reads tx.from, so the creator pays from their own balance.
  //  =========================================================================

  //  ---- AMM Farm: Create ----
  //
  //  Payload layout (matching executeCreateAmmFarm):
  //    [8]  pool_id
  //    [4]  reward_token_id
  //    [8]  reward_rate_per_epoch
  //    [8]  reward_escrow_amount
  //  Total: 28 bytes.
  //
  //  The reward token may be CLRTY (NATIVE_TOKEN_ID == 0) or any
  //  on-chain token. The escrow amount is debited from `from` and
  //  credited to the farm's virtual custody address in the same
  //  transaction.

  struct CreateAmmFarmParams
  {
    TxCommonParams common;
    uint64_t pool_id{0};
    Id reward_token_id{NATIVE_TOKEN_ID};
    uint64_t reward_rate_per_epoch{0};
    uint64_t reward_escrow_amount{0};
  };

  std::optional<Core::Transaction> buildCreateAmmFarm(
      const Crypto::Address &from,
      const CreateAmmFarmParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM Farm: Update Rate ----
  //
  //  Payload layout (matching executeUpdateAmmFarm):
  //    [8]  pool_id
  //    [8]  new_rate_per_epoch
  //  Total: 16 bytes.
  //
  //  The new rate applies at the next epoch boundary, not the
  //  current one. The executor rejects new_rate_per_epoch == 0;
  //  use PauseAmmFarm to stop emissions.

  struct UpdateAmmFarmParams
  {
    TxCommonParams common;
    uint64_t pool_id{0};
    uint64_t new_rate_per_epoch{0};
  };

  std::optional<Core::Transaction> buildUpdateAmmFarm(
      const Crypto::Address &from,
      const UpdateAmmFarmParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM Farm: Pause ----
  //
  //  Payload layout (matching executePauseAmmFarm):
  //    [8]  pool_id
  //  Total: 8 bytes.
  //
  //  Pausing is idempotent: pausing an already-paused farm is a
  //  no-op success. A refill un-pauses automatically.

  struct PauseAmmFarmParams
  {
    TxCommonParams common;
    uint64_t pool_id{0};
  };

  std::optional<Core::Transaction> buildPauseAmmFarm(
      const Crypto::Address &from,
      const PauseAmmFarmParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM Farm: Refill ----
  //
  //  Payload layout (matching executeRefillAmmFarm):
  //    [8]  pool_id
  //    [8]  amount
  //  Total: 16 bytes.
  //
  //  Adds `amount` of the farm's reward token to the escrow,
  //  debited from `from`. If the farm was paused, this un-pauses
  //  it. Refilling an unpaused farm is a no-op on the pause state
  //  and just adds to the escrow.

  struct RefillAmmFarmParams
  {
    TxCommonParams common;
    uint64_t pool_id{0};
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildRefillAmmFarm(
      const Crypto::Address &from,
      const RefillAmmFarmParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM Farm: Close ----
  //
  //  Payload layout (matching executeCloseAmmFarm):
  //    [8]  pool_id
  //  Total: 8 bytes.
  //
  //  A farm can only be closed when the pool has no liquidity
  //  and the farm is paused. The path is: pause, drain the pool
  //  (last LP's RemoveLiquidity closes the pool and the farm
  //  together), or pause then close. Any remaining escrow is
  //  refunded to the farm's creator.

  struct CloseAmmFarmParams
  {
    TxCommonParams common;
    uint64_t pool_id{0};
  };

  std::optional<Core::Transaction> buildCloseAmmFarm(
      const Crypto::Address &from,
      const CloseAmmFarmParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- AMM Farm: Claim Rewards ----
  //
  //  Empty payload. Settles every position the caller holds on
  //  every farmed pool into pending_rewards. The actual balance
  //  movement is a separate ClaimRewards transaction, matching
  //  the two-step pattern NFT rewards use (ClaimNftReward then
  //  ClaimRewards).
  //
  //  This is the correct behavior even though it's two
  //  transactions: the settle step is O(positions held) and the
  //  balance step is O(1). Bundling them would mean every claim
  //  pays for the settle whether or not the caller wanted to
  //  move the balance to spendable CLRTY in that same moment.

  struct ClaimAmmFarmRewardsParams
  {
    TxCommonParams common;
  };

  std::optional<Core::Transaction> buildClaimAmmFarmRewards(
      const Crypto::Address &from,
      const ClaimAmmFarmRewardsParams &params,
      WalletStatus *error_out = nullptr);

  //  =========================================================================
  //  Bridge
  //
  //  The builders below produce transactions that the executor's
  //  executeBridge* handlers accept. The payload layouts match the
  //  parsers in TransactionExecutor.cpp byte-for-byte — any change
  //  to one side must be mirrored on the other, or the executor
  //  rejects the transaction.
  //
  //  Two distinct trust layers:
  //
  //    * BridgeMint, BridgeAckWithdrawal, BridgeAckAttest: carry
  //      watcher-produced signatures or signature blocks. The
  //      signatures are produced off-chain by the active watcher
  //      set (their consensus keys), and the builder takes the
  //      completed block as opaque bytes. The builder does NOT
  //      sign, produce, or validate the block — that is the
  //      signing service's job. The executor validates against
  //      the active watcher set resolved from chain state.
  //
  //    * BridgeBurn: no signature block. The burn is authorized by
  //      the sender's own transaction signature. Anyone holding the
  //      wrapped token can burn it.
  //
  //    * BridgePause/Unpause/RegisterChain: governance. The
  //      signature block is signed by the validator set (also
  //      produced off-chain) and validated by
  //      verifyGovernanceSignatures.
  //  =========================================================================

  //  BridgeMint: mint wrapped tokens from an attested deposit on the
  //  source chain.
  //
  //  Payload layout (matching executeBridgeMint):
  //    [8]  source_chain_id
  //    [32] source_tx_hash
  //    [4]  source_output_index
  //    [32] destination_address
  //    [8]  amount
  //    [2]  signer_count
  //    [N]  signatures, each [2] index || [64] sig
  //
  //  The signature_block is the encoded `[2] count || N*66` block
  //  produced by the watcher federation. It is passed through
  //  opaque — the builder does not inspect it beyond checking its
  //  length matches the declared count (which the executor does
  //  again anyway).
  //
  //  This is the transaction a watcher submits after observing a
  //  deposit on the source chain and collecting M-of-N attestations
  //  from the active watcher set.

  struct BridgeMintParams
  {
    TxCommonParams common;

    uint64_t source_chain_id{0};
    Crypto::Hash source_tx_hash{};
    uint32_t source_output_index{0};
    Crypto::Address destination{};
    uint64_t amount{0};

    //  Encoded `[2] count || N*66` signature block.
    std::vector<uint8_t> signature_block;
  };

  std::optional<Core::Transaction> buildBridgeMint(
      const Crypto::Address &from,
      const BridgeMintParams &params,
      WalletStatus *error_out = nullptr);

  //  BridgeBurn: burn wrapped tokens and enqueue a withdrawal.
  //
  //  Payload layout (matching executeBridgeBurn):
  //   [8]  source_chain_id
  //   [1]  blob_len
  //   [N]  destination_blob
  //   [1]  addr_len
  //   [M]  destination_address
  //   [8]  amount
  //
  //  The wrapped token id goes in `token_id` (executor rejects if
  //  it does not match the chain registration's wrapped_token_id).
  //  No signature block: the sender's tx signature authorizes it.

  struct BridgeBurnParams
  {
    TxCommonParams common;

    uint64_t source_chain_id{0};
    Id wrapped_token_id{0};
    std::vector<uint8_t> destination_blob;

    //  Eexactly as the user typed it or received it.
    //  Stored on-chain with the withdrawal record;
    std::string destination_address;

    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildBridgeBurn(
      const Crypto::Address &from,
      const BridgeBurnParams &params,
      WalletStatus *error_out = nullptr);

  //  BridgeAckWithdrawal: confirm that a withdrawal was released on
  //  the source chain, recording the source-chain release tx hash
  //  and height on Clarity. Signed by the active watcher set.
  //
  //  Payload layout:
  //    [8]  withdrawal_id
  //    [32] release_tx_hash    — the source-chain tx hash
  //    [8]  release_height     — the source-chain block height
  //    [2]  signer_count
  //    [N]  signatures, each [2] index || [64] sig
  //
  //  The watcher signatures cover only the withdrawal_id (see
  //  executeBridgeAckWithdrawal's header comment): they authorize
  //  "release withdrawal N". The release_tx_hash and release_height
  //  are attestation data that anyone can independently verify
  //  against the source chain (via the withdrawal's payment ID),
  //  so they do not need to be under the signature.

  struct BridgeAckWithdrawalParams
  {
    TxCommonParams common;

    uint64_t withdrawal_id{0};

    //  The source-chain tx that performed the release.
    Crypto::Hash release_tx_hash{};

    //  The source-chain block height the release landed at.
    uint64_t release_height{0};

    //  Encoded `[2] count || N*66` signature block.
    std::vector<uint8_t> signature_block;
  };

  std::optional<Core::Transaction> buildBridgeAckWithdrawal(
      const Crypto::Address &from,
      const BridgeAckWithdrawalParams &params,
      WalletStatus *error_out = nullptr);

  //  BridgePause / BridgeUnpause: freeze or resume the bridge.
  //  Signed by the validator set.
  //
  //  Payload layout (matching executeBridgePause / executeBridgeUnpause):
  //    [8]  bound_height
  //    [2]  signer_count
  //    [N]  signatures, each [2] index || [64] sig
  //
  //  The signed message is `Blake2b("bpau" || LE64(bound_height))`
  //  for pause, `Blake2b("bunp"  || LE64(bound_height))` for unpause.
  //  The builder takes the completed signature block as opaque bytes.

  struct BridgePauseParams
  {
    TxCommonParams common;

    uint64_t bound_height{0};

    std::vector<uint8_t> signature_block;
  };

  std::optional<Core::Transaction> buildBridgePause(
      const Crypto::Address &from,
      const BridgePauseParams &params,
      WalletStatus *error_out = nullptr);

  std::optional<Core::Transaction> buildBridgeUnpause(
      const Crypto::Address &from,
      const BridgePauseParams &params,
      WalletStatus *error_out = nullptr);

  //  BridgeRegisterChain: register a new source chain. Signed by the
  //  validator set.
  //
  //  Payload layout (matching executeBridgeRegisterChain):
  //    [1]  registration_blob_len
  //    [N]  registration_blob (BridgeChainRegistration::serializeState)
  //    [2]  signer_count
  //    [N]  signatures, each [2] index || [64] sig
  //
  //  The signed message is the registration blob itself, so the
  //  signers commit to the exact bytes that will be written.

  struct BridgeRegisterChainParams
  {
    TxCommonParams common;

    //  Raw serialized BridgeChainRegistration bytes.
    std::vector<uint8_t> registration_blob;

    //  Encoded `[2] count || N*66` signature block.
    std::vector<uint8_t> signature_block;
  };

  std::optional<Core::Transaction> buildBridgeRegisterChain(
      const Crypto::Address &from,
      const BridgeRegisterChainParams &params,
      WalletStatus *error_out = nullptr);

  //  BridgeRegisterDeposit: register a per-authority deposit
  //  destination for a bridge source chain.
  //
  //  Payload layout (matching executeBridgeRegisterDeposit):
  //    [8]  source_chain_id
  //    [32] destination
  //  Total: 40 bytes.
  //
  //  There is no signature block. The registration is authorized
  //  by the sender's own transaction signature (tx.from becomes
  //  the record's `authority`), so the builder does not take,
  //  produce, or validate one.
  //
  //  The on-chain index is assigned by the executor from a
  //  per-chain counter; the caller does not supply it and cannot
  //  predict it. To learn the assigned index after submission,
  //  call getBridgeDepositsForAuthority for the sender's address
  //  once the transaction has confirmed, or watch the receipt.
  //
  //  Caps enforced by the executor:
  //    - MAX_BRIDGE_DEPOSITS_PER_AUTHORITY per (chain, sender)
  //    - MAX_BRIDGE_DEPOSITS_PER_CHAIN per chain.
  //
  //  This builder does not check either cap: both are live
  //  chain state, not something the wallet can see without an
  //  RPC round-trip. A registration that hits either cap
  //  returns Failure at apply time, and the fee is charged.
  //
  //  The chain must be registered and enabled at apply time.
  //  Same rationale for not checking it here: it is live
  //  chain state, and the executor rejects with Failure if
  //  the chain is not registered.
  struct BridgeRegisterDepositParams
  {
    TxCommonParams common;
    uint64_t source_chain_id{0};
    Crypto::Address destination{};
  };

  std::optional<Core::Transaction> buildBridgeRegisterDeposit(
      const Crypto::Address &from,
      const BridgeRegisterDepositParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Sign ----

  std::optional<Crypto::Hash> signTransaction(
      Core::Transaction &tx,
      Signer &signer,
      const HdPath &path = clrtyPath(0, 0, 0),
      WalletStatus *error_out = nullptr);

  //  BridgeAttest: record a single watcher's attestation over a
  //  deposit. The payload carries the deposit identifier, the
  //  destination and amount as the watcher understands them, the
  //  watcher's position in the sorted active set, and the
  //  watcher's signature over the canonical mint message.
  //
  //  The signature must be produced by `Bridge::Signing::Sign`
  //  with the watcher's *consensus* key, not their account key.
  //  The transaction's own signature (produced by signTransaction)
  //  is separate: it authorizes the transaction on-chain, while
  //  the attestation signature authorizes the deposit.
  struct BridgeAttestParams
  {
    TxCommonParams common;
    uint64_t source_chain_id{0};
    Crypto::Hash source_tx_hash{};
    uint32_t source_output_index{0};
    Crypto::Address destination{};
    uint64_t amount{0};
    uint16_t signer_index{0};
    Crypto::Signature signature{};
  };

  std::optional<Core::Transaction> buildBridgeAttest(
      const Crypto::Address &from,
      const BridgeAttestParams &params,
      WalletStatus *error_out = nullptr);

  //  BridgeAckAttest: record a single watcher's attestation over a
  //  withdrawal. The payload carries the withdrawal id, the
  //  watcher's position in the sorted active set, and the watcher's
  //  signature over `Blake2b("back" || LE64(withdrawal_id))`.
  //
  //  The signature must be produced by `Bridge::Signing::Sign`
  //  with the watcher's *consensus* key, not their account key.
  //  The transaction's own signature (produced by signTransaction)
  //  is separate: it authorizes the transaction on-chain, while
  //  the attestation signature authorizes the release.
  //
  //  Unlike BridgeAttest, this record carries no destination or
  //  amount: those live in the BridgeWithdrawal created at burn
  //  time. The attestation is only a vote that the federation
  //  observed the burn.
  struct BridgeAckAttestParams
  {
    TxCommonParams common;
    uint64_t withdrawal_id{0};
    uint16_t signer_index{0};
    Crypto::Signature signature{};
  };

  std::optional<Core::Transaction> buildBridgeAckAttest(
      const Crypto::Address &from,
      const BridgeAckAttestParams &params,
      WalletStatus *error_out = nullptr);
} // namespace Wallet