// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionExecutor.h"

#include "ActiveRouter.h"
#include "AmmPool.h"
#include "AmmPosition.h"
#include "BlockProcessor.h"
#include "Order.h"
#include "TokenTypes.h"
#include "ValidatorTypes.h"
#include "GlobalState.h"
#include "RewardTypes.h"
#include "KeyRotation.h"
#include "BridgeWatcherTypes.h"

#include "State/Keys.h"
#include "State/StateAccess.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <iomanip>

namespace Core
{

  namespace
  {
    //  Integer square root. Returns floor(sqrt(n)).
    //
    //  Binary search over [0, 2^64). The result of sqrt(n) for
    //  n < 2^128 always fits in 64 bits, so the search is bounded.
    //
    //  Used to compute a pool's initial LP supply from the initial
    //  reserves: for a first deposit of amount_a and amount_b, the
    //  minted liquidity is floor(sqrt(amount_a * amount_b)). This is
    //  the Uniswap V2 convention and gives the first LP a share
    //  proportional to the geometric mean of the two deposits.
    uint64_t isqrt128(__uint128_t n)
    {
      if (n == 0)
        return 0;

      __uint128_t lo = 0;
      __uint128_t hi = (__uint128_t(1) << 64); // exclusive upper bound

      while (hi - lo > 1)
      {
        __uint128_t mid = lo + (hi - lo) / 2;
        if (mid * mid <= n)
          lo = mid;
        else
          hi = mid;
      }

      return static_cast<uint64_t>(lo);
    }

    //  Read a uint64 from a global state entry via the SMT.
    //  Duplicated from BlockProcessor's anonymous namespace —
    //  small enough that sharing it via a header would be more
    //  code than the copy.
    uint64_t readU64GlobalInternal(State::StateAccess &state,
                                   const char *name)
    {
      std::vector<uint8_t> bytes;
      if (!state.getGlobal(name, bytes) || bytes.size() != 8)
        return 0;
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(bytes[i]) << (i * 8);
      return v;
    }

    void writeU64GlobalInternal(State::StateAccess &state,
                                const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(v >> (i * 8));
      state.putGlobal(name, bytes);
    }

    //  ---- Bridge helpers ----
    //
    //  Read a 2-byte LE count followed by `count` 66-byte entries
    //  ([2] signer_index LE || [64] signature). The whole block must
    //  be exactly 2 + count * 66 bytes. On any malformation, return
    //  false and leave `out` empty.
    //
    //  The parser is separate from the verifier so that a caller
    //  that wants only structural validation (e.g. mempool admission
    //  for a BridgeMint before checking signatures) can call it
    //  without doing any crypto.
    struct BridgeSignatureEntry
    {
      uint16_t signer_index{0};
      Crypto::Signature signature{};
    };

    bool parseBridgeSignatureBlock(const uint8_t *data, size_t len,
                                   std::vector<BridgeSignatureEntry> &out)
    {
      out.clear();
      if (len < 2)
        return false;

      const uint16_t count =
          uint16_t(data[0]) | (uint16_t(data[1]) << 8);

      //  Bound the allocation before computing size * 66.
      //  BRIDGE_MAX_WATCHERS is 100, so a count above that is
      //  rejected without allocation.
      if (count > BRIDGE_MAX_WATCHERS)
        return false;

      const size_t expected = 2 + static_cast<size_t>(count) * 66;
      if (len != expected)
        return false;

      out.reserve(count);
      for (uint16_t i = 0; i < count; ++i)
      {
        const uint8_t *p = data + 2 + i * 66;
        BridgeSignatureEntry e;
        e.signer_index = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
        std::memcpy(e.signature.data.data(), p + 2, 64);
        out.push_back(e);
      }

      return true;
    }

    //  Build the domain-separated signing message:
    //
    //    Blake2b(domain4 || message)
    //
    //  The 4-byte domain tag separates bridge operations from each
    //  other (and from the rest of the chain's hashing), which is
    //  what prevents a signature harvested from one operation from
    //  being replayed in another.
    Crypto::Hash bridgeSigningHash(std::string_view domain,
                                   const uint8_t *message, size_t message_len)
    {
      return Crypto::hashDomain(domain.data(), message, message_len);
    }

    //  Encode the canonical message that a mint attestation covers.
    //
    //    LE64(source_chain_id) || source_tx_hash(32) ||
    //    LE32(source_output_index) || destination(32) ||
    //    LE64(amount)
    std::vector<uint8_t> encodeBridgeMintMessage(
        uint64_t source_chain_id,           // 8 bytes LE
        const Crypto::Hash &source_tx_hash, // 32 bytes
        uint32_t source_output_index,       // 4 bytes LE
        const Crypto::Address &destination, // 32 bytes
        uint64_t amount)                    // 8 bytes LE
    {
      std::vector<uint8_t> out;
      out.reserve(8 + 32 + 4 + 32 + 8);

      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(source_chain_id >> (i * 8)));
      out.insert(out.end(), source_tx_hash.data.begin(), source_tx_hash.data.end());
      for (int i = 0; i < 4; ++i)
        out.push_back(uint8_t(source_output_index >> (i * 8)));
      out.insert(out.end(), destination.data.begin(), destination.data.end());
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(amount >> (i * 8)));

      return out;
    }

    //  Encode the canonical message that a withdrawal-ack
    //  attestation covers:
    //
    //    LE64(withdrawal_id)
    //
    //  The domain tag is "back", applied by bridgeSigningHash.
    //  Kept in lockstep with Bridge::Signing::EncodeBridgeAckMessage
    //  on the client side.
    std::vector<uint8_t> encodeBridgeAckMessage(uint64_t withdrawal_id)
    {
      std::vector<uint8_t> out;
      out.reserve(8);
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(withdrawal_id >> (i * 8)));
      return out;
    }

    //  Read or initialize the bridge stats row for a chain and
    //  apply a delta. Centralized so every handler updates the
    //  same fields the same way, and so a missing row is
    //  initialized on first touch.
    //
    //  The caller passes the incremental change; this function
    //  reads-modifies-writes in one step. Not reentrant: the
    //  handlers never call this twice for the same chain in one
    //  transaction, because each transaction touches exactly one
    //  chain.
    void bumpBridgeStats(State::StateAccess &state,
                         uint64_t source_chain_id,
                         uint64_t current_height,
                         uint64_t minted_delta,
                         uint64_t burned_delta,
                         uint64_t released_delta,
                         bool count_deposit,
                         bool count_withdrawal,
                         bool count_release)
    {
      Core::BridgeStats stats;
      if (!state.getBridgeStats(source_chain_id, stats))
      {
        stats.source_chain_id = source_chain_id;
        stats.registered_at_height = current_height;
      }

      stats.total_minted += minted_delta;
      stats.total_burned += burned_delta;
      stats.total_released += released_delta;

      if (count_deposit)
      {
        stats.deposit_count += 1;
        stats.last_mint_height = current_height;
      }
      if (count_withdrawal)
      {
        stats.withdrawal_count += 1;
        stats.last_burn_height = current_height;
      }
      if (count_release)
      {
        stats.released_withdrawal_count += 1;
        stats.last_release_height = current_height;
      }

      state.putBridgeStats(stats);
    }

    //  Read a 2-byte LE count from a payload at `off`, and advance
    //  `off` past it. Returns 0 and does NOT advance on truncation
    //  (caller must check `off <= payload.size()` afterwards).
    uint16_t readU16At(const std::vector<uint8_t> &p, size_t &off)
    {
      if (off + 2 > p.size())
        return 0;
      const uint16_t v = uint16_t(p[off]) | (uint16_t(p[off + 1]) << 8);
      off += 2;
      return v;
    }

    //  Debit an account's balance of a token (native or custom).
    //  Returns false if the balance is insufficient.
    bool debitToken(State::StateAccess &state,
                    const Crypto::Address &addr,
                    Id token_id, uint64_t amount)
    {
      if (token_id == NATIVE_TOKEN_ID)
      {
        Core::Account acct = state.getAccount(addr);
        if (acct.balance < amount)
          return false;
        acct.balance -= amount;
        state.putAccount(addr, acct);
        return true;
      }

      uint64_t bal = state.getTokenBalance(addr, token_id);
      if (bal < amount)
        return false;
      state.putTokenBalance(addr, token_id, bal - amount);
      return true;
    }

    //  Credit an account's balance of a token (native or custom).
    void creditToken(State::StateAccess &state,
                     const Crypto::Address &addr,
                     Id token_id, uint64_t amount)
    {
      if (amount == 0)
        return;

      if (token_id == NATIVE_TOKEN_ID)
      {
        Core::Account acct = state.getAccount(addr);
        acct.balance += amount;
        state.putAccount(addr, acct);
        return;
      }

      uint64_t bal = state.getTokenBalance(addr, token_id);
      state.putTokenBalance(addr, token_id, bal + amount);
    }

    //  Read an id from a payload at a byte offset, LE. No bounds
    //  check — callers are expected to have validated size first.
    uint32_t readU32At(const std::vector<uint8_t> &p, size_t off)
    {
      return uint32_t(p[off]) | (uint32_t(p[off + 1]) << 8) |
             (uint32_t(p[off + 2]) << 16) | (uint32_t(p[off + 3]) << 24);
    }

    uint64_t readU64At(const std::vector<uint8_t> &p, size_t off)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(p[off + i]) << (i * 8);
      return v;
    }

    //  Record a bridge event. Called once per successful operation,
    //  after the operation's state changes are in place. The table
    //  is non-SMT, so this is safe on both the dry-run and apply
    //  paths; the dry-run path aborts and discards it.
    void recordBridgeEvent(State::StateAccess &state,
                           Core::BridgeEventKind kind,
                           uint64_t source_chain_id,
                           uint64_t current_height,
                           uint64_t tx_index,
                           const Crypto::Hash &tx_hash,
                           const Crypto::Address &actor,
                           const Crypto::Hash &source_tx_hash,
                           bool has_source,
                           uint32_t source_output_index,
                           uint64_t withdrawal_id,
                           uint64_t amount,
                           uint64_t counterparty)
    {
      Core::BridgeEvent evt;
      evt.kind = kind;
      evt.source_chain_id = source_chain_id;
      evt.block_height = current_height;
      evt.tx_index_in_block = static_cast<uint32_t>(tx_index);
      evt.tx_hash = tx_hash;
      evt.has_source_hash = has_source;
      evt.source_tx_hash = source_tx_hash;
      evt.source_output_index = source_output_index;
      evt.withdrawal_id = withdrawal_id;
      evt.actor = actor;
      evt.amount = amount;
      evt.counterparty = counterparty;
      evt.has_tx_hash = true;
      state.putBridgeEvent(evt);
    }
  } // anonymous namespace

  //  Dispatch

  Receipt TransactionExecutor::execute(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // ---- Structural validation ----
    if (!tx.isWellFormed())
    {
      return failure;
    }

    // ---- Chain ID ----
    if (tx.chain_id != ctx.chain_id)
    {
      return failure;
    }

    // ---- Expiry ----
    if (!checkExpiry(tx, ctx))
    {
      return failure;
    }

    // ---- Signature ----
    if (!verifySignature(tx))
    {
      return failure;
    }

    // ---- Nonce ----
    if (!verifyNonce(state, tx))
    {
      return failure;
    }

    // ---- Fee charge ----
    // Charge fee before dispatch. If the sender can't pay, fail.
    if (!chargeFee(state, tx))
    {
      return failure;
    }

    // ---- Dispatch by type ----
    Receipt receipt{ReceiptStatus::Failure, tx.fee};

    switch (tx.tx_type)
    {
    case TxType::Transfer:
      receipt = executeTransfer(state, tx, ctx);
      break;

    case TxType::OptInStaking:
      receipt = executeOptInStaking(state, tx, ctx);
      break;

    case TxType::OptOutStaking:
      receipt = executeOptOutStaking(state, tx, ctx);
      break;

    case TxType::ClaimRewards:
      receipt = executeClaimRewards(state, tx, ctx);
      break;

    case TxType::RegisterValidator:
      receipt = executeRegisterValidator(state, tx, ctx);
      break;

    case TxType::UnregisterValidator:
      receipt = executeUnregisterValidator(state, tx, ctx);
      break;

    case TxType::UpdateRewardAddress:
      receipt = executeUpdateRewardAddress(state, tx, ctx);
      break;

    case TxType::RotateConsensusKey:
      receipt = executeRotateConsensusKey(state, tx, ctx);
      break;

    case TxType::CreateToken:
      receipt = executeCreateToken(state, tx, ctx);
      break;

    case TxType::MintToken:
      receipt = executeMintToken(state, tx, ctx);
      break;

    case TxType::BurnToken:
      receipt = executeBurnToken(state, tx, ctx);
      break;

    case TxType::UpdateTokenMeta:
      receipt = executeUpdateTokenMeta(state, tx, ctx);
      break;

    case TxType::CreatePool:
      receipt = executeCreatePool(state, tx, ctx);
      break;

    case TxType::AddLiquidity:
      receipt = executeAddLiquidity(state, tx, ctx);
      break;

    case TxType::RemoveLiquidity:
      receipt = executeRemoveLiquidity(state, tx, ctx);
      break;

    case TxType::Swap:
      receipt = executeSwap(state, tx, ctx);
      break;

    case TxType::CreateOrder:
      receipt = executeCreateOrder(state, tx, ctx);
      break;

    case TxType::CancelOrder:
      receipt = executeCancelOrder(state, tx, ctx);
      break;

    case TxType::CreateNftCollection:
      receipt = executeCreateNftCollection(state, tx, ctx);
      break;

    case TxType::MintNft:
      receipt = executeMintNft(state, tx, ctx);
      break;

    case TxType::WrapNft:
      receipt = executeWrapNft(state, tx, ctx);
      break;

    case TxType::TransferNft:
      receipt = executeTransferNft(state, tx, ctx);
      break;

    case TxType::BurnNft:
      receipt = executeBurnNft(state, tx, ctx);
      break;

    case TxType::UpdateNftMetadata:
      receipt = executeUpdateNftMetadata(state, tx, ctx);
      break;

    case TxType::TopUpNft:
      receipt = executeTopUpNft(state, tx, ctx);
      break;

    case TxType::ClaimNftReward:
      receipt = executeClaimNftReward(state, tx, ctx);
      break;

    case TxType::RefillCollectionReward:
      receipt = executeRefillCollectionReward(state, tx, ctx);
      break;

    case TxType::BridgeMint:
      receipt = executeBridgeMint(state, tx, ctx);
      break;

    case TxType::BridgeBurn:
      receipt = executeBridgeBurn(state, tx, ctx);
      break;

    case TxType::BridgePause:
      receipt = executeBridgePause(state, tx, ctx);
      break;

    case TxType::BridgeUnpause:
      receipt = executeBridgeUnpause(state, tx, ctx);
      break;

    case TxType::BridgeAckWithdrawal:
      receipt = executeBridgeAckWithdrawal(state, tx, ctx);
      break;

    case TxType::BridgeRegisterChain:
      receipt = executeBridgeRegisterChain(state, tx, ctx);
      break;

    case TxType::BridgeAttest:
      receipt = executeBridgeAttest(state, tx, ctx);
      break;

    case TxType::BridgeAckAttest:
      receipt = executeBridgeAckAttest(state, tx, ctx);
      break;

    case TxType::RegisterBridgeWatcher:
      receipt = executeRegisterBridgeWatcher(state, tx, ctx);
      break;

    case TxType::UnregisterBridgeWatcher:
      receipt = executeUnregisterBridgeWatcher(state, tx, ctx);
      break;

    default:
      // Unhandled type — fail.
      return failure;
    }

    // ---- Nonce bump on success ----
    if (receipt.status == ReceiptStatus::Success)
    {
      bumpNonce(state, tx);
    }

    return receipt;
  }

  //  Common helpers

  bool TransactionExecutor::verifySignature(const Transaction &tx)
  {
    Crypto::Hash hash = tx.signingHash();
    return Crypto::verify(hash, tx.from, tx.signature);
  }

  bool TransactionExecutor::verifyNonce(State::StateAccess &state,
                                        const Transaction &tx)
  {
    Account acct = state.getAccount(tx.from);
    return acct.nonce == tx.nonce;
  }

  bool TransactionExecutor::checkExpiry(const Transaction &tx,
                                        const TxExecutionContext &ctx)
  {
    if (tx.valid_until_height == 0)
      return true;
    return ctx.current_height <= tx.valid_until_height;
  }

  bool TransactionExecutor::chargeFee(State::StateAccess &state,
                                      const Transaction &tx)
  {
    Account sender = state.getAccount(tx.from);

    if (sender.balance < tx.fee)
    {
      return false;
    }

    sender.balance -= tx.fee;
    state.putAccount(tx.from, sender);
    return true;
  }

  void TransactionExecutor::refundFee(State::StateAccess &state,
                                      const Transaction &tx)
  {
    Account sender = state.getAccount(tx.from);
    sender.balance += tx.fee;
    state.putAccount(tx.from, sender);
  }

  void TransactionExecutor::bumpNonce(State::StateAccess &state,
                                      const Transaction &tx)
  {
    Account sender = state.getAccount(tx.from);
    sender.nonce++;
    state.putAccount(tx.from, sender);
  }

  std::vector<Id> TransactionExecutor::loadActiveSet(
      State::StateAccess &state)
  {
    std::vector<Id> result;

    std::vector<uint8_t> set_bytes;
    if (!state.getGlobal("active_set", set_bytes))
      return result;

    size_t count = set_bytes.size() / 8;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t id = 0;
      for (int j = 0; j < 8; ++j)
        id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
      result.push_back(id);
    }

    return result;
  }

  void TransactionExecutor::saveActiveSet(
      State::StateAccess &state,
      const std::vector<Id> &active_set)
  {
    std::vector<uint8_t> set_bytes;
    set_bytes.reserve(active_set.size() * 8);
    for (auto vid : active_set)
    {
      for (int i = 0; i < 8; ++i)
        set_bytes.push_back(uint8_t(vid >> (i * 8)));
    }
    state.putGlobal("active_set", set_bytes);
  }

  //  Transfer

  Receipt TransactionExecutor::executeTransfer(State::StateAccess &state,
                                               const Transaction &tx,
                                               const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.amount == 0)
      return failure;
    if (tx.to.isNull())
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
    {
      Account sender = state.getAccount(tx.from);

      if (sender.balance < tx.amount)
        return failure;

      sender.balance -= tx.amount;
      state.putAccount(tx.from, sender);

      Account receiver = state.getAccount(tx.to);
      receiver.balance += tx.amount;
      if (receiver.created_at_height == 0)
      {
        receiver.created_at_height = ctx.current_height;
      }
      state.putAccount(tx.to, receiver);

      return {ReceiptStatus::Success, tx.fee};
    }

    uint64_t sender_balance = state.getTokenBalance(tx.from, tx.token_id);
    if (sender_balance < tx.amount)
      return failure;

    state.putTokenBalance(tx.from, tx.token_id, sender_balance - tx.amount);

    uint64_t receiver_balance = state.getTokenBalance(tx.to, tx.token_id);
    state.putTokenBalance(tx.to, tx.token_id, receiver_balance + tx.amount);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Opt-In Staking

  Receipt TransactionExecutor::executeOptInStaking(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext & /*ctx*/)
  {
    Account acct = state.getAccount(tx.from);
    acct.staking_opted_out = false;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Opt-Out Staking

  Receipt TransactionExecutor::executeOptOutStaking(State::StateAccess &state,
                                                    const Transaction &tx,
                                                    const TxExecutionContext & /*ctx*/)
  {
    Account acct = state.getAccount(tx.from);
    acct.staking_opted_out = true;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Claim Rewards

  Receipt TransactionExecutor::executeClaimRewards(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext & /*ctx*/)
  {
    Account acct = state.getAccount(tx.from);

    acct.balance += acct.pending_rewards;
    acct.pending_rewards = 0;

    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);

    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Register Validator

  Receipt TransactionExecutor::executeRegisterValidator(State::StateAccess &state,
                                                        const Transaction &tx,
                                                        const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    Account acct = state.getAccount(tx.from);

    if (acct.balance < GlobalConfig::VALIDATOR_MIN_STAKE)
      return failure;

    if (tx.payload.size() != 32)
      return failure;

    uint64_t existing_id = 0;
    if (state.getValidatorByAddress(tx.from, existing_id))
      return failure;

    std::vector<uint8_t> id_bytes;
    if (!state.getGlobal("next_validator_id", id_bytes))
    {
      id_bytes.resize(8, 0);
      id_bytes[0] = 1;
    }

    uint64_t next_id = 0;
    for (int i = 0; i < 8; ++i)
    {
      if (i < (int)id_bytes.size())
      {
        next_id |= uint64_t(id_bytes[i]) << (i * 8);
      }
    }

    ValidatorInfo validator;
    validator.id = next_id;
    validator.reward_address = tx.from;
    validator.owner = tx.from;
    validator.stake = acct.balance;
    validator.registered_at_height = ctx.current_height;
    validator.uptime_score = 10'000;
    validator.is_seed = false;
    validator.is_active = false;
    std::memcpy(validator.consensus_key.data.data(), tx.payload.data(), 32);

    state.putValidator(validator);
    state.putValidatorByAddress(validator.reward_address, validator.id);

    //  Initialize the key history with a single entry covering
    //  from registration onward. The initial signing key is
    //  whatever the record carries, which for a fresh
    //  registration is the payload key.
    {
      std::vector<Core::KeyRotation> history;
      Core::KeyRotation entry;
      entry.key = validator.effectiveConsensusKey();
      entry.valid_from_height = ctx.current_height;
      entry.valid_until_height = 0;
      history.push_back(entry);
      state.putValidatorKeyHistory(validator.id, history);
    }

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_validator_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Unregister Validator

  Receipt TransactionExecutor::executeUnregisterValidator(State::StateAccess &state,
                                                          const Transaction &tx,
                                                          const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    if (validator.is_seed)
      return failure;

    std::vector<Id> active_set = loadActiveSet(state);
    const bool was_active =
        std::find(active_set.begin(), active_set.end(), validator_id) !=
        active_set.end();

    if (was_active)
    {
      std::vector<Id> new_set;
      new_set.reserve(active_set.size());
      for (auto vid : active_set)
      {
        if (vid != validator_id)
          new_set.push_back(vid);
      }

      if (new_set.size() < GlobalConfig::ACTIVE_SET_MIN)
        return failure;

      saveActiveSet(state, new_set);
    }

    if (validator.pending_unbond_height != 0)
      return failure;

    validator.is_active = false;
    validator.last_active_at = ctx.current_height;
    validator.pending_unbond_height = ctx.current_height + UNBONDING_PERIOD;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Update Reward Address

  Receipt TransactionExecutor::executeUpdateRewardAddress(State::StateAccess &state,
                                                          const Transaction &tx,
                                                          const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 32)
      return failure;

    Crypto::Address new_address;
    std::memcpy(new_address.data.data(), tx.payload.data(), 32);

    if (new_address.isNull())
      return failure;

    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    if (new_address != tx.from)
    {
      uint64_t collision = 0;
      if (state.getValidatorByAddress(new_address, collision))
        return failure;
    }

    if (validator.consensus_key.isNull())
      validator.consensus_key = validator.effectiveConsensusKey();

    state.deleteValidatorByAddress(validator.reward_address);
    state.putValidatorByAddress(new_address, validator.id);

    validator.reward_address = new_address;
    validator.owner = new_address;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Rotate Consensus Key

  Receipt TransactionExecutor::executeRotateConsensusKey(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 32)
      return failure;

    Crypto::PublicKey new_key;
    std::memcpy(new_key.data.data(), tx.payload.data(), 32);

    if (new_key.isNull())
      return failure;

    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    //  Only the owner can rotate. In current deployments the owner
    //  and reward_address are the same; the check is written
    //  against owner so the invariant survives a future split.
    if (validator.owner != tx.from)
      return failure;

    //  A no-op rotation is a user error. effectiveConsensusKey()
    //  returns the current signing key whether it's the explicit
    //  consensus_key or the reward_address fallback.
    if (validator.effectiveConsensusKey() == new_key)
      return failure;

    //  A departing validator should not extend its signing window.
    if (validator.pending_unbond_height != 0)
      return failure;

    //  Load the current history. If it doesn't exist (a validator
    //  registered before the feature existed, or a record whose
    //  history was never written), synthesize a single-entry
    //  history covering from registration onward using the
    //  record's current key. This migration path keeps every
    //  pre-feature validator working through the first rotation.
    std::vector<Core::KeyRotation> history;
    if (!state.getValidatorKeyHistory(validator_id, history) ||
        history.empty())
    {
      history.clear();
      Core::KeyRotation initial;
      initial.key = validator.effectiveConsensusKey();
      initial.valid_from_height = validator.registered_at_height;
      initial.valid_until_height = 0;
      history.push_back(initial);
    }

    //  Seal the previous last entry at the rotation height.
    history.back().valid_until_height = ctx.current_height;

    //  Append the new entry.
    Core::KeyRotation entry;
    entry.key = new_key;
    entry.valid_from_height = ctx.current_height;
    entry.valid_until_height = 0;
    history.push_back(entry);

    state.putValidatorKeyHistory(validator_id, history);

    //  Update the record's cached key.
    validator.consensus_key = new_key;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Token

  Receipt TransactionExecutor::executeCreateToken(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 3)
      return failure;

    size_t off = 0;
    uint8_t decimals = tx.payload[off++];
    uint8_t backing = tx.payload[off++];
    uint8_t name_len = tx.payload[off++];

    if (off + name_len + 1 > tx.payload.size())
      return failure;
    std::string name(reinterpret_cast<const char *>(tx.payload.data() + off), name_len);
    off += name_len;

    uint8_t sym_len = tx.payload[off++];
    if (off + sym_len + 8 + 2 + 1 > tx.payload.size())
      return failure;
    std::string symbol(reinterpret_cast<const char *>(tx.payload.data() + off), sym_len);
    off += sym_len;

    uint64_t max_supply = 0;
    for (int i = 0; i < 8; ++i)
      max_supply |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint16_t royalty_bps = uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;

    uint8_t has_fp = tx.payload[off++];
    std::optional<Crypto::Hash> fingerprint;
    if (has_fp)
    {
      if (off + 32 > tx.payload.size())
        return failure;
      Crypto::Hash fp;
      std::memcpy(fp.data.data(), tx.payload.data() + off, 32);
      off += 32;
      fingerprint = fp;
    }

    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_token_id", id_bytes);
    uint64_t next_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_id = 1;

    TokenInfo token;
    token.id = static_cast<Id>(next_id);
    token.name = name;
    token.symbol = symbol;
    token.decimals = decimals;
    token.creator = tx.from;
    token.backing = static_cast<BackingModel>(backing);
    token.maxSupply = max_supply;
    token.royaltyBps = royalty_bps;
    token.fingerprint = fingerprint;

    if (!token.isValid())
      return failure;

    state.putToken(token);
    state.putTokenSupply(token.id, 0);

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_token_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Mint Token

  Receipt TransactionExecutor::executeMintToken(State::StateAccess &state,
                                                const Transaction &tx,
                                                const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.amount == 0)
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    if (token.creator != tx.from)
      return failure;

    uint64_t current_supply = state.getTokenSupply(tx.token_id);

    if (token.maxSupply > 0 && current_supply + tx.amount > token.maxSupply)
      return failure;

    uint64_t recipient_balance = state.getTokenBalance(tx.to, tx.token_id);
    state.putTokenBalance(tx.to, tx.token_id, recipient_balance + tx.amount);

    state.putTokenSupply(tx.token_id, current_supply + tx.amount);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Burn Token

  Receipt TransactionExecutor::executeBurnToken(State::StateAccess &state,
                                                const Transaction &tx,
                                                const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.amount == 0)
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    //  Bridged tokens are not user-burnable. The only way to
    //  destroy a bridged token is BridgeBurn, which produces a
    //  withdrawal record; a user BurnToken would decrement supply
    //  without producing one, destroying value with no release.
    if (token.isBridged())
      return failure;

    uint64_t sender_balance = state.getTokenBalance(tx.from, tx.token_id);
    if (sender_balance < tx.amount)
      return failure;

    state.putTokenBalance(tx.from, tx.token_id, sender_balance - tx.amount);

    uint64_t current_supply = state.getTokenSupply(tx.token_id);
    uint64_t new_supply = (current_supply >= tx.amount)
                              ? current_supply - tx.amount
                              : 0;
    state.putTokenSupply(tx.token_id, new_supply);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Update Token Meta

  Receipt TransactionExecutor::executeUpdateTokenMeta(State::StateAccess &state,
                                                      const Transaction &tx,
                                                      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 4)
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    if (token.creator != tx.from)
      return failure;

    size_t off = 0;
    uint8_t name_len = tx.payload[off++];
    if (off + name_len + 1 > tx.payload.size())
      return failure;

    std::string new_name(reinterpret_cast<const char *>(tx.payload.data() + off),
                         name_len);
    off += name_len;

    uint8_t sym_len = tx.payload[off++];
    if (off + sym_len + 2 > tx.payload.size())
      return failure;

    std::string new_symbol(reinterpret_cast<const char *>(tx.payload.data() + off),
                           sym_len);
    off += sym_len;

    uint16_t new_royalty = uint16_t(tx.payload[off]) |
                           (uint16_t(tx.payload[off + 1]) << 8);

    TokenInfo updated = token;
    if (name_len > 0)
      updated.name = new_name;
    if (sym_len > 0)
      updated.symbol = new_symbol;
    if (new_royalty != 0)
      updated.royaltyBps = new_royalty;

    if (!updated.isValid())
      return failure;

    state.putToken(updated);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Pool

  Receipt TransactionExecutor::executeCreatePool(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 14)
      return failure;

    size_t off = 0;
    uint32_t token_b = uint32_t(tx.payload[off]) | (uint32_t(tx.payload[off + 1]) << 8) | (uint32_t(tx.payload[off + 2]) << 16) | (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t amount_b = 0;
    for (int i = 0; i < 8; ++i)
      amount_b |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint16_t fee_bps = uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);

    uint32_t token_a = tx.token_id;
    uint64_t amount_a = tx.amount;

    if (token_a == token_b)
      return failure;
    if (amount_a == 0 || amount_b == 0)
      return failure;
    if (fee_bps > AMM_MAX_FEE_BPS)
      return failure;

    //  Enforce the pool-creation floor, but only on the CLRTY side.
    //
    //  MIN_POOL_LIQUIDITY is denominated in atomic units of the
    //  native token. Applying it to a non-CLRTY side would mean a
    //  token with low decimals — say, a token with decimals = 0
    //  and max supply 100 — could never be pooled, because the
    //  floor would exceed its entire supply.
    //
    //  A token/token pool has no CLRTY reference and therefore no
    //  meaningful "1000 CLRTY equivalent" floor. Both reserves
    //  must be positive; the exact amounts are the creator's
    //  choice.
    if (token_a == NATIVE_TOKEN_ID &&
        amount_a < MIN_POOL_LIQUIDITY)
      return failure;
    if (token_b == NATIVE_TOKEN_ID &&
        amount_b < MIN_POOL_LIQUIDITY)
      return failure;

    if (token_a > token_b)
    {
      std::swap(token_a, token_b);
      std::swap(amount_a, amount_b);
    }

    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_pool_id", id_bytes);
    uint64_t next_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_id = 1;

    AmmPool pool;
    pool.id = next_id;
    pool.creator = tx.from;
    pool.token_a = token_a;
    pool.token_b = token_b;
    pool.reserve_a = amount_a;
    pool.reserve_b = amount_b;
    pool.fee_bps = fee_bps;
    pool.created_at_height = ctx.current_height;
    pool.active = true;

    const __uint128_t prod = static_cast<__uint128_t>(amount_a) * amount_b;
    pool.total_liquidity = isqrt128(prod);

    if (!pool.isValid())
      return failure;

    if (token_a == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_a)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_a);
      if (bal < amount_a)
        return failure;
    }

    if (token_b == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_b)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_b);
      if (bal < amount_b)
        return failure;
    }

    if (token_a == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_a;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_a);
      state.putTokenBalance(tx.from, token_a, bal - amount_a);
    }

    if (token_b == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_b;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_b);
      state.putTokenBalance(tx.from, token_b, bal - amount_b);
    }

    state.putAmmPool(pool);

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_pool_id", new_id_bytes);

    std::vector<uint8_t> pos_id_bytes;
    state.getGlobal("next_position_id", pos_id_bytes);
    uint64_t next_pos_id = 1;
    for (int i = 0; i < 8 && i < (int)pos_id_bytes.size(); ++i)
    {
      next_pos_id |= uint64_t(pos_id_bytes[i]) << (i * 8);
    }
    if (pos_id_bytes.empty())
      next_pos_id = 1;

    AmmPosition pos;
    pos.id = next_pos_id;
    pos.owner = tx.from;
    pos.pool_id = pool.id;
    pos.liquidity = isqrt128(prod);
    pos.created_at_height = ctx.current_height;
    state.putAmmPosition(pos);

    state.putPositionIndex(tx.from, pool.id, next_pos_id);

    uint64_t new_pos_next = next_pos_id + 1;
    std::vector<uint8_t> new_pos_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_pos_id_bytes[i] = uint8_t(new_pos_next >> (i * 8));
    state.putGlobal("next_position_id", new_pos_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Add Liquidity

  Receipt TransactionExecutor::executeAddLiquidity(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 16)
      return failure;

    size_t off = 0;
    uint64_t pool_id = 0;
    for (int i = 0; i < 8; ++i)
      pool_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint64_t amount_b = 0;
    for (int i = 0; i < 8; ++i)
      amount_b |= uint64_t(tx.payload[off + i]) << (i * 8);

    AmmPool pool;
    if (!state.getAmmPool(pool_id, pool))
      return failure;
    if (!pool.active)
      return failure;

    Id token_in = tx.token_id;
    Id token_other = (token_in == pool.token_a) ? pool.token_b : pool.token_a;
    if (token_in != pool.token_a && token_in != pool.token_b)
      return failure;

    uint64_t amount_in = tx.amount;

    if (pool.reserve_a == 0 || pool.reserve_b == 0)
      return failure;

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_in)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      if (bal < amount_in)
        return failure;
    }

    if (token_other == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_b)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_other);
      if (bal < amount_b)
        return failure;
    }

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_in;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      state.putTokenBalance(tx.from, token_in, bal - amount_in);
    }

    if (token_other == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_b;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_other);
      state.putTokenBalance(tx.from, token_other, bal - amount_b);
    }

    uint64_t share_a = (amount_in * pool.total_liquidity) / pool.reserve_a;
    uint64_t share_b = (amount_b * pool.total_liquidity) / pool.reserve_b;
    uint64_t liquidity_minted = std::min(share_a, share_b);

    if (token_in == pool.token_a)
    {
      pool.reserve_a += amount_in;
      pool.reserve_b += amount_b;
    }
    else
    {
      pool.reserve_b += amount_in;
      pool.reserve_a += amount_b;
    }
    pool.total_liquidity += liquidity_minted;
    state.putAmmPool(pool);

    uint64_t existing_pos_id = 0;

    if (state.getPositionIndex(tx.from, pool_id, existing_pos_id))
    {
      AmmPosition pos;
      if (state.getAmmPosition(existing_pos_id, pos))
      {
        pos.liquidity += liquidity_minted;
        state.putAmmPosition(pos);
        return {ReceiptStatus::Success, tx.fee};
      }
    }

    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_position_id", id_bytes);
    uint64_t next_pos_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_pos_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_pos_id = 1;

    AmmPosition pos;
    pos.id = next_pos_id;
    pos.owner = tx.from;
    pos.pool_id = pool_id;
    pos.liquidity = liquidity_minted;
    pos.created_at_height = ctx.current_height;
    state.putAmmPosition(pos);

    state.putPositionIndex(tx.from, pool_id, next_pos_id);

    uint64_t new_next = next_pos_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_position_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Remove Liquidity

  Receipt TransactionExecutor::executeRemoveLiquidity(State::StateAccess &state,
                                                      const Transaction &tx,
                                                      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [8]  position_id (LE)
    //    [8]  amount (LE)      — 0 = remove the whole position
    if (tx.payload.size() != 16)
      return failure;

    const uint64_t position_id = readU64At(tx.payload, 0);
    const uint64_t requested_amount = readU64At(tx.payload, 8);

    AmmPosition pos;
    if (!state.getAmmPosition(position_id, pos))
      return failure;
    if (pos.owner != tx.from)
      return failure;
    if (pos.liquidity == 0)
      return failure;

    //  amount == 0 means "remove everything". amount > 0 must not
    //  exceed the position's liquidity. Any value in between is a
    //  partial removal.
    const uint64_t amount =
        (requested_amount == 0) ? pos.liquidity : requested_amount;

    if (amount > pos.liquidity)
      return failure;

    AmmPool pool;
    if (!state.getAmmPool(pos.pool_id, pool))
      return failure;

    //  Compute the LP's pro-rata share of both reserves.
    //
    //  Two issues with the naive form:
    //
    //    1. amount * pool.reserve_a overflows uint64_t for
    //       realistic pool sizes. The products must be promoted
    //       to unsigned __int128.
    //
    //    2. When the removal is the last of the pool's liquidity
    //       (amount == pool.total_liquidity), rounding in the
    //       pro-rata computation can leave dust in the reserves.
    //       A pool with `1` unit on each side is not `isClosed()`
    //       (which requires both reserves to be exactly zero) and
    //       cannot be drained further. Special-case the last
    //       removal: the LP gets everything, regardless of
    //       rounding.
    const bool is_last_removal = (amount == pool.total_liquidity);

    uint64_t share_a = 0;
    uint64_t share_b = 0;

    if (is_last_removal)
    {
      share_a = pool.reserve_a;
      share_b = pool.reserve_b;
    }
    else
    {
      share_a = static_cast<uint64_t>(
          static_cast<unsigned __int128>(amount) * pool.reserve_a /
          pool.total_liquidity);
      share_b = static_cast<uint64_t>(
          static_cast<unsigned __int128>(amount) * pool.reserve_b /
          pool.total_liquidity);
    }

    pool.reserve_a -= share_a;
    pool.reserve_b -= share_b;
    pool.total_liquidity -= amount;
    state.putAmmPool(pool);

    //  Credit the LP with both shares.
    if (pool.token_a == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance += share_a;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, pool.token_a);
      state.putTokenBalance(tx.from, pool.token_a, bal + share_a);
    }

    if (pool.token_b == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance += share_b;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, pool.token_b);
      state.putTokenBalance(tx.from, pool.token_b, bal + share_b);
    }

    //  Update the position. Partial removal decrements liquidity
    //  and keeps the position record and index. Full removal
    //  zeroes liquidity and drops the index entry.
    if (is_last_removal)
    {
      pos.liquidity = 0;
      state.putAmmPosition(pos);
      state.deletePositionIndex(pos.owner, pos.pool_id);
    }
    else
    {
      pos.liquidity -= amount;
      state.putAmmPosition(pos);
      //  Position index unchanged.
    }

    //  If the pool is now drained (last LP removed all their
    //  liquidity), delete the pool record.
    if (pool.isClosed())
    {
      state.deleteAmmPool(pool.id);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Swap

  Receipt TransactionExecutor::executeSwap(State::StateAccess &state,
                                           const Transaction &tx,
                                           const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 16)
      return failure;

    size_t off = 0;
    uint64_t pool_id = 0;
    for (int i = 0; i < 8; ++i)
      pool_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint64_t min_amount_out = 0;
    for (int i = 0; i < 8; ++i)
      min_amount_out |= uint64_t(tx.payload[off + i]) << (i * 8);

    AmmPool pool;
    if (!state.getAmmPool(pool_id, pool))
      return failure;
    if (!pool.active)
      return failure;

    Id token_in = tx.token_id;
    Id token_out;
    uint64_t reserve_in, reserve_out;

    if (token_in == pool.token_a)
    {
      token_out = pool.token_b;
      reserve_in = pool.reserve_a;
      reserve_out = pool.reserve_b;
    }
    else if (token_in == pool.token_b)
    {
      token_out = pool.token_a;
      reserve_in = pool.reserve_b;
      reserve_out = pool.reserve_a;
    }
    else
    {
      return failure;
    }

    uint64_t amount_in = tx.amount;

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_in)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      if (bal < amount_in)
        return failure;
    }

    const uint64_t amount_in_with_fee = static_cast<uint64_t>(
        static_cast<__uint128_t>(amount_in) * (10'000 - pool.fee_bps) / 10'000);

    __uint128_t numerator = static_cast<__uint128_t>(reserve_out) * amount_in_with_fee;
    uint64_t denominator = reserve_in + amount_in_with_fee;
    uint64_t amount_out = static_cast<uint64_t>(numerator / denominator);

    if (amount_out < min_amount_out)
      return failure;

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_in;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      state.putTokenBalance(tx.from, token_in, bal - amount_in);
    }

    if (token_out == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.to);
      acct.balance += amount_out;
      state.putAccount(tx.to, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.to, token_out);
      state.putTokenBalance(tx.to, token_out, bal + amount_out);
    }

    uint64_t clrty_volume = 0;

    if (token_in == NATIVE_TOKEN_ID)
    {
      clrty_volume = amount_in;
    }
    else if (pool.token_a == NATIVE_TOKEN_ID && pool.reserve_b > 0)
    {
      clrty_volume = static_cast<uint64_t>(
          static_cast<__uint128_t>(amount_in) *
          pool.reserve_a / pool.reserve_b);
    }
    else if (pool.token_b == NATIVE_TOKEN_ID && pool.reserve_a > 0)
    {
      clrty_volume = static_cast<uint64_t>(
          static_cast<__uint128_t>(amount_in) *
          pool.reserve_b / pool.reserve_a);
    }

    if (pool.volume_window_height == 0)
    {
      pool.volume_window_height = ctx.current_height;
      pool.volume_current = clrty_volume;
      pool.volume_last = 0;
    }
    else if (ctx.current_height >=
             pool.volume_window_height + ROTATION_INTERVAL)
    {
      pool.volume_last = pool.volume_current;
      pool.volume_current = clrty_volume;
      pool.volume_window_height = ctx.current_height;
    }
    else
    {
      pool.volume_current += clrty_volume;
    }

    if (token_in == pool.token_a)
    {
      pool.reserve_a += amount_in;
      pool.reserve_b -= amount_out;
    }
    else
    {
      pool.reserve_b += amount_in;
      pool.reserve_a -= amount_out;
    }
    state.putAmmPool(pool);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Order

  Receipt TransactionExecutor::executeCreateOrder(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Structural validation. This is the same check the mempool
    //  runs on admission, applied again here so a block built from
    //  an unvalidated source cannot smuggle a malformed order into
    //  state.
    if (!validateCreateOrderStructure(tx))
      return failure;

    //  Re-parse the payload now that we know it is well-formed.
    //
    //  Layout:
    //    [4]  buy_token (LE)
    //    [8]  min_buy_amount (LE)
    //    [1]  mode
    //    [4]  pool_id (LE)
    //    [8]  expires_at_height (LE)
    //    [1]  condition_count
    //    [N]  conditions (13 bytes each)
    size_t off = 0;
    uint32_t buy_token = uint32_t(tx.payload[off]) |
                         (uint32_t(tx.payload[off + 1]) << 8) |
                         (uint32_t(tx.payload[off + 2]) << 16) |
                         (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t min_buy_amount = 0;
    for (int i = 0; i < 8; ++i)
      min_buy_amount |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t mode = tx.payload[off++];

    uint32_t pool_id = uint32_t(tx.payload[off]) |
                       (uint32_t(tx.payload[off + 1]) << 8) |
                       (uint32_t(tx.payload[off + 2]) << 16) |
                       (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t expires_at_height = 0;
    for (int i = 0; i < 8; ++i)
      expires_at_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t condition_count = tx.payload[off++];

    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      OrderCondition::deserializeState(
          tx.payload.data(), tx.payload.size(), off, conditions[i]);
    }

    Id sell_token = tx.token_id;
    uint64_t sell_amount = tx.amount;

    //  Allocate the order ID. The counter lives in the SMT under
    //  "next_order_id"; the same key Genesis writes.
    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_order_id", id_bytes);

    uint64_t next_id = 0;
    if (id_bytes.empty())
    {
      next_id = 1;
    }
    else
    {
      for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
      {
        next_id |= uint64_t(id_bytes[i]) << (i * 8);
      }
    }

    //  Build the order record.
    Order order;
    order.id = next_id;
    order.owner = tx.from;
    order.mode = static_cast<OrderExecutionMode>(mode);
    order.pool_id = pool_id;
    order.sell_token = sell_token;
    order.buy_token = buy_token;
    order.sell_amount = sell_amount;
    order.min_buy_amount = min_buy_amount;
    order.created_at_height = ctx.current_height;
    order.order_expires_at_height = expires_at_height;
    order.filled_amount = 0;
    order.condition_count = condition_count;
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      order.conditions[i] = conditions[i];
    }

    if (!order.isValid())
      return failure;

    //  Balance check. All other structural checks have already
    //  passed in validateCreateOrderStructure.
    if (sell_token == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < sell_amount)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, sell_token);
      if (bal < sell_amount)
        return failure;
    }

    //  ---- Pre-route validation for Active orders ----
    //
    //  An Active order with no conditions routes immediately on
    //  creation. If the pool is missing, closed, or does not
    //  contain the order's pair, the order can never fill and must
    //  be rejected. This check has to happen BEFORE the sell-token
    //  lock is taken and BEFORE the order record is written,
    //  because a failure after those points would leave state
    //  modified under a rejected transaction — the executor has no
    //  rollback primitive, so "modify then fail" is a leak.
    //
    //  Active orders WITH conditions do not route on creation; they
    //  wait for the epoch boundary. For them, the pool may not exist
    //  yet, or may be created later, so we do NOT pre-validate.
    if (order.mode == OrderExecutionMode::Active &&
        order.condition_count == 0)
    {
      AmmPool pool;
      if (!state.getAmmPool(order.pool_id, pool))
        return failure;
      if (!pool.active)
        return failure;

      const bool sells_a = (order.sell_token == pool.token_a &&
                            order.buy_token == pool.token_b);
      const bool sells_b = (order.sell_token == pool.token_b &&
                            order.buy_token == pool.token_a);
      if (!sells_a && !sells_b)
        return failure;

      if (pool.reserve_a == 0 || pool.reserve_b == 0)
        return failure;
    }

    //  ---- All checks passed. Apply state changes. ----

    //  Take the sell-token lock. Both the matcher and the router
    //  require the lock to be in place before they run.
    if (sell_token == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= sell_amount;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, sell_token);
      state.putTokenBalance(tx.from, sell_token, bal - sell_amount);
    }

    //  Persist the record. The matcher or the router may overwrite
    //  or delete it.
    state.putOrder(order);

    //  Execute.
    std::vector<Fill> fills;

    if (order.mode == OrderExecutionMode::Passive)
    {
      MatchOutcome outcome = matchPassiveOrder(
          state, order, ctx.current_height, ctx.tx_index_in_block);
      fills = std::move(outcome.fills);
    }
    else // Active
    {
      //  No conditions: route immediately against the order's pool.
      //  The pre-route validation above guarantees the pool is
      //  usable, so executeActiveOrder cannot return Unroutable for
      //  a structural reason. It can still return Rested if the
      //  pool's current price is unfavorable — that's fine, the
      //  order rests.
      //
      //  With conditions: leave the order in state. The condition
      //  evaluator, running at the next epoch boundary, will route
      //  it if the conditions hold or cancel it if they do not.
      if (order.condition_count == 0)
      {
        const auto outcome = BlockProcessor::executeActiveOrder(
            state, order, ctx.current_height, ctx.tx_index_in_block, fills);

        //  Defensive: the pre-route check should have caught any
        //  structural reason for Unroutable, but if the state
        //  changed between the check and here (it can't within a
        //  single tx, but the invariant is worth asserting),
        //  reject rather than leave a partially-applied state.
        if (outcome == ActiveRouteOutcome::Unroutable)
        {
          return failure;
        }

        //  Filled: fills already contains the fill(s).
        //  Rested: the order is in state with a remainder. The
        //  expiry index below will pick it up if it has one.
      }
    }

    //  Expiry index. Only if the order still exists after execution.
    //  A fully filled order was deleted by the matcher or the
    //  router, and indexing a deleted order would leave an expiry
    //  row pointing at nothing.
    Order still_exists;
    if (state.getOrder(order.id, still_exists) &&
        expires_at_height != 0)
    {
      state.addOrderExpiry(expires_at_height, order.id);
    }

    //  Bump the next-order-id counter. The counter is advanced once
    //  per successful CreateOrder, regardless of whether the order
    //  rested or executed.
    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_order_id", new_id_bytes);

    //  Receipt with fills.
    Receipt receipt{ReceiptStatus::Success, tx.fee};
    receipt.fills = std::move(fills);
    return receipt;
  }

  //  Cancel Order

  Receipt TransactionExecutor::executeCancelOrder(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8)
      return failure;

    uint64_t order_id = 0;
    for (int i = 0; i < 8; ++i)
      order_id |= uint64_t(tx.payload[i]) << (i * 8);

    Order order;
    if (!state.getOrder(order_id, order))
      return failure;
    if (order.owner != tx.from)
      return failure;

    uint64_t refund = order.remainingAmount();
    if (refund > 0)
    {
      if (order.sell_token == NATIVE_TOKEN_ID)
      {
        Account acct = state.getAccount(tx.from);
        acct.balance += refund;
        state.putAccount(tx.from, acct);
      }
      else
      {
        uint64_t bal = state.getTokenBalance(tx.from, order.sell_token);
        state.putTokenBalance(tx.from, order.sell_token, bal + refund);
      }
    }

    state.deleteRestingOrder(order);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create NFT Collection

  Receipt TransactionExecutor::executeCreateNftCollection(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [1]  name_len
    //    [N]  name
    //    [1]  symbol_len
    //    [M]  symbol
    //    [2]  uri_len (LE)
    //    [K]  base_uri
    //    [4]  reward_token_id (LE)   — 0 = no schedule
    //    [8]  reward_rate_per_epoch  — 0 if no schedule
    //    [8]  reward_escrow_amount   — funded from tx.from
    if (tx.payload.size() < 1)
      return failure;

    size_t off = 0;
    const uint8_t name_len = tx.payload[off++];
    if (off + name_len > tx.payload.size())
      return failure;
    std::string name(reinterpret_cast<const char *>(tx.payload.data() + off),
                     name_len);
    off += name_len;

    if (off + 1 > tx.payload.size())
      return failure;
    const uint8_t sym_len = tx.payload[off++];
    if (off + sym_len > tx.payload.size())
      return failure;
    std::string symbol(reinterpret_cast<const char *>(tx.payload.data() + off),
                       sym_len);
    off += sym_len;

    if (off + 2 > tx.payload.size())
      return failure;
    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len > tx.payload.size())
      return failure;
    std::string base_uri(
        reinterpret_cast<const char *>(tx.payload.data() + off), uri_len);
    off += uri_len;

    if (off + 4 + 8 + 8 > tx.payload.size())
      return failure;
    const Id reward_token_id = readU32At(tx.payload, off);
    off += 4;
    const uint64_t reward_rate_per_epoch = readU64At(tx.payload, off);
    off += 8;
    const uint64_t reward_escrow_amount = readU64At(tx.payload, off);
    off += 8;

    //  Allocate the collection id from the SMT global.
    uint64_t next_id = readU64GlobalInternal(state, "next_collection_id");
    if (next_id == 0)
      next_id = 1;

    Core::NftCollection c;
    c.id = next_id;
    c.creator = tx.from;
    c.name = std::move(name);
    c.symbol = std::move(symbol);
    c.base_uri = std::move(base_uri);
    c.reward_token_id = reward_token_id;
    c.reward_rate_per_epoch = reward_rate_per_epoch;
    c.created_at_height = ctx.current_height;

    if (!c.isValid())
      return failure;

    //  Fund the reward escrow from tx.from. The escrow is a
    //  balance at Keys::nftCollectionAddress(id). Debit tx.from
    //  and credit the escrow address in one atomic pair — if
    //  either fails, the tx fails and neither write persists.
    if (reward_escrow_amount > 0)
    {
      if (!debitToken(state, tx.from, reward_token_id, reward_escrow_amount))
        return failure;

      creditToken(state, State::Keys::nftCollectionAddress(c.id),
                  reward_token_id, reward_escrow_amount);
      c.reward_escrow_remaining = reward_escrow_amount;
    }

    state.putNftCollection(c);

    //  Bump the id counter.
    writeU64GlobalInternal(state, "next_collection_id", c.id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Mint NFT (standalone)

  Receipt TransactionExecutor::executeMintNft(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [8]  collection_id (LE)    — 0 = no collection
    //    [32] metadata_hash
    //    [1]  has_hash (0 or 1)
    //    [2]  uri_len (LE)
    //    [N]  uri
    if (tx.payload.size() < 8 + 32 + 1 + 2)
      return failure;

    size_t off = 0;
    const uint64_t collection_id = readU64At(tx.payload, off);
    off += 8;

    Crypto::Hash metadata_hash;
    std::memcpy(metadata_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint8_t has_hash = tx.payload[off++];
    if (has_hash > 1)
      return failure;
    if (has_hash == 0 && !metadata_hash.isNull())
      return failure;
    if (has_hash == 0)
      metadata_hash = Crypto::Hash{};

    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len > tx.payload.size())
      return failure;
    std::string uri(reinterpret_cast<const char *>(tx.payload.data() + off),
                    uri_len);
    off += uri_len;

    if (uri.size() > NFT_URI_MAX)
      return failure;

    //  Collection validation, if requested.
    Core::NftCollection collection;
    if (collection_id != 0)
    {
      if (!state.getNftCollection(collection_id, collection))
        return failure;
    }

    //  Allocate the NFT id from the shared token counter. The
    //  shadow token's id equals the NFT's id by construction, so
    //  there is no separate next_nft_id global and no collision
    //  class between user tokens and NFT shadows.
    uint64_t next_token_id = readU64GlobalInternal(state, "next_token_id");
    if (next_token_id == 0)
      next_token_id = 1;
    const uint64_t next_nft_id = next_token_id;

    //  The shadow token. maxSupply = 1, decimals = 0. name and
    //  symbol come from the collection if present, otherwise a
    //  per-NFT default. The creator is tx.from.
    Core::TokenInfo shadow;
    shadow.id = static_cast<Id>(next_nft_id);
    shadow.decimals = 0;
    shadow.maxSupply = 1;
    shadow.creator = tx.from;
    shadow.backing = Core::BackingModel::Unbacked;

    if (collection_id != 0)
    {
      shadow.name = collection.name + " #" + std::to_string(next_nft_id);
      shadow.symbol = collection.symbol;
    }
    else
    {
      shadow.name = "NFT #" + std::to_string(next_nft_id);
      shadow.symbol = "NFT";
    }

    if (!shadow.isValid())
      return failure;

    //  Mint the shadow token to tx.from. putToken records the
    //  metadata; putTokenBalance gives the creator the balance of 1.
    state.putToken(shadow);
    state.putTokenSupply(shadow.id, 1);
    state.putTokenBalance(tx.from, shadow.id, 1);

    //  Build and persist the NftInfo.
    Core::NftInfo nft;
    nft.id = next_nft_id;
    nft.owner = tx.from;
    nft.creator = tx.from;
    nft.shadow_token_id = shadow.id;
    nft.underlying_token_id = 0;
    nft.wrapped_amount = 0;
    nft.collection_id = collection_id;
    nft.metadata_hash = metadata_hash;
    nft.metadata_uri = std::move(uri);
    nft.last_accrual_height = ctx.current_height;
    nft.created_at_height = ctx.current_height;

    if (!nft.isValid())
      return failure;

    state.putNft(nft);

    //  Collection bookkeeping.
    if (collection_id != 0)
    {
      collection.minted_count += 1;
      state.putNftCollection(collection);
    }

    writeU64GlobalInternal(state, "next_token_id", nft.id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Wrap NFT

  Receipt TransactionExecutor::executeWrapNft(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [4]  underlying_token_id (LE)
    //    [8]  wrapped_amount (LE)
    //    [8]  collection_id (LE)    — 0 = no collection
    //    [32] metadata_hash
    //    [1]  has_hash
    //    [2]  uri_len
    //    [N]  uri
    if (tx.payload.size() < 4 + 8 + 8 + 32 + 1 + 2)
      return failure;

    size_t off = 0;
    const Id underlying_token_id = readU32At(tx.payload, off);
    off += 4;
    const uint64_t wrapped_amount = readU64At(tx.payload, off);
    off += 8;
    const uint64_t collection_id = readU64At(tx.payload, off);
    off += 8;

    Crypto::Hash metadata_hash;
    std::memcpy(metadata_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint8_t has_hash = tx.payload[off++];
    if (has_hash > 1)
      return failure;
    if (has_hash == 0 && !metadata_hash.isNull())
      return failure;
    if (has_hash == 0)
      metadata_hash = Crypto::Hash{};

    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len > tx.payload.size())
      return failure;
    std::string uri(reinterpret_cast<const char *>(tx.payload.data() + off),
                    uri_len);

    if (underlying_token_id == 0)
      return failure;
    if (wrapped_amount == 0)
      return failure;
    if (uri.size() > NFT_URI_MAX)
      return failure;

    //  Collection validation.
    Core::NftCollection collection;
    if (collection_id != 0)
    {
      if (!state.getNftCollection(collection_id, collection))
        return failure;
    }

    //  Allocate the NFT id from the shared token counter. The
    //  shadow token's id equals the NFT's id by construction.
    uint64_t next_token_id = readU64GlobalInternal(state, "next_token_id");
    if (next_token_id == 0)
      next_token_id = 1;
    const uint64_t next_nft_id = next_token_id;

    //  Underlying cannot be the NFT's own shadow token.
    if (underlying_token_id == next_nft_id)
      return failure;

    //  Build the shadow token.
    Core::TokenInfo shadow;
    shadow.id = static_cast<Id>(next_nft_id);
    shadow.decimals = 0;
    shadow.maxSupply = 1;
    shadow.creator = tx.from;
    shadow.backing = Core::BackingModel::Unbacked;

    if (collection_id != 0)
    {
      shadow.name = collection.name + " #" + std::to_string(next_nft_id);
      shadow.symbol = collection.symbol;
    }
    else
    {
      shadow.name = "NFT #" + std::to_string(next_nft_id);
      shadow.symbol = "NFT";
    }

    if (!shadow.isValid())
      return failure;

    //  Take custody of the underlying. Debit tx.from, credit the
    //  NFT's virtual address. Both happen in this transaction or
    //  neither does.
    if (!debitToken(state, tx.from, underlying_token_id, wrapped_amount))
      return failure;

    const Crypto::Address custody = State::Keys::nftAddress(next_nft_id);
    creditToken(state, custody, underlying_token_id, wrapped_amount);

    //  Mint the shadow token.
    state.putToken(shadow);
    state.putTokenSupply(shadow.id, 1);
    state.putTokenBalance(tx.from, shadow.id, 1);

    //  Build and persist the NftInfo.
    Core::NftInfo nft;
    nft.id = next_nft_id;
    nft.owner = tx.from;
    nft.creator = tx.from;
    nft.shadow_token_id = shadow.id;
    nft.underlying_token_id = underlying_token_id;
    nft.wrapped_amount = wrapped_amount;
    nft.collection_id = collection_id;
    nft.metadata_hash = metadata_hash;
    nft.metadata_uri = std::move(uri);
    nft.last_accrual_height = ctx.current_height;
    nft.created_at_height = ctx.current_height;

    if (!nft.isValid())
      return failure;

    state.putNft(nft);

    if (collection_id != 0)
    {
      collection.minted_count += 1;
      state.putNftCollection(collection);
    }

    writeU64GlobalInternal(state, "next_token_id", nft.id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Transfer NFT

  Receipt TransactionExecutor::executeTransferNft(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [8]  nft_id (LE)
    //    [32] new_owner
    if (tx.payload.size() != 8 + 32)
      return failure;

    const uint64_t nft_id = readU64At(tx.payload, 0);
    Crypto::Address new_owner;
    std::memcpy(new_owner.data.data(), tx.payload.data() + 8, 32);

    if (new_owner.isNull())
      return failure;

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.owner != tx.from)
      return failure;

    if (nft.owner == new_owner)
      return failure; // no-op transfer

    //  Settle accrued rewards to the current owner before the
    //  transfer. The NFT's last_accrual_height is reset so the
    //  buyer starts accruing from this height.
    if (nft.collection_id != 0)
    {
      Core::NftCollection collection;
      if (state.getNftCollection(nft.collection_id, collection) &&
          collection.hasReward())
      {
        const uint64_t accrued =
            (ctx.current_height - nft.last_accrual_height) /
            ROTATION_INTERVAL * collection.reward_rate_per_epoch;

        if (accrued > 0)
        {
          Core::Account acct = state.getAccount(nft.owner);
          acct.pending_rewards += accrued;
          state.putAccount(nft.owner, acct);
        }
      }
    }

    //  Move the shadow token balance from the seller to the buyer.
    //  This is a normal token transfer under the shadow token's id.
    const uint64_t shadow_balance =
        state.getTokenBalance(nft.owner, nft.shadow_token_id);
    if (shadow_balance < 1)
      return failure; // invariant violation

    state.putTokenBalance(nft.owner, nft.shadow_token_id,
                          shadow_balance - 1);

    const uint64_t buyer_balance =
        state.getTokenBalance(new_owner, nft.shadow_token_id);
    state.putTokenBalance(new_owner, nft.shadow_token_id,
                          buyer_balance + 1);

    //  Unindex the old owner's row before rewriting the record.
    //  putNft no longer does this itself: a read inside a write
    //  path interleaves with the SMT's pending-update state, which
    //  is what caused the reward-pass update in a subsequent txn
    //  to be lost. The read here is safe because it's the same
    //  record we just read at the top of the handler, and we're
    //  passing it as data, not re-reading through the SMT.
    state.unindexNft(nft);

    //  Update the NftInfo. Owner changes; custody stays at the
    //  NFT's virtual address (the custody is a property of the
    //  NFT, not of the owner). Wrapped_amount unchanged. Metadata
    //  unchanged.
    nft.owner = new_owner;
    nft.last_accrual_height = ctx.current_height;
    nft.accrued_owed = 0; // settled above

    state.putNft(nft);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Burn NFT

  Receipt TransactionExecutor::executeBurnNft(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 8)
      return failure;

    const uint64_t nft_id = readU64At(tx.payload, 0);

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.owner != tx.from)
      return failure;

    //  Settle accrued rewards to the owner before burning, same
    //  as a transfer.
    if (nft.collection_id != 0)
    {
      Core::NftCollection collection;
      if (state.getNftCollection(nft.collection_id, collection) &&
          collection.hasReward())
      {
        const uint64_t accrued =
            (ctx.current_height - nft.last_accrual_height) /
            ROTATION_INTERVAL * collection.reward_rate_per_epoch;

        if (accrued > 0)
        {
          Core::Account acct = state.getAccount(nft.owner);
          acct.pending_rewards += accrued;
          state.putAccount(nft.owner, acct);
        }
      }
    }

    //  Burn the shadow token from the owner's balance.
    const uint64_t shadow_balance =
        state.getTokenBalance(nft.owner, nft.shadow_token_id);
    if (shadow_balance < 1)
      return failure;

    state.putTokenBalance(nft.owner, nft.shadow_token_id,
                          shadow_balance - 1);
    state.putTokenSupply(nft.shadow_token_id, 0);

    //  For a wrapped NFT, release the custody back to the owner.
    //  For a standalone NFT, there is no custody to release.
    if (nft.isWrapped() && nft.wrapped_amount > 0)
    {
      const Crypto::Address custody = State::Keys::nftAddress(nft_id);
      if (!debitToken(state, custody, nft.underlying_token_id,
                      nft.wrapped_amount))
      {
        return failure; // invariant violation: custody is missing
      }

      creditToken(state, nft.owner, nft.underlying_token_id,
                  nft.wrapped_amount);
    }

    //  Delete the NFT record and its indexes.
    state.deleteNft(nft_id);

    //  Collection bookkeeping. A burn reduces minted_count, so the
    //  reward schedule sizes its per-epoch obligation correctly.
    if (nft.collection_id != 0)
    {
      Core::NftCollection collection;
      if (state.getNftCollection(nft.collection_id, collection))
      {
        if (collection.minted_count > 0)
          collection.minted_count -= 1;
        state.putNftCollection(collection);
      }
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Update NFT Metadata

  Receipt TransactionExecutor::executeUpdateNftMetadata(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [8]  nft_id (LE)
    //    [32] metadata_hash
    //    [1]  has_hash
    //    [2]  uri_len
    //    [N]  uri
    //    [1]  freeze (0 or 1)
    if (tx.payload.size() < 8 + 32 + 1 + 2)
      return failure;

    size_t off = 0;
    const uint64_t nft_id = readU64At(tx.payload, off);
    off += 8;

    Crypto::Hash new_hash;
    std::memcpy(new_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint8_t has_hash = tx.payload[off++];
    if (has_hash > 1)
      return failure;
    if (has_hash == 0)
      new_hash = Crypto::Hash{};

    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len + 1 > tx.payload.size())
      return failure;

    std::string new_uri(
        reinterpret_cast<const char *>(tx.payload.data() + off), uri_len);
    off += uri_len;

    const uint8_t freeze = tx.payload[off];

    if (freeze > 1)
      return failure;
    if (new_uri.size() > NFT_URI_MAX)
      return failure;

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.owner != tx.from)
      return failure;
    if (nft.frozen)
      return failure;

    nft.metadata_hash = new_hash;
    nft.metadata_uri = std::move(new_uri);
    if (freeze == 1)
      nft.frozen = true;

    if (!nft.isValid())
      return failure;

    state.putNft(nft);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Top Up NFT

  Receipt TransactionExecutor::executeTopUpNft(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [8]  nft_id (LE)
    //    [4]  token_id (LE)
    //    [8]  amount (LE)
    if (tx.payload.size() != 8 + 4 + 8)
      return failure;

    const uint64_t nft_id = readU64At(tx.payload, 0);
    const Id token_id = readU32At(tx.payload, 8);
    const uint64_t amount = readU64At(tx.payload, 12);

    if (amount == 0)
      return failure;

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    //  For a wrapped NFT, the top-up must be the underlying token.
    //  For a standalone NFT, any token is accepted — the gift is
    //  real custody, and a holder who later wraps the NFT to that
    //  token will find the balance already there.
    if (nft.isWrapped() && token_id != nft.underlying_token_id)
      return failure;

    if (!debitToken(state, tx.from, token_id, amount))
      return failure;

    const Crypto::Address custody = State::Keys::nftAddress(nft_id);
    creditToken(state, custody, token_id, amount);

    //  Update the NFT's recorded wrapped amount only when the
    //  top-up matches the NFT's underlying. A standalone NFT
    //  receiving a gift of an arbitrary token doesn't change its
    //  wrapped_amount, because wrapped_amount is meaningful only
    //  for wrapped NFTs.
    if (nft.isWrapped() && token_id == nft.underlying_token_id)
    {
      nft.wrapped_amount += amount;
      state.putNft(nft);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Claim NFT Reward

  Receipt TransactionExecutor::executeClaimNftReward(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (!tx.payload.empty())
      return failure;

    //  Walk every NFT owned by tx.from. For each NFT in a
    //  reward-bearing collection, compute the accrual since the
    //  last settlement and credit tx.from's pending_rewards.
    //
    //  The walk is bounded by the number of NFTs the caller owns.
    //  A holder with 10,000 NFTs pays 10,000 SMT writes to claim;
    //  that's a tax on large holders but not a chain-wide cost.

    Core::Account acct = state.getAccount(tx.from);
    uint64_t total_claimed = 0;

    state.forEachNftForOwner(tx.from,
                             [&](const Core::NftInfo &nft)
                             {
                               if (nft.collection_id == 0)
                                 return;

                               Core::NftCollection collection;
                               if (!state.getNftCollection(nft.collection_id, collection))
                                 return;

                               if (!collection.hasReward())
                                 return;

                               const uint64_t accrued =
                                   (ctx.current_height - nft.last_accrual_height) /
                                   ROTATION_INTERVAL * collection.reward_rate_per_epoch;

                               if (accrued == 0)
                                 return;

                               total_claimed += accrued;

                               //  Reset the NFT's accrual clock. The escrow was
                               //  decremented at the epoch boundary; the claim just
                               //  settles the pending amount to the holder.
                               Core::NftInfo updated = nft;
                               updated.last_accrual_height = ctx.current_height;
                               updated.accrued_owed = 0;
                               state.putNft(updated);
                             });

    if (total_claimed > 0)
    {
      acct.pending_rewards += total_claimed;
      state.putAccount(tx.from, acct);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Refill Collection Reward

  Receipt TransactionExecutor::executeRefillCollectionReward(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload layout:
    //    [8]  collection_id (LE)
    //    [8]  amount (LE)
    if (tx.payload.size() != 16)
      return failure;

    const uint64_t collection_id = readU64At(tx.payload, 0);
    const uint64_t amount = readU64At(tx.payload, 8);

    if (amount == 0)
      return failure;

    Core::NftCollection collection;
    if (!state.getNftCollection(collection_id, collection))
      return failure;

    if (!collection.hasReward())
      return failure;

    //  Only the creator can refill. A third party topping up
    //  someone else's escrow is a gift, but it's a policy the
    //  creator should opt into explicitly, not have happen by
    //  accident. Reject for now; a "gift to collection" op is a
    //  follow-up if there's demand.
    if (collection.creator != tx.from)
      return failure;

    if (!debitToken(state, tx.from, collection.reward_token_id, amount))
      return failure;

    creditToken(state, State::Keys::nftCollectionAddress(collection_id),
                collection.reward_token_id, amount);

    collection.reward_escrow_remaining += amount;

    //  Un-pause if the refill restores the escrow.
    if (collection.reward_paused && collection.reward_escrow_remaining > 0)
      collection.reward_paused = false;

    state.putNftCollection(collection);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — shared verifiers
  //  =========================================================================
  //
  //  Two verifier flavors:
  //
  //    verifyBridgeSignatures    — operational attestations (mint,
  //                                ack). Signs against the active
  //                                watcher set for a source chain.
  //                                Threshold is bftQuorum(active_watchers).
  //
  //    verifyGovernanceSignatures — governance decisions (pause,
  //                                 unpause, register-chain). Signs
  //                                 against the active validator set.
  //                                 Threshold is bftQuorum(active_validators).
  //
  //  Both accept the same `[2] count || N*66` signature block. The
  //  only difference is which set the signer_index resolves against.

  bool TransactionExecutor::verifyBridgeSignatures(
      State::StateAccess &state,
      uint64_t source_chain_id,
      std::string_view domain,
      const uint8_t *message, size_t message_len,
      const uint8_t *signatures, size_t signatures_len,
      const TxExecutionContext &ctx)
  {
    if (domain.size() != 4)
      return false;

    //  Resolve the active watcher set at this height. The
    //  accessor returns each watcher's full record, filtered by
    //  isInActiveSet(height).
    std::vector<Core::BridgeWatcherInfo> active;
    state.forEachActiveBridgeWatcherForChain(
        source_chain_id, ctx.current_height,
        [&](const Core::BridgeWatcherInfo &w)
        { active.push_back(w); });

    //  Sort by watcher id so signer_index is deterministic across
    //  nodes. The owner-address index iteration is hash-ordered,
    //  not id-ordered, so a caller that builds a signature block
    //  with `signer_index = position in the active set` needs the
    //  set to be in the same order on the verifier.
    std::sort(active.begin(), active.end(),
              [](const Core::BridgeWatcherInfo &a,
                 const Core::BridgeWatcherInfo &b)
              { return a.id < b.id; });

    //  Chain registration must be present; it carries the
    //  per-chain minimum active-watcher count.
    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return false;
    if (active.size() < reg.active_watcher_min)
      return false;

    const size_t threshold = Core::bftQuorum(active.size());

    std::vector<BridgeSignatureEntry> sigs;
    if (!parseBridgeSignatureBlock(signatures, signatures_len, sigs))
      return false;

    if (sigs.size() < threshold)
      return false;

    std::vector<bool> seen(active.size(), false);
    for (const auto &e : sigs)
    {
      if (e.signer_index >= active.size())
        return false;
      if (seen[e.signer_index])
        return false;
      seen[e.signer_index] = true;
    }

    const Crypto::Hash hash =
        bridgeSigningHash(domain, message, message_len);

    for (const auto &e : sigs)
    {
      const Id validator_id = active[e.signer_index].validator_id;
      auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
      if (!pk.has_value())
      {
        return false;
      }
      const bool ok = Crypto::verify(hash, *pk, e.signature);
      if (!ok)
        return false;
    }

    return true;
  }

  bool TransactionExecutor::verifyGovernanceSignatures(
      State::StateAccess &state,
      std::string_view domain,
      const uint8_t *message, size_t message_len,
      const uint8_t *signatures, size_t signatures_len,
      const TxExecutionContext &ctx)
  {
    if (domain.size() != 4)
    {
      return false;
    }

    std::vector<Id> active = loadActiveSet(state);
    std::sort(active.begin(), active.end());

    if (active.empty())
      return false;

    const size_t threshold = Core::bftQuorum(active.size());

    std::vector<BridgeSignatureEntry> sigs;
    if (!parseBridgeSignatureBlock(signatures, signatures_len, sigs))
    {
      return false;
    }

    if (sigs.size() < threshold)
      return false;

    std::vector<bool> seen(active.size(), false);
    for (const auto &e : sigs)
    {
      if (e.signer_index >= active.size())
        return false;
      if (seen[e.signer_index])
        return false;
      seen[e.signer_index] = true;
    }

    const Crypto::Hash hash =
        bridgeSigningHash(domain, message, message_len);

    for (const auto &e : sigs)
    {
      const Id validator_id = active[e.signer_index];

      auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
      if (!pk.has_value())
      {
        return false;
      }

      const bool ok = Crypto::verify(hash, *pk, e.signature);
      if (!ok)
        return false;
    }

    return true;
  }

  //  =========================================================================
  //  Bridge — BridgeMint
  //  =========================================================================
  //
  //  Payload layout (little-endian):
  //    [8]  source_chain_id
  //    [32] source_tx_hash
  //    [4]  source_output_index
  //    [32] destination_address
  //    [8]  amount                 — Clarity atomic units
  //    [2]  signer_count           — LE
  //    [N]  signatures             — each: [2] index LE || [64] sig
  //
  //  The signature block covers the mint message built by
  //  encodeBridgeMintMessage. Signatures verify against the active
  //  bridge watcher set for `source_chain_id` at `ctx.current_height`,
  //  with threshold bftQuorum(active_watchers).
  //
  //  Mint checks, in order:
  //    1. Bridge not paused.
  //    2. Source chain registered and enabled.
  //    3. Wrapped token exists and its fingerprint matches.
  //    4. Deposit not already consumed.
  //    5. Watcher signatures verify (active set, threshold, replay).
  //    6. Mint to destination, write consumed-deposit record,
  //       bump consumed count.
  //
  //  All failure modes return a Failure receipt; no state is
  //  modified until every check passes.

  Receipt TransactionExecutor::executeBridgeMint(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload minimum: the fixed fields before the signature block.
    if (tx.payload.size() < 8 + 32 + 4 + 32 + 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    Crypto::Hash source_tx_hash;
    std::memcpy(source_tx_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint32_t source_output_index = readU32At(tx.payload, off);
    off += 4;

    Crypto::Address destination;
    std::memcpy(destination.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint64_t amount = readU64At(tx.payload, off);
    off += 8;

    //  The signature block, including its 2-byte count, is the
    //  remainder of the payload. parseBridgeSignatureBlock expects
    //  the count at data[0], so do NOT advance `off` past it here.
    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    //  Peek at the count without consuming it, purely to bound-check.
    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    if (amount == 0)
      return failure;
    if (destination.isNull())
      return failure;

    //  Global bridge pause.
    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    //  Chain registration.
    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    //  Wrapped token fingerprint.
    Core::TokenInfo token;
    if (!state.getToken(reg.wrapped_token_id, token))
      return failure;
    if (!token.isBridged() ||
        !token.fingerprint.has_value() ||
        *token.fingerprint != reg.fingerprint)
      return failure;

    //  Replay guard: the deposit must not have been minted before.
    uint64_t existing_mint_height = 0;
    if (state.getBridgeConsumed(source_chain_id, source_tx_hash,
                                source_output_index, existing_mint_height))
      return failure;

    //  Build the message the federation signed, and verify.
    const std::vector<uint8_t> message = encodeBridgeMintMessage(
        source_chain_id, source_tx_hash, source_output_index,
        destination, amount);

    if (!verifyBridgeSignatures(
            state, source_chain_id, "bmin",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    //  All checks passed. Apply state changes.

    //  Mint to the destination.
    const uint64_t existing_balance =
        state.getTokenBalance(destination, reg.wrapped_token_id);
    state.putTokenBalance(destination, reg.wrapped_token_id,
                          existing_balance + amount);

    //  Bump the wrapped token's supply.
    const uint64_t supply = state.getTokenSupply(reg.wrapped_token_id);
    state.putTokenSupply(reg.wrapped_token_id, supply + amount);

    //  Consumed-deposit record.
    state.putBridgeConsumed(source_chain_id, source_tx_hash,
                            source_output_index, ctx.current_height);

    //  Aggregate counter.
    GlobalStateWriter writer(state);
    writer.setBridgeConsumedCount(reader.bridgeConsumedCount() + 1);

    //  Aggregate stats.
    bumpBridgeStats(state, source_chain_id, ctx.current_height,
                    /*minted*/ amount, /*burned*/ 0, /*released*/ 0,
                    /*count_deposit*/ true,
                    /*count_withdrawal*/ false,
                    /*count_release*/ false);

    recordBridgeEvent(state, Core::BridgeEventKind::Mint,
                      source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/source_tx_hash,
                      /*has_source=*/true,
                      /*source_output_index=*/source_output_index,
                      /*withdrawal_id=*/0,
                      /*amount=*/amount,
                      /*counterparty=*/0);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — BridgeBurn
  //  =========================================================================
  //
  //  Payload layout:
  //    [8]  source_chain_id
  //    [1]  blob_len
  //    [N]  destination_blob      — N == blob_len
  //    [8]  amount                — Clarity atomic units
  //
  //  No signature block. A burn is authorized by the user's own
  //  signature over the tx's signing hash; the standard pipeline
  //  verifies it before dispatch.
  //
  //  No watcher-set check either. Whether the watcher set can
  //  currently mint is a mint-time concern; a burn just queues a
  //  withdrawal. The withdrawal record is durable even if the
  //  watcher set is temporarily below threshold, so the release
  //  will happen once the set recovers. This asymmetry is
  //  deliberate: a fake mint steals value, a burn doesn't.

  Receipt TransactionExecutor::executeBridgeBurn(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 1 + 8)
      return failure;

    size_t off = 0;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    const uint8_t blob_len = tx.payload[off];
    off += 1;

    //  Minimum payload: source_chain_id(8) + blob_len(1) +
    //  destination_blob(blob_len) + addr_len(1) +
    //  destination_address(addr_len) + amount(8).
    if (tx.payload.size() < off + blob_len + 1 + 8)
      return failure;

    std::vector<uint8_t> destination_blob(blob_len);
    if (blob_len > 0)
    {
      std::memcpy(destination_blob.data(), tx.payload.data() + off, blob_len);
      off += blob_len;
    }

    const uint8_t addr_len = tx.payload[off];
    off += 1;

    if (tx.payload.size() != off + addr_len + 8)
      return failure;

    std::string destination_address;
    if (addr_len > 0)
    {
      destination_address.assign(
          reinterpret_cast<const char *>(tx.payload.data() + off), addr_len);
      off += addr_len;
    }

    const uint64_t amount = readU64At(tx.payload, off);

    if (amount == 0)
      return failure;
    if (destination_address.empty())
      return failure;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    if (tx.token_id != reg.wrapped_token_id)
      return failure;

    if (blob_len < reg.destination_blob_min_len ||
        blob_len > reg.destination_blob_max_len)
      return failure;

    const uint64_t balance = state.getTokenBalance(tx.from, tx.token_id);
    if (balance < amount)
      return failure;

    //  ---- Apply ----

    state.putTokenBalance(tx.from, tx.token_id, balance - amount);

    const uint64_t supply = state.getTokenSupply(tx.token_id);
    state.putTokenSupply(tx.token_id,
                         supply >= amount ? supply - amount : 0);

    uint64_t next_id = reader.bridgeNextWithdrawalId();
    if (next_id == 0)
      next_id = 1;

    Core::BridgeWithdrawal w;
    w.id = next_id;
    w.source_chain_id = source_chain_id;
    w.wrapped_token_id = tx.token_id;
    w.burner = tx.from;
    w.amount = amount;
    w.destination_blob = std::move(destination_blob);
    w.destination_address = std::move(destination_address);
    w.created_at_height = ctx.current_height;

    if (!w.isWellFormed())
      return failure;

    state.putBridgeWithdrawal(w);

    GlobalStateWriter writer(state);
    writer.setBridgeNextWithdrawalId(next_id + 1);
    writer.setBridgeWithdrawalsPending(reader.bridgeWithdrawalsPending() + 1);

    bumpBridgeStats(state, source_chain_id, ctx.current_height,
                    /*minted*/ 0, /*burned*/ amount, /*released*/ 0,
                    /*count_deposit*/ false,
                    /*count_withdrawal*/ true,
                    /*count_release*/ false);

    recordBridgeEvent(state, Core::BridgeEventKind::Burn,
                      source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/Crypto::Hash{},
                      /*has_source=*/false,
                      /*source_output_index=*/0,
                      /*withdrawal_id=*/w.id,
                      /*amount=*/amount,
                      /*counterparty=*/0);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — Pause / Unpause (governance)
  //  =========================================================================
  //
  //  Payload layout (both):
  //    [8]  current_height        — binds the pause to a specific
  //                                 height, prevents a signature
  //                                 harvested from one pause from
  //                                 being replayed at a different
  //                                 height
  //    [2]  signer_count          — LE
  //    [N]  signatures            — governance signatures
  //
  //  Message:
  //    Blake2b("bpau" || LE64(current_height))   — for pause
  //    Blake2b("bunp"  || LE64(current_height))   — for unpause
  //
  //  Governance signatures verify against the active validator set,
  //  with bftQuorum threshold. The operational watcher set has no
  //  authority to freeze or unfreeze the bridge.

  Receipt TransactionExecutor::executeBridgePause(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t bound_height = 0;
    for (int i = 0; i < 8; ++i)
      bound_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    //  The signature block, including its 2-byte count, is the
    //  remainder of the payload. parseBridgeSignatureBlock expects
    //  the count at data[0], so do NOT advance `off` past it here.
    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    //  Build the signed message.
    std::vector<uint8_t> message;
    message.reserve(8);
    for (int i = 0; i < 8; ++i)
      message.push_back(uint8_t(bound_height >> (i * 8)));

    if (!verifyGovernanceSignatures(
            state, "bpau",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    //  Apply.
    GlobalStateWriter writer(state);
    writer.setBridgePaused(true);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeBridgeUnpause(State::StateAccess &state,
                                                    const Transaction &tx,
                                                    const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t bound_height = 0;
    for (int i = 0; i < 8; ++i)
      bound_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    //  The signature block, including its 2-byte count, is the
    //  remainder of the payload. parseBridgeSignatureBlock expects
    //  the count at data[0], so do NOT advance `off` past it here.
    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    std::vector<uint8_t> message;
    message.reserve(8);
    for (int i = 0; i < 8; ++i)
      message.push_back(uint8_t(bound_height >> (i * 8)));

    if (!verifyGovernanceSignatures(
            state, "bunp",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    GlobalStateWriter writer(state);
    writer.setBridgePaused(false);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — AckWithdrawal
  //  =========================================================================
  //
  //  Payload layout:
  //    [8]  withdrawal_id
  //    [32] release_tx_hash        — the source-chain (CCX) tx hash
  //    [8]  release_height         — the source-chain block height
  //    [2]  signer_count           — LE
  //    [N]  signatures             — operational watcher signatures
  //
  //  Message:
  //    Blake2b("back" || LE64(withdrawal_id))
  //
  //  The message is deliberately UNCHANGED from the pre-Phase-3
  //  form. The release_tx_hash and release_height are not covered
  //  by the watcher signatures — they are attestation data that
  //  the submitting watcher provides, cross-checked against
  //  CCX on-chain (payment ID), not against the signatures. The
  //  signatures authorize "release withdrawal N"; the hash and
  //  height record "the release was tx H at height X". Anyone can
  //  verify the latter independently.
  //
  //  The ack is watcher-signed against the operational set for the
  //  withdrawal's chain — the same set that signs mints. The chain
  //  is resolved from the withdrawal record, not from the payload.
  //
  //  On success:
  //    - the withdrawal record's release_* fields are populated;
  //    - the record is NOT deleted (it is the permanent audit trail);
  //    - the height index row is updated (the record drops out of
  //      the unreleased scan by virtue of isReleased());
  //    - the pending counter is decremented;
  //    - BridgeStats.total_released += w.amount, release counters ++.

  Receipt TransactionExecutor::executeBridgeAckWithdrawal(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Minimum: id(8) + release_hash(32) + release_height(8) + count(2)
    if (tx.payload.size() < 8 + 32 + 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t withdrawal_id = 0;
    for (int i = 0; i < 8; ++i)
      withdrawal_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    Crypto::Hash release_tx_hash;
    std::memcpy(release_tx_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint64_t release_height = readU64At(tx.payload, off);
    off += 8;

    //  The signature block, including its 2-byte count, is the
    //  remainder of the payload.
    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    //  Peek at the count without consuming it, purely to bound-check.
    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    if (release_tx_hash.isNull())
      return failure;
    if (release_height == 0)
      return failure;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeWithdrawal w;
    if (!state.getBridgeWithdrawal(withdrawal_id, w))
      return failure;
    if (!w.isWellFormed())
      return failure;

    //  Idempotency / conflict:
    //    - already released with the SAME hash  → no-op success
    //    - already released with a DIFFERENT hash → reject
    if (w.isReleased())
    {
      if (w.release_tx_hash == release_tx_hash &&
          w.release_height == release_height)
      {
        return {ReceiptStatus::Success, tx.fee};
      }
      return failure;
    }

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(w.source_chain_id, reg))
      return failure;

    //  Message: the withdrawal id.
    const std::vector<uint8_t> message = encodeBridgeAckMessage(withdrawal_id);

    if (!verifyBridgeSignatures(
            state, w.source_chain_id, "back",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    //  Apply: populate the release audit fields in place. The
    //  record stays in state — it is the permanent audit trail.
    w.release_tx_hash = release_tx_hash;
    w.release_height = release_height;
    w.released_at_height = ctx.current_height;
    state.putBridgeWithdrawal(w);

    //  Attribute the release to the submitting watcher, if the
    //  sender is a registered watcher for this chain. It usually
    //  is; if not (someone relaying a peer's release), leave 0.
    {
      uint64_t watcher_id = 0;
      if (state.getBridgeWatcherIdByAddress(tx.from, watcher_id))
      {
        Core::BridgeWatcherInfo wi;
        if (state.getBridgeWatcher(watcher_id, wi) &&
            wi.source_chain_id == w.source_chain_id)
        {
          w.released_by_watcher_id = watcher_id;
        }
      }
    }

    if (!w.isWellFormed())
      return failure;

    //  Rewrite the record in place. putBridgeWithdrawal reindexes
    //  the height row; the record is now isReleased() and so drops
    //  out of forEachUnreleasedBridgeWithdrawal.
    state.putBridgeWithdrawal(w);

    GlobalStateWriter writer(state);
    const uint64_t pending = reader.bridgeWithdrawalsPending();
    writer.setBridgeWithdrawalsPending(pending > 0 ? pending - 1 : 0);

    //  Aggregate stats.
    bumpBridgeStats(state, w.source_chain_id, ctx.current_height,
                    /*minted*/ 0, /*burned*/ 0, /*released*/ w.amount,
                    /*count_deposit*/ false,
                    /*count_withdrawal*/ false,
                    /*count_release*/ true);

    recordBridgeEvent(state, Core::BridgeEventKind::AckWithdrawal,
                      w.source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/Crypto::Hash{},
                      /*has_source=*/false,
                      /*source_output_index=*/0,
                      /*withdrawal_id=*/withdrawal_id,
                      /*amount=*/w.amount,
                      /*counterparty=*/release_height);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — RegisterChain (governance)
  //  =========================================================================
  //
  //  Payload layout:
  //    [1]  registration_len      — LE (1 byte)
  //    [N]  registration_blob     — BridgeChainRegistration::serializeState()
  //    [2]  signer_count
  //    [N]  signatures            — governance signatures
  //
  //  The signature covers the registration blob, so the signers
  //  commit to the exact bytes that will be stored.

  Receipt TransactionExecutor::executeBridgeRegisterChain(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 1 + 2)
      return failure;

    size_t off = 0;

    const uint8_t reg_len = tx.payload[off];
    off += 1;

    if (off + reg_len + 2 > tx.payload.size())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!Core::BridgeChainRegistration::deserializeState(
            tx.payload.data() + off, reg_len, reg))
      return failure;
    off += reg_len;

    //  The signature block, including its 2-byte count, is the
    //  remainder of the payload. parseBridgeSignatureBlock expects
    //  the count at data[0], so do NOT advance `off` past it here.
    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    //  The message covered by the signatures is the registration
    //  blob (from the payload) — which is what will be written.
    const uint8_t *msg_ptr = tx.payload.data() + 1; // skip len prefix
    const size_t msg_len = reg_len;

    if (!verifyGovernanceSignatures(
            state, "brgr",
            msg_ptr, msg_len,
            sigs_ptr, sigs_len, ctx))
      return failure;

    //  Reject if a registration already exists for this chain id
    //  (registrations are immutable; to change one, deregister and
    //  re-register, or use a future "update" transaction).
    Core::BridgeChainRegistration existing;
    if (state.getBridgeChainRegistration(reg.source_chain_id, existing))
      return failure;

    state.putBridgeChainRegistration(reg);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — BridgeAttest
  //  =========================================================================
  //
  //  Payload layout:
  //    [8]  source_chain_id
  //    [32] source_tx_hash
  //    [4]  source_output_index
  //    [32] destination_address
  //    [8]  amount
  //    [2]  signer_index (LE, position in sorted active watcher set)
  //    [64] signature (ed25519 over the canonical mint message)
  //
  //  Total: 8 + 32 + 4 + 32 + 8 + 2 + 64 = 150 bytes, exact.
  //
  //  Each active watcher submits one BridgeAttest per deposit. The
  //  transaction records the attestation in TBL_BRIDGE_ATTESTATIONS.
  //  The submission assembler later reads the attestations back,
  //  verifies that they form a quorum and agree on (destination,
  //  amount), and assembles the [2] count || N*66 block that a
  //  BridgeMint transaction carries.
  //
  //  The executor's job is to validate *one* attestation in
  //  isolation:
  //    - the bridge is not paused;
  //    - the chain is registered and enabled;
  //    - the deposit is not already consumed (minting already
  //      happened; attesting to it is pointless);
  //    - the signer_index is within the active watcher set;
  //    - the resolved consensus key at ctx.current_height signs
  //      the canonical message;
  //    - no other attestation exists for the same (deposit,
  //      validator_id) — resubmission is rejected;
  //    - no other attestation exists for the same deposit with a
  //      *different* (destination, amount) — this would be a
  //      federation split and must not be silently recorded.
  //
  //  The last check is the important one. The executor does not
  //  know which of two conflicting attestations is "the truth" —
  //  both are signed by legitimate watchers. It refuses to record
  //  the second, and the deposit never gets minted until the
  //  federation resolves the conflict offline (a slash + a fresh
  //  attestation, or a governance action). That's the correct
  //  shape: silently picking one side would make the bridge a
  //  silent authority over federation disputes.

  Receipt TransactionExecutor::executeBridgeAttest(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    std::cerr << "[attest] ==== executeBridgeAttest ====\n";
    std::cerr << "[attest] current_height=" << ctx.current_height
              << " chain_id=" << ctx.chain_id << "\n";
    std::cerr << "[attest] tx.from=" << tx.from.toString().substr(0, 16) << "\n";
    std::cerr << "[attest] payload.size()=" << tx.payload.size() << "\n";

    if (tx.payload.size() != 8 + 32 + 4 + 32 + 8 + 2 + 64)
    {
      std::cerr << "[attest] FAIL: payload size wrong\n";
      return failure;
    }

    size_t off = 0;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    Crypto::Hash source_tx_hash;
    std::memcpy(source_tx_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint32_t source_output_index = readU32At(tx.payload, off);
    off += 4;

    Crypto::Address destination;
    std::memcpy(destination.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint64_t amount = readU64At(tx.payload, off);
    off += 8;

    const uint16_t signer_index =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;

    Crypto::Signature signature;
    std::memcpy(signature.data.data(), tx.payload.data() + off, 64);
    off += 64;

    std::cerr << "[attest] parsed: chain=0x" << std::hex << source_chain_id << std::dec
              << " tx_hash=" << source_tx_hash.toString().substr(0, 16)
              << " out_idx=" << source_output_index
              << " amount=" << amount
              << " signer_idx=" << signer_index << "\n";
    std::cerr << "[attest] dest(first 8B): ";
    for (int i = 0; i < 8; ++i)
      std::cerr << std::hex << (int)destination.data[i];
    std::cerr << std::dec << "\n";

    if (amount == 0)
    {
      std::cerr << "[attest] FAIL: amount==0\n";
      return failure;
    }
    if (destination.isNull())
    {
      std::cerr << "[attest] FAIL: dest null\n";
      return failure;
    }

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
    {
      std::cerr << "[attest] FAIL: bridge paused\n";
      return failure;
    }

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
    {
      std::cerr << "[attest] FAIL: chain not registered\n";
      return failure;
    }
    std::cerr << "[attest] reg: enabled=" << (reg.enabled ? 1 : 0)
              << " active_watcher_min=" << reg.active_watcher_min
              << " wrapped_token=" << reg.wrapped_token_id << "\n";
    if (!reg.isWellFormed() || !reg.enabled)
    {
      std::cerr << "[attest] FAIL: reg malformed/disabled\n";
      return failure;
    }

    uint64_t existing_mint_height = 0;
    if (state.getBridgeConsumed(source_chain_id, source_tx_hash,
                                source_output_index, existing_mint_height))
    {
      std::cerr << "[attest] FAIL: deposit already consumed at height "
                << existing_mint_height << "\n";
      return failure;
    }

    std::vector<Core::BridgeWatcherInfo> active;
    state.forEachActiveBridgeWatcherForChain(
        source_chain_id, ctx.current_height,
        [&](const Core::BridgeWatcherInfo &w)
        { active.push_back(w); });

    std::cerr << "[attest] active set before sort (size=" << active.size() << "):\n";
    for (const auto &w : active)
    {
      std::cerr << "[attest]   watcher.id=" << w.id
                << " validator_id=" << w.validator_id
                << " stake=" << w.stake
                << " is_active=" << w.is_active << "\n";
    }

    std::sort(active.begin(), active.end(),
              [](const Core::BridgeWatcherInfo &a, const Core::BridgeWatcherInfo &b)
              { return a.id < b.id; });

    std::cerr << "[attest] active set after sort:\n";
    for (size_t i = 0; i < active.size(); ++i)
    {
      std::cerr << "[attest]   [" << i << "] watcher.id=" << active[i].id
                << " validator_id=" << active[i].validator_id << "\n";
    }

    if (active.size() < reg.active_watcher_min)
    {
      std::cerr << "[attest] FAIL: active.size()=" << active.size()
                << " < min=" << reg.active_watcher_min << "\n";
      return failure;
    }

    if (signer_index >= active.size())
    {
      std::cerr << "[attest] FAIL: signer_index=" << signer_index
                << " >= active.size()=" << active.size() << "\n";
      return failure;
    }

    const Id validator_id = active[signer_index].validator_id;
    std::cerr << "[attest] signer_index=" << signer_index
              << " -> watcher.id=" << active[signer_index].id
              << " validator_id=" << validator_id << "\n";

    auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
    if (!pk.has_value())
    {
      std::cerr << "[attest] FAIL: no consensus key for validator "
                << validator_id << " at height " << ctx.current_height << "\n";
      return failure;
    }

    std::cerr << "[attest] consensus pk (first 16B): ";
    for (int i = 0; i < 16; ++i)
      std::cerr << std::hex << (int)pk->data[i];
    std::cerr << std::dec << "\n";

    const std::vector<uint8_t> message = encodeBridgeMintMessage(
        source_chain_id, source_tx_hash, source_output_index,
        destination, amount);

    std::cerr << "[attest] message size=" << message.size() << " hex: ";
    for (size_t i = 0; i < message.size(); ++i)
      std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)message[i];
    std::cerr << std::dec << "\n";

    const Crypto::Hash hash =
        bridgeSigningHash("bmin", message.data(), message.size());

    std::cerr << "[attest] signing hash=" << hash.toString() << "\n";

    std::cerr << "[attest] sig (first 16B): ";
    for (int i = 0; i < 16; ++i)
      std::cerr << std::hex << (int)signature.data[i];
    std::cerr << std::dec << "\n";

    if (!Crypto::verify(hash, *pk, signature))
    {
      std::cerr << "[attest] FAIL: signature verification failed\n";
      return failure;
    }

    std::cerr << "[attest] signature OK\n";

    //  Duplicate check
    {
      Core::BridgeAttestation existing;
      if (state.getBridgeAttestation(
              source_chain_id, source_tx_hash, source_output_index,
              validator_id, existing))
      {
        std::cerr << "[attest] FAIL: already attested by validator "
                  << validator_id << "\n";
        return failure;
      }
    }

    //  Conflict check
    bool has_conflict = false;
    state.forEachBridgeAttestationForDeposit(
        source_chain_id, source_tx_hash, source_output_index,
        [&](uint64_t other_vid, const Core::BridgeAttestation &other) -> bool
        {
          if (other.destination != destination || other.amount != amount)
          {
            std::cerr << "[attest] CONFLICT: other validator=" << other_vid
                      << " other.dest=" << other.destination.toString().substr(0, 16)
                      << " other.amount=" << other.amount << "\n";
            has_conflict = true;
            return false;
          }
          return true;
        });

    if (has_conflict)
    {
      std::cerr << "[attest] FAIL: conflicting attestation\n";
      return failure;
    }

    Core::BridgeAttestation attestation;
    attestation.signer_index = signer_index;
    attestation.signature = signature;
    attestation.destination = destination;
    attestation.amount = amount;
    attestation.attested_at_height = ctx.current_height;

    if (!attestation.isWellFormed())
    {
      std::cerr << "[attest] FAIL: attestation not well-formed\n";
      return failure;
    }

    state.putBridgeAttestation(source_chain_id, source_tx_hash,
                               source_output_index, validator_id,
                               attestation);

    std::cerr << "[attest] SUCCESS: recorded attestation\n";
    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — BridgeAckAttest
  //  =========================================================================
  //
  //  Payload layout:
  //    [8]  withdrawal_id
  //    [2]  signer_index (LE, position in sorted active watcher set)
  //    [64] signature (ed25519 over Blake2b("back" || LE64(withdrawal_id)))
  //
  //  Total: 8 + 2 + 64 = 74 bytes, exact.
  //
  //  Each active watcher submits one BridgeAckAttest per withdrawal.
  //  The submission assembler later reads the attestations back,
  //  verifies that they form a quorum, and assembles the
  //  [2] count || N*66 block that a BridgeAckWithdrawal carries.
  //
  //  The executor's job is to validate *one* attestation in
  //  isolation:
  //    - the bridge is not paused;
  //    - the withdrawal exists and is not already released;
  //    - the signer_index is within the active watcher set;
  //    - the resolved consensus key at ctx.current_height signs
  //      the canonical message;
  //    - no other attestation exists for (withdrawal, validator) —
  //      resubmission is rejected.
  //
  //  There is no conflict check: the record carries no
  //  destination/amount, so all watchers either attest to the same
  //  withdrawal_id or not at all.

  Receipt TransactionExecutor::executeBridgeAckAttest(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 8 + 2 + 64)
      return failure;

    size_t off = 0;

    uint64_t withdrawal_id = 0;
    for (int i = 0; i < 8; ++i)
      withdrawal_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    const uint16_t signer_index =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;

    Crypto::Signature signature;
    std::memcpy(signature.data.data(), tx.payload.data() + off, 64);
    off += 64;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeWithdrawal w;
    if (!state.getBridgeWithdrawal(withdrawal_id, w))
      return failure;
    if (!w.isWellFormed())
      return failure;
    if (w.isReleased())
      return failure; // pointless to attest to an already-released withdrawal

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(w.source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    //  Resolve the active watcher set at this height, sorted by id
    //  (same ordering as verifyBridgeSignatures).
    std::vector<Core::BridgeWatcherInfo> active;
    state.forEachActiveBridgeWatcherForChain(
        w.source_chain_id, ctx.current_height,
        [&](const Core::BridgeWatcherInfo &wi)
        { active.push_back(wi); });

    std::sort(active.begin(), active.end(),
              [](const Core::BridgeWatcherInfo &a,
                 const Core::BridgeWatcherInfo &b)
              { return a.id < b.id; });

    if (active.size() < reg.active_watcher_min)
      return failure;

    if (signer_index >= active.size())
      return failure;

    const Id validator_id = active[signer_index].validator_id;

    auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
    if (!pk.has_value())
      return failure;

    const std::vector<uint8_t> message = encodeBridgeAckMessage(withdrawal_id);
    const Crypto::Hash hash =
        bridgeSigningHash("back", message.data(), message.size());

    if (!Crypto::verify(hash, *pk, signature))
      return failure;

    //  Duplicate check.
    {
      Core::BridgeAckAttestation existing;
      if (state.getBridgeAckAttestation(withdrawal_id, validator_id, existing))
        return failure;
    }

    Core::BridgeAckAttestation attestation;
    attestation.signer_index = signer_index;
    attestation.signature = signature;
    attestation.attested_at_height = ctx.current_height;

    if (!attestation.isWellFormed())
      return failure;

    state.putBridgeAckAttestation(withdrawal_id, validator_id, attestation);

    recordBridgeEvent(state, Core::BridgeEventKind::AckAttest,
                      w.source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/Crypto::Hash{},
                      /*has_source=*/false,
                      /*source_output_index=*/0,
                      /*withdrawal_id=*/withdrawal_id,
                      /*amount=*/0,
                      /*counterparty=*/validator_id);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — RegisterBridgeWatcher
  //  =========================================================================
  //
  //  Payload layout:
  //    [8]  source_chain_id (LE)
  //    [8]  stake           (LE)
  //
  //  No signature block. The watcher registers themselves; the
  //  authorization is "caller is a validator with enough balance to
  //  lock the stake." Registration is one-shot per (validator,
  //  chain); a second one while the first is unbonding-expired is
  //  allowed (re-registration), a second one while active is not.
  //
  //  The registration does not verify the caller's authority beyond
  //  "has a validator record whose reward_address equals tx.from,"
  //  because the validator record itself is the authority.

  Receipt TransactionExecutor::executeRegisterBridgeWatcher(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 8 + 8)
      return failure;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[i]) << (i * 8);

    uint64_t stake = 0;
    for (int i = 0; i < 8; ++i)
      stake |= uint64_t(tx.payload[8 + i]) << (i * 8);

    if (stake < BRIDGE_WATCHER_MIN_STAKE)
      return failure;

    //  Caller must be a registered validator.
    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    //  Chain must be registered and enabled.
    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    //  Caller must not already have an active (or unbonding) watcher
    //  for this chain. The lookup is by owner address, which is the
    //  validator's reward_address for a legacy validator and the
    //  explicit reward_address for a modern one.
    uint64_t existing = 0;
    if (state.getBridgeWatcherIdByAddress(tx.from, existing))
    {
      Core::BridgeWatcherInfo w;
      if (state.getBridgeWatcher(existing, w) &&
          w.source_chain_id == source_chain_id &&
          !w.isUnbondExpired(ctx.current_height))
        return failure;
    }

    //  Caller must not be pending-unbond as a validator; the
    //  watcher stake and the validator stake would both be locked
    //  at departure and the accounting gets confusing.
    Core::ValidatorInfo v;
    if (!state.getValidator(validator_id, v))
      return failure;
    if (v.pending_unbond_height != 0)
      return failure;

    //  Debit the stake. Locks it out of the balance until the
    //  watcher unbonds (or gets slashed), matching the validator
    //  stake model.
    Core::Account acct = state.getAccount(tx.from);
    if (acct.balance < stake)
      return failure;
    acct.balance -= stake;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    state.putAccount(tx.from, acct);

    //  Allocate the watcher id.
    GlobalStateReader reader(state);
    uint64_t next_id = reader.bridgeNextWatcherId();
    if (next_id == 0)
      next_id = 1;

    Core::BridgeWatcherInfo w;
    w.id = next_id;
    w.validator_id = validator_id;
    w.source_chain_id = source_chain_id;
    w.reward_address = tx.from;
    w.registered_at_height = ctx.current_height;
    w.stake = stake;
    w.last_seen_height = ctx.current_height;
    w.is_active = true;
    w.became_active_at = ctx.current_height;
    w.last_active_at = ctx.current_height;

    if (!w.isWellFormed())
      return failure;

    state.putBridgeWatcher(w);

    GlobalStateWriter writer(state);
    writer.setBridgeNextWatcherId(next_id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — UnregisterBridgeWatcher
  //  =========================================================================
  //
  //  Payload layout:
  //    [8]  source_chain_id (LE)
  //
  //  Starts the watcher's unbonding. The watcher is removed from
  //  the active set immediately (is_active = false) but the record
  //  and stake stay until pending_unbond_height. During the window
  //  the stake is slashable; at expiry the record is deleted and
  //  the stake is returned to the owner.
  //
  //  Refused if removing this watcher would drop the active set
  //  below the registration's active_watcher_min.

  Receipt TransactionExecutor::executeUnregisterBridgeWatcher(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 8)
      return failure;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[i]) << (i * 8);

    uint64_t watcher_id = 0;
    if (!state.getBridgeWatcherIdByAddress(tx.from, watcher_id))
      return failure;

    Core::BridgeWatcherInfo w;
    if (!state.getBridgeWatcher(watcher_id, w))
      return failure;
    if (w.source_chain_id != source_chain_id)
      return failure;
    if (w.pending_unbond_height != 0)
      return failure;

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;

    //  Refuse if removing this watcher would drop the active set
    //  below the registration's minimum. The caller can retry once
    //  more watchers register.
    const size_t active_count =
        state.countActiveBridgeWatchersForChain(
            source_chain_id, ctx.current_height);

    if (active_count <= reg.active_watcher_min)
      return failure;

    //  Mark unbonding. Record stays until pending_unbond_height;
    //  stake is locked and slashable for the whole window.
    w.is_active = false;
    w.last_active_at = ctx.current_height;
    w.pending_unbond_height =
        ctx.current_height + BRIDGE_WATCHER_UNBONDING_PERIOD;
    state.putBridgeWatcher(w);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  System Slash

  Receipt TransactionExecutor::executeSystemSlash(State::StateAccess &state,
                                                  uint64_t validator_id,
                                                  uint64_t slash_height,
                                                  const TxExecutionContext & /*ctx*/)
  {
    const Receipt no_op{ReceiptStatus::Success, 0};

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return no_op;

    if (SEED_SLASH_EXEMPT && validator.is_seed)
      return no_op;

    const uint64_t slash_amount =
        applyBps(validator.stake, SLASH_AMOUNT_BPS);

    if (slash_amount <= validator.stake)
      validator.stake -= slash_amount;

    validator.applyInfractionPenalty(slash_height);

    state.putValidator(validator);

    if (slash_amount > 0)
    {
      GlobalStateReader reader(state);
      GlobalStateWriter writer(state);

      uint64_t pot = reader.pot();
      pot += slash_amount;
      writer.setPot(pot);
    }

    return {ReceiptStatus::Success, 0};
  }

  //  Validate Create Order Structure

  bool TransactionExecutor::validateCreateOrderStructure(const Transaction &tx)
  {
    //  Minimum length: buy_token(4) + min_buy_amount(8) + mode(1)
    //  + pool_id(4) + expires_at_height(8) + condition_count(1) = 26.
    if (tx.payload.size() < 26)
      return false;

    size_t off = 0;
    uint32_t buy_token = uint32_t(tx.payload[off]) |
                         (uint32_t(tx.payload[off + 1]) << 8) |
                         (uint32_t(tx.payload[off + 2]) << 16) |
                         (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t min_buy_amount = 0;
    for (int i = 0; i < 8; ++i)
      min_buy_amount |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t mode = tx.payload[off++];

    uint32_t pool_id = uint32_t(tx.payload[off]) |
                       (uint32_t(tx.payload[off + 1]) << 8) |
                       (uint32_t(tx.payload[off + 2]) << 16) |
                       (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t expires_at_height = 0;
    for (int i = 0; i < 8; ++i)
      expires_at_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t condition_count = tx.payload[off++];

    if (condition_count > ORDER_MAX_CONDITIONS)
      return false;

    if (mode != static_cast<uint8_t>(OrderExecutionMode::Passive) &&
        mode != static_cast<uint8_t>(OrderExecutionMode::Active))
      return false;

    //  pool_id is meaningful only for Active orders.
    if (mode == static_cast<uint8_t>(OrderExecutionMode::Active))
    {
      if (pool_id == 0)
        return false;
    }
    else
    {
      if (pool_id != 0)
        return false;
    }

    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      if (!OrderCondition::deserializeState(
              tx.payload.data(), tx.payload.size(), off, conditions[i]))
      {
        return false;
      }
    }

    //  Cheap structural checks that mirror Order::isValid without
    //  needing a full Order record.
    if (tx.token_id == buy_token)
      return false;
    if (tx.amount == 0)
      return false;
    if (min_buy_amount == 0)
      return false;

    //  Overflow guard for Passive orders: an order whose canonical
    //  price cannot fit in u64 cannot enter the book, so reject it
    //  up front rather than creating a lock the matcher will never
    //  release. Active orders do not go through the book and so do
    //  not need this check.
    if (mode == static_cast<uint8_t>(OrderExecutionMode::Passive))
    {
      Order probe;
      probe.sell_token = tx.token_id;
      probe.buy_token = buy_token;
      probe.sell_amount = tx.amount;
      probe.min_buy_amount = min_buy_amount;
      uint64_t canonical_price = 0;
      if (!OrderBook::canonicalPrice(probe, canonical_price))
        return false;
    }

    return true;
  }

} // namespace Core