#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>

#include "Logger.h"

#include "Consensus/BftConsensus.h"

#include "Core/Block.h"
#include "Core/Chain.h"
#include "Core/Mempool.h"
#include "Core/StateView.h"
#include "Core/RewardCalculator.h"
#include "Core/TransactionExecutor.h"

#include "Crypto/Argon2id.h"
#include "Crypto/Ed25519.h"

#include "Node/Node.h"

#include "P2P/Config.h"
#include "P2P/Message.h"
#include "P2P/P2PManager.h"

#include "RPC/Config.h"
#include "RPC/JsonRpcDispatcher.h"

#include "Serialization/ISerializer.h"

#include "State/StateAccess.h"
#include "State/StateDB.h"

using namespace std::chrono_literals;

namespace Tests
{
  // Test global values

  constexpr uint64_t EXEC_CHAIN_ID = 0x434C5247;
  constexpr uint32_t TEST_MAGIC = 0x434C5247; // 'CLRG'
  constexpr uint32_t TEST_MAX_SIZE = 32 * 1024 * 1024;

  //  ---- Address + key helpers ----

  //  Address of a keypair is its public key. Same convention as the
  //  on-chain ValidatorInfo::reward_address for seed validators.
  inline Crypto::Address addressOf(const Crypto::KeyPair &kp)
  {
    Crypto::Address a;
    std::memcpy(a.data.data(), kp.publicKey.data.data(), 32);
    return a;
  }

  //  Deterministic validator key. Derivation matches
  //  ConsensusTestEnv::TestValidator::make so a test that builds a
  //  key this way can sign against a validator registered with the
  //  same id.
  inline Crypto::KeyPair deterministicValidatorKey(uint64_t validator_id)
  {
    Crypto::KeyPair kp;
    for (size_t i = 0; i < kp.secretKey.data.size(); ++i)
      kp.secretKey.data[i] = static_cast<uint8_t>(0x80 + validator_id + i);
    kp.publicKey = Crypto::derivePublicKey(kp.secretKey);
    return kp;
  }

  //  Alice and Bob are the funded non-validator accounts used by
  //  mempool and reward-redirect tests. Their keys are stable across
  //  runs so a genesis built by one test is compatible with another.
  inline Crypto::KeyPair aliceKey()
  {
    Crypto::SecretKey seed;
    for (int i = 0; i < 8; ++i)
      seed.data[i] = uint8_t(0xA1 + i);
    for (size_t i = 8; i < 32; ++i)
      seed.data[i] = uint8_t(0xDD);
    return Crypto::generateKeyPairFromSeed(seed);
  }

  inline Crypto::KeyPair bobKey()
  {
    Crypto::SecretKey seed;
    for (int i = 0; i < 8; ++i)
      seed.data[i] = uint8_t(0xB2 + i);
    for (size_t i = 8; i < 32; ++i)
      seed.data[i] = uint8_t(0xEE);
    return Crypto::generateKeyPairFromSeed(seed);
  }

  //  ---- Genesis ----

  //  Build a test genesis.
  //
  //    reward_keys     — one keypair per validator. Reward address
  //                      and identity. Funded with SEED_FUND_AMOUNT.
  //    consensus_keys  — one keypair per validator. The key the
  //                      validator signs votes and proposals with.
  //                      Must be the same length as reward_keys.
  //    active_count    — how many of the first entries start in the
  //                      active set. The remainder are pool
  //                      candidates.
  //
  //  In single-key mode, consensus_keys[i] == reward_keys[i]. In
  //  split-key mode they differ.
  inline Core::GenesisConfig makeGenesis(
      const std::vector<Crypto::KeyPair> &reward_keys,
      const std::vector<Crypto::KeyPair> &consensus_keys,
      size_t active_count)
  {
    constexpr uint64_t INITIAL = GlobalConfig::GENESIS_SUPPLY;

    Core::GenesisConfig cfg;
    cfg.chain_id = 0x434C5247;
    cfg.timestamp_ms = 1'700'000'000'000ULL;

    Crypto::Address fund_addr;
    std::fill(fund_addr.data.begin(), fund_addr.data.end(), 0x01);
    cfg.accounts.push_back({fund_addr, INITIAL, "test fund"});

    cfg.accounts.push_back({addressOf(aliceKey()), INITIAL, "alice"});
    cfg.accounts.push_back({addressOf(bobKey()), 0, "bob"});

    const size_t n = reward_keys.size();
    for (size_t i = 0; i < n; ++i)
    {
      const Crypto::Address addr = addressOf(reward_keys[i]);
      const Crypto::PublicKey consensus_pub =
          (i < consensus_keys.size())
              ? consensus_keys[i].publicKey
              : reward_keys[i].publicKey;

      cfg.accounts.push_back({addr,
                              GlobalConfig::SEED_FUND_AMOUNT,
                              "validator " + std::to_string(i + 1)});

      cfg.validators.push_back({static_cast<Id>(i + 1),
                                addr,          // reward_address
                                consensus_pub, // node_key (unused in v1)
                                /*is_seed=*/i < active_count,
                                consensus_pub}); // consensus_key ← the split key
    }

    cfg.initial_total_supply = INITIAL;
    cfg.initial_active_set_size = active_count;
    return cfg;
  }

  //  Single-key overload: consensus key == reward key.
  inline Core::GenesisConfig makeGenesis(
      const std::vector<Crypto::KeyPair> &keys)
  {
    return makeGenesis(keys, keys, keys.size());
  }

  //  ---- Unrelated helpers used across the test suite ----

  Crypto::Hash makeHash(uint64_t n);
  Crypto::Address makeAddress(uint64_t n);
  Crypto::Signature makeSignature(uint8_t seed);
  Core::AmmPool makePool();
  Core::Block makeBlock(uint64_t height);
  Core::Block makeBlock(Core::BlockHeader header,
                        std::vector<Core::Transaction> txs = {},
                        std::vector<Id> participants = {});
  Core::BlockHeader makeBlockHeader(uint64_t height = 1,
                                    const Crypto::Hash &parent = Crypto::Hash{},
                                    uint64_t chain_id = 0x434C5247);
  Core::Transaction makeTransaction();
  Core::Transaction makeTransaction(uint64_t nonce);
  Core::Transaction makeTransaction(const Crypto::KeyPair &kp,
                                    uint64_t nonce,
                                    uint64_t amount,
                                    uint64_t fee,
                                    uint64_t chain_id = 0x434C5247);
  Core::RewardContext makeContext();
  Core::ValidatorRegistry makeRegistry(size_t n);
  std::vector<uint8_t> makeCreatePoolPayload(uint32_t token_b, uint64_t amount_b, uint16_t fee_bps);
  std::vector<uint8_t> makeCreateTokenPayload(
      const std::string &name,
      const std::string &symbol,
      uint8_t decimals = 8,
      uint8_t backing = 0,
      uint64_t max_supply = 0,
      uint16_t royalty_bps = 0,
      std::optional<Crypto::Hash> fingerprint = std::nullopt);
  std::vector<uint8_t> makeAddLiquidityPayload(uint64_t pool_id, uint64_t amount_b);
  std::vector<uint8_t> makeSwapPayload(uint64_t pool_id, uint64_t amount_min_out);
  std::vector<uint8_t> makeRemoveLiquidityPayload(uint64_t position_id);
  std::vector<uint8_t> makeCancelOrderPayload(uint64_t order_id);
  std::vector<uint8_t> makeRegisterValidatorPayload();
  std::vector<uint8_t> makeCreateOrderPayload(
      uint32_t buy_token,
      uint64_t min_buy_amount,
      uint8_t mode,
      uint64_t expires_at,
      const std::vector<uint8_t> &condition_bytes = {});
  Crypto::KeyPair makeKeyPair();
  Core::TokenInfo makeToken();

  Node::NodeConfig makeNodeConfig(const std::string &data_dir);
  Rpc::RpcConfig makeRpcConfig();

  std::vector<uint8_t> proofValue(uint64_t n, size_t len = 32);

  uint64_t readU64Global(State::StateAccess &s, const std::string &name);
  uint64_t readU64GlobalSV(State::StateAccess &s, std::string_view name);
  void createKVBinarySerializer(Serialization::MemoryInputStream &stream);
  P2P::Message roundTripThroughWire(const P2P::Message &in);
  uint16_t pickFreePort();
  const char *stepNameLocal(Consensus::Step s);
  bool canConnect(uint16_t port);
  std::string toHex(const uint8_t *data, size_t len);
  bool fromHex(const std::string &hex, uint8_t *out, size_t out_len);
  uint64_t feeRateOf(const Core::Transaction &tx);
  void appendOrderCondition(std::vector<uint8_t> &p,
                            Core::OrderConditionType type,
                            uint64_t param1,
                            uint32_t param2 = 0);
  uint64_t expectedSwapOutput(uint64_t reserve_in,
                              uint64_t reserve_out,
                              uint64_t amount_in,
                              uint16_t fee_bps);
  uint64_t expectedInitialLiquidity(uint64_t amount_a, uint64_t amount_b);

  std::vector<uint8_t> testPassword();
  std::vector<uint8_t> testSalt();
  std::string argon2idHex(const std::vector<uint8_t> &password,
                          const std::vector<uint8_t> &salt,
                          const Crypto::Argon2Params &params,
                          size_t out_len = 32);
  std::vector<uint8_t> testPayload();

  std::string hmacHex(const std::vector<uint8_t> &key,
                      const std::vector<uint8_t> &msg);
  std::vector<uint8_t> repeat(uint8_t byte, size_t n);

  std::vector<uint8_t> bytes(std::string_view s);

  std::string pbkdf2Hex(std::string_view password,
                        std::string_view salt,
                        uint32_t iterations,
                        size_t out_len);
  std::string pbkdf2Hex(const std::vector<uint8_t> &password,
                        const std::vector<uint8_t> &salt,
                        uint32_t iterations,
                        size_t out_len);

  void registerAllNonAdminMethods(Rpc::JsonRpcDispatcher &d);

  template <typename Pred>
  bool waitFor(Pred &&pred, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (pred())
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  }
}