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

  // Helpers

  Crypto::Hash makeHash(uint64_t n);
  Crypto::Address makeAddress(uint64_t n);
  Crypto::Signature makeSignature(uint8_t seed);
  Core::AmmPool makePool();
  std::vector<uint8_t> proofValue(uint64_t n, size_t len = 32);
  Core::ValidatorInfo makeValidator();
  uint64_t readU64Global(State::StateAccess &s, const std::string &name);
  uint64_t readU64GlobalSV(State::StateAccess &s, std::string_view name);
  void createKVBinarySerializer(Serialization::MemoryInputStream &stream);
  Core::Block makeBlock(uint64_t height);
  P2P::Message roundTripThroughWire(const P2P::Message &in);
  uint16_t pickFreePort();
  Crypto::KeyPair deterministicValidatorKey(uint64_t id);
  Crypto::KeyPair aliceKey();
  Crypto::KeyPair bobKey();
  Crypto::Address addressOf(const Crypto::KeyPair &kp);
  Core::GenesisConfig makeTestGenesis(const std::vector<Crypto::KeyPair> &validators);
  const char *stepNameLocal(Consensus::Step s);
  bool canConnect(uint16_t port);
  std::string toHex(const uint8_t *data, size_t len);
  bool fromHex(const std::string &hex, uint8_t *out, size_t out_len);
  uint64_t feeRateOf(const Core::Transaction &tx);
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
  std::vector<uint8_t> makeSwapPayload(uint64_t pool_id, uint64_t min_amount_out);
  std::vector<uint8_t> makeRemoveLiquidityPayload(uint64_t position_id);
  std::vector<uint8_t> makeCancelOrderPayload(uint64_t order_id);
  std::vector<uint8_t> makeRegisterValidatorPayload();
  void appendOrderCondition(std::vector<uint8_t> &p,
                                   Core::OrderConditionType type,
                                   uint64_t param1,
                                   uint32_t param2 = 0);
  std::vector<uint8_t> makeCreateOrderPayload(
      uint32_t buy_token,
      uint64_t min_buy_amount,
      uint8_t mode,
      uint64_t expires_at,
      const std::vector<uint8_t> &condition_bytes = {});
  uint64_t expectedSwapOutput(uint64_t reserve_in,
                                     uint64_t reserve_out,
                                     uint64_t amount_in,
                                     uint16_t fee_bps);
  uint64_t expectedInitialLiquidity(uint64_t amount_a, uint64_t amount_b);
  Core::BlockHeader makeTestHeader(uint64_t height = 1,
                                          const Crypto::Hash &parent = Crypto::Hash{},
                                          uint64_t chain_id = 0x434C5247);
  Core::Block makeTestBlock(Core::BlockHeader header,
                                   std::vector<Core::Transaction> txs = {},
                                   std::vector<Id> participants = {});
  Crypto::KeyPair makeTestKeyPair();
  Core::Transaction makeTestTx(const Crypto::KeyPair &kp,
                                      uint64_t nonce,
                                      uint64_t amount,
                                      uint64_t fee,
                                      uint64_t chain_id = 0x434C5247);
  Core::Transaction makeTx();
  Core::TokenInfo makeToken();
  Core::BlockHeader makeHeader();
  Core::Transaction makeSimpleTx(uint64_t nonce);

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

  Node::NodeConfig makeTestNodeConfig(const std::string &data_dir);
  Rpc::RpcConfig makeTestRpcConfig();
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

  struct Envelope
  {
    enum Kind
    {
      Proposal,
      Prevote,
      Precommit,
      TimeoutVote,
      Restart
    } kind;
    size_t from{0};
    size_t to{0};
    Consensus::Proposal proposal;
    Consensus::Vote vote;
    Consensus::TimeoutVote timeout_vote;
    Height restart_height{0};

    //  True when the proposal carries the emergency flag. Set by the
    //  proposer's broadcast_proposal callback so deliverAll can honor
    //  proposal suppression without decoding the block itself.
    bool is_emergency{false};
  };

  // TempFile creates a unique temp file path, removes it on destruction.
  // The file itself is not created; the fixture's code does that.

  class TempFile
  {
  public:
    TempFile(const std::string &prefix = "clrty_p2p_test")
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              (prefix + "_" + std::to_string(counter.fetch_add(1)) + ".tmp");
      std::filesystem::remove(path_);
    }

    ~TempFile()
    {
      std::error_code ec;
      std::filesystem::remove(path_, ec);
    }

    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;

    std::string path() const { return path_.string(); }

  private:
    std::filesystem::path path_;
  };

  class TempDB
  {
  public:
    TempDB()
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              ("clrty_state_test_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(path_);
      db_ = std::make_unique<State::StateDB>(path_.string(), 64ULL * 1024 * 1024);
    }

    ~TempDB()
    {
      if (db_)
      {
        db_->close();
        db_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }

    TempDB(const TempDB &) = delete;
    TempDB &operator=(const TempDB &) = delete;

    State::StateDB &db() { return *db_; }
    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
    std::unique_ptr<State::StateDB> db_;
  };

}