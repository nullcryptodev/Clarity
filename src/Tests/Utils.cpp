#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include "Utils.h"

#include "Crypto/Ed25519.h"

#include "Common/Put.h"

namespace Tests
{
  // Avoids overlap with the fixture's so tests can use their own naming.
  Crypto::Hash makeHash(uint64_t n)
  {
    Crypto::Hash h;
    for (int i = 0; i < 8; ++i)
      h.data[i] = uint8_t(n >> (i * 8));
    for (size_t i = 8; i < 32; ++i)
      h.data[i] = 0;
    return h;
  }

  Crypto::Address makeAddress(uint64_t n)
  {
    Crypto::Address a;
    for (int i = 0; i < 8; ++i)
      a.data[i] = uint8_t(n >> (i * 8));
    for (size_t i = 8; i < 32; ++i)
      a.data[i] = 0;
    return a;
  }

  Crypto::Signature makeSignature(uint8_t seed)
  {
    Crypto::Signature s;
    for (size_t i = 0; i < 64; ++i)
      s.data[i] = uint8_t(seed + i);
    return s;
  }

  std::vector<uint8_t> proofValue(uint64_t n, size_t len)
  {
    std::vector<uint8_t> v(len);
    for (size_t i = 0; i < len; ++i)
      v[i] = uint8_t((n >> ((i % 8) * 8)) ^ (i * 7));
    return v;
  }

  // Read a uint64 global from a StateAccess. Returns 0 if the entry is
  // missing or the wrong size.
  uint64_t readU64Global(State::StateAccess &s, const std::string &name)
  {
    std::vector<uint8_t> bytes;
    if (!s.getGlobal(name, bytes) || bytes.size() != 8)
      return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v |= uint64_t(bytes[i]) << (i * 8);
    return v;
  }

  // Creates a KVBinarySerializer from a stream (for exception testing)
  void createKVBinarySerializer(Serialization::MemoryInputStream &stream)
  {
    Serialization::KVBinarySerializer serializer(stream);
  }

  // Build a minimal well-formed block. The bytes just have to survive
  // the encode/decode round trip — they don't need to be a valid block.
  Core::Block makeBlock(uint64_t height)
  {
    Core::Block b;
    b.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
    b.header.chain_id = TEST_MAGIC;
    b.header.height = height;
    b.header.parent_hash = makeHash(0x10);
    b.header.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
    b.header.proposer = Crypto::Address{};
    for (size_t i = 0; i < 32; ++i)
      b.header.proposer.data[i] = uint8_t(0x80 + i);
    b.header.epoch = height / 60;
    b.header.rotation_index = height / 60;
    b.header.state_root = makeHash(0x20);
    b.header.tx_root = makeHash(0x40);
    b.header.receipts_root = makeHash(0x60);
    b.header.validator_set_root = makeHash(0x70);
    b.header.total_fees = 0;
    b.header.tx_count = 0;
    b.header.active_validator_count = 2;
    return b;
  }

  // Encode a Message through the wire framing, feed the bytes into a
  // decoder, and return the decoded Message. This is the exact path the
  // production P2P layer takes: encodeMessage on send, MessageDecoder
  // on receive.
  P2P::Message roundTripThroughWire(const P2P::Message &in)
  {
    auto wire = P2P::encodeMessage(in, TEST_MAGIC, TEST_MAX_SIZE);

    P2P::MessageDecoder decoder(TEST_MAGIC, TEST_MAX_SIZE);
    decoder.feed(wire.data(), wire.size());

    auto result = decoder.next();
    EXPECT_EQ(result.status, P2P::DecodeStatus::Ok);
    EXPECT_TRUE(result.message.has_value());
    return *result.message;
  }

  //  bind to port 0, read the assigned port, close.
  //  There is a TOCTOU window between close() and the P2PManager
  //  binding the port. On loopback with a 2s test timeout this is fine.

  uint16_t pickFreePort()
  {
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor acc(
        io, boost::asio::ip::tcp::endpoint(
                boost::asio::ip::tcp::v4(), 0));
    uint16_t port = acc.local_endpoint().port();
    boost::system::error_code ec;
    acc.close(ec);
    return port;
  }

  Crypto::KeyPair deterministicValidatorKey(uint64_t id)
  {
    Crypto::SecretKey seed;
    for (int i = 0; i < 8; ++i)
      seed.data[i] = uint8_t(id >> (i * 8));
    for (size_t i = 8; i < 32; ++i)
      seed.data[i] = uint8_t(0xC0 + i);
    return Crypto::generateKeyPairFromSeed(seed);
  }

  Crypto::KeyPair aliceKey()
  {
    Crypto::SecretKey seed;
    for (int i = 0; i < 8; ++i)
      seed.data[i] = uint8_t(0xA1 + i);
    for (size_t i = 8; i < 32; ++i)
      seed.data[i] = uint8_t(0xDD);
    return Crypto::generateKeyPairFromSeed(seed);
  }

  Crypto::KeyPair bobKey()
  {
    Crypto::SecretKey seed;
    for (int i = 0; i < 8; ++i)
      seed.data[i] = uint8_t(0xB2 + i);
    for (size_t i = 8; i < 32; ++i)
      seed.data[i] = uint8_t(0xEE);
    return Crypto::generateKeyPairFromSeed(seed);
  }

  Crypto::Address addressOf(const Crypto::KeyPair &kp)
  {
    Crypto::Address a;
    std::memcpy(a.data.data(), kp.publicKey.data.data(), 32);
    return a;
  }

  Core::GenesisConfig makeTestGenesis(
      const std::vector<Crypto::KeyPair> &validators)
  {
    Core::GenesisConfig cfg;
    cfg.chain_id = 0x434C5247; // 'CLRG'
    cfg.timestamp_ms = 1'700'000'000'000ULL;

    constexpr uint64_t INITIAL =
        GlobalConfig::GENESIS_SUPPLY * GlobalConfig::ATOMIC_UNITS_PER_COIN;

    Crypto::Address fund_addr;
    std::fill(fund_addr.data.begin(), fund_addr.data.end(), 0x01);
    cfg.accounts.push_back({fund_addr, INITIAL, "test fund"});

    cfg.accounts.push_back({addressOf(aliceKey()), INITIAL, "alice"});
    cfg.accounts.push_back({addressOf(bobKey()), 0, "bob"});

    for (size_t i = 0; i < validators.size(); ++i)
    {
      cfg.validators.push_back({static_cast<Id>(i + 1),
                                addressOf(validators[i]),
                                validators[i].publicKey,
                                true});
    }

    cfg.initial_total_supply = INITIAL;
    cfg.initial_active_set_size = static_cast<uint64_t>(validators.size());
    return cfg;
  }

  const char *stepNameLocal(Consensus::Step s)
  {
    using Consensus::Step;
    switch (s)
    {
    case Step::NewHeight:
      return "NewHeight";
    case Step::Propose:
      return "Propose";
    case Step::Prevote:
      return "Prevote";
    case Step::Precommit:
      return "Precommit";
    case Step::Commit:
      return "Commit";
    }
    return "?";
  }

  bool canConnect(uint16_t port)
  {
    try
    {
      boost::asio::io_context io;
      boost::asio::ip::tcp::socket sock(io);
      boost::system::error_code ec;
      sock.connect(boost::asio::ip::tcp::endpoint(
                       boost::asio::ip::address_v4::loopback(), port),
                   ec);
      boost::system::error_code ignored;
      sock.close(ignored);
      return !ec;
    }
    catch (...)
    {
      return false;
    }
  }

  std::string toHex(const uint8_t *data, size_t len)
  {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
      out.push_back(hex[data[i] >> 4]);
      out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
  }

  bool fromHex(const std::string &hex, uint8_t *out, size_t out_len)
  {
    if (hex.size() != out_len * 2)
      return false;
    for (size_t i = 0; i < out_len; ++i)
    {
      auto nib = [](char c) -> int
      {
        if (c >= '0' && c <= '9')
          return c - '0';
        if (c >= 'a' && c <= 'f')
          return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
          return c - 'A' + 10;
        return -1;
      };
      int hi = nib(hex[i * 2]);
      int lo = nib(hex[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
  }

  // Byte size helper for tx fee rate calculations
  uint64_t feeRateOf(const Core::Transaction &tx)
  {
    size_t size = tx.serializedSize();
    if (size == 0)
      return 0;
    return tx.fee / size;
  }

  // Context builder
  // Produces a RewardContext with sane defaults. Callers override the
  // fields they care about.
  Core::RewardContext makeContext()
  {
    Core::RewardContext ctx;
    ctx.height = 1000;
    ctx.epoch_number = 16;
    ctx.active_set_size = 21;
    ctx.total_staked = 0;
    ctx.pot = 0;
    ctx.fees_this_block = 0;
    ctx.block_reward_atomic = GlobalConfig::BLOCK_REWARD;
    ctx.apy_base_bps = Core::APY_BASE_BPS;
    ctx.apy_activity_bps = 0;
    ctx.apy_pot_bonus_bps = 0;
    return ctx;
  }

  //  Registry builder
  //  Produces a ValidatorRegistry with N fake validators. Validator IDs
  //  start at 1 and increment. Active set is filled with all of them.
  //  Uptime scores are set above the "can be active" threshold.
  Core::ValidatorRegistry makeRegistry(size_t n)
  {
    Core::ValidatorRegistry reg;
    reg.next_id = 1;

    // Sentinel at index 0 (matches production convention).
    reg.validators.push_back(Core::ValidatorInfo{});

    for (size_t i = 0; i < n; ++i)
    {
      Core::ValidatorInfo v;
      v.id = static_cast<Id>(i + 1);
      v.stake = Core::VALIDATOR_MIN_STAKE;
      v.uptime_score = 10'000;
      v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
      v.is_active = true;
      reg.validators.push_back(v);
      reg.active_set.push_back(v.id);
    }

    return reg;
  }

  std::vector<uint8_t> makeCreatePoolPayload(uint32_t token_b,
                                                    uint64_t amount_b,
                                                    uint16_t fee_bps)
  {
    std::vector<uint8_t> p;
    Common::putU32(p, token_b);
    Common::putU64(p, amount_b);
    Common::putU16(p, fee_bps);
    return p;
  }

  std::vector<uint8_t> makeCreateTokenPayload(
      const std::string &name,
      const std::string &symbol,
      uint8_t decimals,
      uint8_t backing,
      uint64_t max_supply,
      uint16_t royalty_bps,
      std::optional<Crypto::Hash> fingerprint)
  {
    std::vector<uint8_t> p;
    p.push_back(decimals);
    p.push_back(backing);
    p.push_back(uint8_t(name.size()));
    p.insert(p.end(), name.begin(), name.end());
    p.push_back(uint8_t(symbol.size()));
    p.insert(p.end(), symbol.begin(), symbol.end());
    Common::putU64(p, max_supply);
    Common::putU16(p, royalty_bps);
    if (fingerprint)
    {
      p.push_back(1);
      p.insert(p.end(), fingerprint->data.begin(), fingerprint->data.end());
    }
    else
    {
      p.push_back(0);
    }
    return p;
  }

  std::vector<uint8_t> makeAddLiquidityPayload(uint64_t pool_id,
                                                      uint64_t amount_b)
  {
    std::vector<uint8_t> p;
    Common::putU64(p, pool_id);
    Common::putU64(p, amount_b);
    return p;
  }

  std::vector<uint8_t> makeSwapPayload(uint64_t pool_id,
                                              uint64_t min_amount_out)
  {
    std::vector<uint8_t> p;
    Common::putU64(p, pool_id);
    Common::putU64(p, min_amount_out);
    return p;
  }

  std::vector<uint8_t> makeRemoveLiquidityPayload(uint64_t position_id)
  {
    std::vector<uint8_t> p;
    Common::putU64(p, position_id);
    return p;
  }

  std::vector<uint8_t> makeCancelOrderPayload(uint64_t order_id)
  {
    std::vector<uint8_t> p;
    Common::putU64(p, order_id);
    return p;
  }

  std::vector<uint8_t> makeRegisterValidatorPayload()
  {
    std::vector<uint8_t> p(32);
    for (size_t i = 0; i < 32; ++i)
      p[i] = uint8_t(0x40 + i);
    return p;
  }

  // Single order condition, encoded as [1] type, [8] param1, [4] param2.
  void appendOrderCondition(std::vector<uint8_t> &p,
                                   Core::OrderConditionType type,
                                   uint64_t param1,
                                   uint32_t param2)
  {
    p.push_back(static_cast<uint8_t>(type));
    Common::putU64(p, param1);
    Common::putU32(p, param2);
  }

  std::vector<uint8_t> makeCreateOrderPayload(
      uint32_t buy_token,
      uint64_t min_buy_amount,
      uint8_t mode,
      uint64_t expires_at,
      const std::vector<uint8_t> &condition_bytes)
  {
    std::vector<uint8_t> p;
    Common::putU32(p, buy_token);
    Common::putU64(p, min_buy_amount);
    p.push_back(mode);
    Common::putU64(p, expires_at);
    p.push_back(static_cast<uint8_t>(condition_bytes.size() /
                                     Core::OrderCondition::STATE_SIZE));
    p.insert(p.end(), condition_bytes.begin(), condition_bytes.end());
    return p;
  }

  //  Formula mirrors
  //
  //  These duplicate the executor's math intentionally. If the executor
  //  changes and the tests don't, the anchor tests fail. That's the point.

  uint64_t expectedSwapOutput(uint64_t reserve_in,
                                     uint64_t reserve_out,
                                     uint64_t amount_in,
                                     uint16_t fee_bps)
  {
    uint64_t in_with_fee = amount_in * (10'000 - fee_bps) / 10'000;
    __uint128_t num = static_cast<__uint128_t>(reserve_out) * in_with_fee;
    uint64_t den = reserve_in + in_with_fee;
    return static_cast<uint64_t>(num / den);
  }

  uint64_t expectedInitialLiquidity(uint64_t amount_a, uint64_t amount_b)
  {
    __uint128_t prod = static_cast<__uint128_t>(amount_a) * amount_b;
    uint64_t liq = 1;
    while (liq <= prod / (liq + 1))
      ++liq;
    return liq;
  }

  //  Block builder helpers

  Core::BlockHeader makeTestHeader(uint64_t height, const Crypto::Hash &parent, uint64_t chain_id)
  {
    Core::BlockHeader h;
    h.version = GlobalConfig::CURRENT_BLOCK_VERSION;
    h.chain_id = chain_id;
    h.height = height;
    h.parent_hash = parent;
    h.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
    h.proposer = Crypto::Address{};
    for (size_t i = 0; i < 32; ++i)
    {
      h.proposer.data[i] = static_cast<uint8_t>(0x80 + i);
    }
    h.epoch = 0;
    h.rotation_index = 0;
    h.state_root = Crypto::Hash{};
    h.tx_root = Crypto::Hash{};
    h.receipts_root = Crypto::Hash{};
    h.validator_set_root = Crypto::Hash{};
    h.total_fees = 0;
    h.tx_count = 0;
    h.active_validator_count = 21;
    return h;
  }

  std::vector<Crypto::ValidatorSignature>
  makeDummyQuorum(size_t n)
  {
    std::vector<Crypto::ValidatorSignature> sigs;
    sigs.reserve(n);
    for (size_t i = 0; i < n; ++i)
    {
      Crypto::ValidatorSignature vs;
      vs.signer_index = static_cast<Index>(i);
      for (size_t j = 0; j < 64; ++j)
      {
        vs.signature.data[j] = static_cast<uint8_t>(i + j);
      }
      sigs.push_back(vs);
    }
    return sigs;
  }

  Core::Block makeTestBlock(Core::BlockHeader header,
                                   std::vector<Core::Transaction> txs,
                                   std::vector<Id> participants)
  {
    Core::Block b;
    b.header = header;
    b.header.tx_count = static_cast<uint32_t>(txs.size());
    b.header.tx_root = computeTxRoot(txs);
    b.transactions = std::move(txs);
    b.participants = std::move(participants);

    size_t needed = Core::bftQuorum(b.header.active_validator_count);
    b.quorum_signatures = makeDummyQuorum(needed);

    return b;
  }

  Crypto::KeyPair makeTestKeyPair()
  {
    return Crypto::generateKeyPair();
  }

  Core::Transaction makeTestTx(const Crypto::KeyPair &kp,
                                      uint64_t nonce,
                                      uint64_t amount,
                                      uint64_t fee,
                                      uint64_t chain_id)
  {
    Core::Transaction tx;
    tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
    tx.chain_id = chain_id;
    tx.tx_type = Core::TxType::Transfer;
    tx.nonce = nonce;
    tx.valid_until_height = 0;
    tx.from = kp.publicKey;
    tx.to = Crypto::Address{};
    for (size_t i = 0; i < 32; ++i)
    {
      tx.to.data[i] = static_cast<uint8_t>(0xC0 + i);
    }
    tx.token_id = 0;
    tx.amount = amount;
    tx.fee = fee;

    Crypto::Hash sighash = tx.signingHash();
    tx.signature = Crypto::sign(sighash, kp.secretKey);
    return tx;
  }


  // Bbuild a minimal well-formed transaction.
  Core::Transaction makeTx()
  {
    Core::Transaction tx;
    tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
    tx.chain_id = 0x434C5247; // regtest
    tx.tx_type = Core::TxType::Transfer;
    tx.nonce = 1;
    tx.valid_until_height = 0;

    // Deterministic sender / recipient for testing.
    for (int i = 0; i < 32; ++i)
      tx.from.data[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 32; ++i)
      tx.to.data[i] = static_cast<uint8_t>(0x80 + i);

    tx.token_id = 0;
    tx.amount = 100000;
    tx.fee = 500;
    tx.payload.clear();
    tx.signature = Crypto::Signature{};

    return tx;
  }

  Core::TokenInfo makeToken()
  {
    Core::TokenInfo t;
    t.id = 42;
    t.name = "Test Token";
    t.symbol = "TST";
    t.decimals = 8;
    t.creator = Crypto::Address{};
    for (int i = 0; i < 32; ++i)
      t.creator.data[i] = static_cast<uint8_t>(i);
    t.backing = Core::BackingModel::Unbacked;
    t.maxSupply = 1'000'000'000ULL;
    t.royaltyBps = 250; // 2.5%
    t.fingerprint = std::nullopt;
    return t;
  }

  Core::BlockHeader makeHeader()
  {
    Core::BlockHeader h;
    h.version = GlobalConfig::CURRENT_BLOCK_VERSION;
    h.chain_id = 0x434C5247;
    h.height = 100;
    h.parent_hash = Crypto::Hash{};
    for (size_t i = 0; i < 32; ++i)
      h.parent_hash.data[i] = static_cast<uint8_t>(i);
    h.timestamp_ms = 1700000000000ULL;
    h.proposer = Crypto::Address{};
    for (size_t i = 0; i < 32; ++i)
      h.proposer.data[i] = static_cast<uint8_t>(0x80 + i);
    h.epoch = 1;
    h.rotation_index = 1;
    h.state_root = Crypto::Hash{};
    h.tx_root = Crypto::Hash{};
    h.receipts_root = Crypto::Hash{};
    h.validator_set_root = Crypto::Hash{};
    h.total_fees = 1500;
    h.tx_count = 0;
    h.active_validator_count = 21;
    return h;
  }

  Core::Transaction makeSimpleTx(uint64_t nonce)
  {
    Core::Transaction tx;
    tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
    tx.chain_id = 0x434C5247;
    tx.tx_type = Core::TxType::Transfer;
    tx.nonce = nonce;
    tx.valid_until_height = 0;
    for (int i = 0; i < 32; ++i)
      tx.from.data[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 32; ++i)
      tx.to.data[i] = static_cast<uint8_t>(0x80 + i);
    tx.token_id = 0;
    tx.amount = 100000 + nonce;
    tx.fee = 500;
    return tx;
  }
}