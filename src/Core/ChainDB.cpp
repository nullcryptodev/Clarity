// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ChainDB.h"

#include "Crypto/Blake2b.h"

#include <cstring>

namespace Core
{
  namespace
  {
    // Table IDs. These must match the enum in StateDB.h.
    constexpr uint32_t TBL_BLOCKS_BY_HASH = 13;
    constexpr uint32_t TBL_BLOCKS_BY_HEIGHT = 14;
    constexpr uint32_t TBL_RECEIPTS = 11;
    constexpr uint32_t TBL_META = 2;
  } // anonymous namespace

  //  Construction

  ChainDB::ChainDB(State::StateDB &db)
      : db_(db)
  {
  }

  //  Block storage

  void ChainDB::storeBlock(const Block &block)
  {
    Crypto::Hash hash = block.hash();
    storeBlock(block, hash);
  }

  void ChainDB::storeBlock(const Block &block, const Crypto::Hash &hash)
  {
    // Serialize the block.
    std::vector<uint8_t> block_bytes = block.serialize();

    // Store by hash.
    db_.rawPut(TBL_BLOCKS_BY_HASH,
               hash.data.data(), hash.data.size(),
               block_bytes.data(), block_bytes.size());

    // Store by height: map height → hash.
    uint64_t height = block.header.height;
    uint8_t height_key[8];
    for (int i = 0; i < 8; ++i)
      height_key[i] = uint8_t(height >> (i * 8));

    db_.rawPut(TBL_BLOCKS_BY_HEIGHT,
               height_key, sizeof(height_key),
               hash.data.data(), hash.data.size());
  }

  //  Block retrieval

  std::optional<Block> ChainDB::getBlock(const Crypto::Hash &hash) const
  {
    std::vector<uint8_t> bytes;
    if (!db_.rawGet(TBL_BLOCKS_BY_HASH,
                    hash.data.data(), hash.data.size(),
                    bytes))
    {
      return std::nullopt;
    }

    Block block;
    if (!Block::deserialize(bytes.data(), bytes.size(), block))
    {
      return std::nullopt;
    }

    return block;
  }

  std::optional<Block> ChainDB::getBlockByHeight(uint64_t height) const
  {
    auto hash_opt = getHashByHeight(height);
    if (!hash_opt.has_value())
      return std::nullopt;
    return getBlock(*hash_opt);
  }

  std::optional<BlockHeader> ChainDB::getHeader(const Crypto::Hash &hash) const
  {
    auto block_opt = getBlock(hash);
    if (!block_opt.has_value())
      return std::nullopt;
    return block_opt->header;
  }

  std::optional<BlockHeader> ChainDB::getHeaderByHeight(uint64_t height) const
  {
    auto block_opt = getBlockByHeight(height);
    if (!block_opt.has_value())
      return std::nullopt;
    return block_opt->header;
  }

  std::optional<Crypto::Hash> ChainDB::getHashByHeight(uint64_t height) const
  {
    uint8_t height_key[8];
    for (int i = 0; i < 8; ++i)
      height_key[i] = uint8_t(height >> (i * 8));

    std::vector<uint8_t> hash_bytes;
    if (!db_.rawGet(TBL_BLOCKS_BY_HEIGHT,
                    height_key, sizeof(height_key),
                    hash_bytes))
    {
      return std::nullopt;
    }

    if (hash_bytes.size() != 32)
      return std::nullopt;

    Crypto::Hash hash;
    std::memcpy(hash.data.data(), hash_bytes.data(), 32);
    return hash;
  }

  //  Chain navigation

  bool ChainDB::hasBlock(const Crypto::Hash &hash) const
  {
    std::vector<uint8_t> out;
    return db_.rawGet(TBL_BLOCKS_BY_HASH,
                      hash.data.data(), hash.data.size(),
                      out);
  }

  bool ChainDB::hasBlockAtHeight(uint64_t height) const
  {
    return getHashByHeight(height).has_value();
  }

  //  Receipts

  void ChainDB::storeReceipt(const Crypto::Hash &tx_hash,
                             uint64_t block_height,
                             uint32_t tx_index,
                             const std::vector<uint8_t> &serialized_receipt)
  {
    // Key = tx_hash (32 bytes). Value = height (8) || tx_index (4) || receipt.
    std::vector<uint8_t> value;
    value.reserve(12 + serialized_receipt.size());

    for (int i = 0; i < 8; ++i)
      value.push_back(uint8_t(block_height >> (i * 8)));
    for (int i = 0; i < 4; ++i)
      value.push_back(uint8_t(tx_index >> (i * 8)));
    value.insert(value.end(), serialized_receipt.begin(), serialized_receipt.end());

    db_.rawPut(TBL_RECEIPTS,
               tx_hash.data.data(), tx_hash.data.size(),
               value.data(), value.size());
  }

  bool ChainDB::getReceipt(const Crypto::Hash &tx_hash,
                           std::vector<uint8_t> &out) const
  {
    std::vector<uint8_t> raw;
    if (!db_.rawGet(TBL_RECEIPTS,
                    tx_hash.data.data(), tx_hash.data.size(),
                    raw))
    {
      return false;
    }

    // Stored value layout: height (8 LE) || tx_index (4 LE) || receipt.
    // We strip the metadata here so callers get just the receipt.
    if (raw.size() < 12)
      return false;

    out.assign(raw.begin() + 12, raw.end());
    return true;
  }

  //  Chain head

  ChainDB::ChainHead ChainDB::getHead() const
  {
    ChainHead head;
    std::vector<uint8_t> bytes;

    if (!db_.getMeta("chain_head", bytes))
    {
      return head; // zero
    }

    if (bytes.size() < 40)
      return head; // 32-byte hash + 8-byte height

    std::memcpy(head.hash.data.data(), bytes.data(), 32);
    for (int i = 0; i < 8; ++i)
    {
      head.height |= uint64_t(bytes[32 + i]) << (i * 8);
    }

    return head;
  }

  void ChainDB::setHead(const ChainHead &head)
  {
    std::vector<uint8_t> bytes(40);
    std::memcpy(bytes.data(), head.hash.data.data(), 32);
    for (int i = 0; i < 8; ++i)
    {
      bytes[32 + i] = uint8_t(head.height >> (i * 8));
    }
    db_.putMeta("chain_head", bytes);
  }

  //  Best peer height

  uint64_t ChainDB::getBestPeerHeight() const
  {
    std::vector<uint8_t> bytes;
    if (!db_.getMeta("best_peer_height", bytes))
    {
      return 0;
    }
    uint64_t h = 0;
    for (int i = 0; i < 8 && i < (int)bytes.size(); ++i)
    {
      h |= uint64_t(bytes[i]) << (i * 8);
    }
    return h;
  }

  void ChainDB::setBestPeerHeight(uint64_t height)
  {
    std::vector<uint8_t> bytes(8);
    for (int i = 0; i < 8; ++i)
      bytes[i] = uint8_t(height >> (i * 8));
    db_.putMeta("best_peer_height", bytes);
  }

  //  Chain metadata

  uint64_t ChainDB::getChainId() const
  {
    std::vector<uint8_t> bytes;
    if (!db_.getMeta("chain_id", bytes))
    {
      return 0;
    }
    uint64_t id = 0;
    for (int i = 0; i < 8 && i < (int)bytes.size(); ++i)
    {
      id |= uint64_t(bytes[i]) << (i * 8);
    }
    return id;
  }

  void ChainDB::setChainId(uint64_t chain_id)
  {
    db_.putMeta("chain_id", encodeU64(chain_id));
  }

  Crypto::Hash ChainDB::getGenesisHash() const
  {
    Crypto::Hash h;
    std::vector<uint8_t> bytes;
    if (!db_.getMeta("genesis_hash", bytes))
    {
      return h;
    }
    if (bytes.size() >= 32)
    {
      std::memcpy(h.data.data(), bytes.data(), 32);
    }
    return h;
  }

  void ChainDB::setGenesisHash(const Crypto::Hash &hash)
  {
    db_.putMeta("genesis_hash", encodeHash(hash));
  }

  //  Diagnostics

  size_t ChainDB::blockCount() const
  {
    return db_.entryCount(TBL_BLOCKS_BY_HEIGHT);
  }

  void ChainDB::pruneBelowHeight(uint64_t /*height*/)
  {
    // For v1, we keep all blocks. Archive mode is always on.
    // Future: implement pruning for light nodes.
  }

  //  Helpers

  Crypto::Hash ChainDB::computeBlockHash(const BlockHeader &header)
  {
    return header.hash();
  }

  std::vector<uint8_t> ChainDB::encodeU64(uint64_t v)
  {
    std::vector<uint8_t> out(8);
    for (int i = 0; i < 8; ++i)
      out[i] = uint8_t(v >> (i * 8));
    return out;
  }

  bool ChainDB::decodeU64(const uint8_t *data, size_t len, uint64_t &out)
  {
    if (len < 8)
      return false;
    out = 0;
    for (int i = 0; i < 8; ++i)
      out |= uint64_t(data[i]) << (i * 8);
    return true;
  }

  std::vector<uint8_t> ChainDB::encodeHash(const Crypto::Hash &h)
  {
    return std::vector<uint8_t>(h.data.begin(), h.data.end());
  }

  bool ChainDB::decodeHash(const uint8_t *data, size_t len, Crypto::Hash &out)
  {
    if (len < 32)
      return false;
    std::memcpy(out.data.data(), data, 32);
    return true;
  }

  //  Txn-aware block storage

  void ChainDB::storeBlockTxn(State::StateDB::Txn &txn,
                              const Block &block,
                              const Crypto::Hash &hash)
  {
    std::vector<uint8_t> block_bytes = block.serialize();

    txn.put(TBL_BLOCKS_BY_HASH,
            hash.data.data(), hash.data.size(),
            block_bytes.data(), block_bytes.size());

    uint64_t height = block.header.height;
    uint8_t height_key[8];
    for (int i = 0; i < 8; ++i)
      height_key[i] = uint8_t(height >> (i * 8));

    txn.put(TBL_BLOCKS_BY_HEIGHT,
            height_key, sizeof(height_key),
            hash.data.data(), hash.data.size());
  }

  void ChainDB::setHeadTxn(State::StateDB::Txn &txn, const ChainHead &head)
  {
    std::vector<uint8_t> bytes(40);
    std::memcpy(bytes.data(), head.hash.data.data(), 32);
    for (int i = 0; i < 8; ++i)
    {
      bytes[32 + i] = uint8_t(head.height >> (i * 8));
    }
    txn.put(TBL_META,
            "chain_head", 10,
            bytes.data(), bytes.size());
  }

} // namespace Core