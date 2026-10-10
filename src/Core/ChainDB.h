// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Block.h"
#include "Crypto/Types.h"
#include "State/StateDB.h"

namespace Core
{
  //  ChainDB
  //
  //  Persistent block storage. Uses MDBX tables exposed via StateDB's
  //  raw access API. Not consensus-critical: the canonical source of truth
  //  is the state root, and blocks can be re-downloaded if storage is lost.
  //
  //  Tables used (added to StateDB):
  //    - blocks_by_hash:   block_hash (32B) → serialized Block
  //    - blocks_by_height: height (8B LE)   → block_hash (32B)
  //    - receipts:         tx_hash (32B)    → height(8) || tx_index(4) || receipt
  //    - meta:             "chain_head"     → 32B hash + 8B height
  //
  //  All methods are safe to call from multiple threads. The underlying
  //  StateDB serializes writes internally.

  struct BlockLookupResult
  {
    bool found{false};
    Block block;
    Crypto::Hash hash{};
  };

  class ChainDB
  {
  public:
    explicit ChainDB(State::StateDB &db);

    // ---- Block storage ----

    void storeBlock(const Block &block);
    void storeBlock(const Block &block, const Crypto::Hash &hash);

    // Txn-aware variants. Writes go through the given txn so the caller
    // can commit block index writes atomically with state writes.
    void storeBlockTxn(State::StateDB::Txn &txn,
                       const Block &block,
                       const Crypto::Hash &hash);

    void storeBlockTxn(State::StateDB::Txn &txn,
                       const Block &block)
    {
      storeBlockTxn(txn, block, block.hash());
    }

    // ---- Block retrieval ----

    std::optional<Block> getBlock(const Crypto::Hash &hash) const;
    std::optional<Block> getBlockByHeight(uint64_t height) const;
    std::optional<BlockHeader> getHeader(const Crypto::Hash &hash) const;
    std::optional<BlockHeader> getHeaderByHeight(uint64_t height) const;
    std::optional<Crypto::Hash> getHashByHeight(uint64_t height) const;

    // ---- Chain navigation ----

    bool hasBlock(const Crypto::Hash &hash) const;
    bool hasBlockAtHeight(uint64_t height) const;

    // ---- Receipts ----
    //
    // The receipt write path is txn-aware. Node::applyCommittedBlock
    // writes every receipt inside the same MDBX txn as the block and
    // head it belongs to, so a crash cannot leave a confirmed tx
    // whose receipt is missing. Layout:
    //
    //   key   = tx_hash (32 bytes)
    //   value = block_height (8 LE) || tx_index (4 LE) || receipt bytes
    //
    // The RPC reads via getReceipt(), which strips the 12-byte prefix
    // and returns just the receipt payload.

    void storeReceipt(const Crypto::Hash &tx_hash,
                      uint64_t block_height,
                      uint32_t tx_index,
                      const std::vector<uint8_t> &serialized_receipt);

    void storeReceiptTxn(State::StateDB::Txn &txn,
                         const Crypto::Hash &tx_hash,
                         uint64_t block_height,
                         uint32_t tx_index,
                         const std::vector<uint8_t> &serialized_receipt);

    bool getReceipt(const Crypto::Hash &tx_hash,
                    std::vector<uint8_t> &out) const;

    // ---- Chain head ----

    struct ChainHead
    {
      Crypto::Hash hash{};
      uint64_t height{0};
    };

    ChainHead getHead() const;
    void setHead(const ChainHead &head);

    void setHeadTxn(State::StateDB::Txn &txn, const ChainHead &head);

    uint64_t getBestPeerHeight() const;
    void setBestPeerHeight(uint64_t height);

    // ---- Chain metadata ----

    uint64_t getChainId() const;
    void setChainId(uint64_t chain_id);

    Crypto::Hash getGenesisHash() const;
    void setGenesisHash(const Crypto::Hash &hash);

    // ---- Diagnostics ----

    size_t blockCount() const;
    void pruneBelowHeight(uint64_t height);

    // ---- Transaction index ----

    struct TxLocation
    {
      Crypto::Hash block_hash{};
      uint64_t block_height{0};
      uint32_t tx_index{0};
    };

    std::optional<TxLocation> getTxLocation(const Crypto::Hash &txid) const;

  private:
    static Crypto::Hash computeBlockHash(const BlockHeader &header);

    static std::vector<uint8_t> encodeU64(uint64_t v);
    static bool decodeU64(const uint8_t *data, size_t len, uint64_t &out);
    static std::vector<uint8_t> encodeHash(const Crypto::Hash &h);
    static bool decodeHash(const uint8_t *data, size_t len, Crypto::Hash &out);

    static std::vector<uint8_t> encodeTxLocation(const TxLocation &loc);
    static bool decodeTxLocation(const uint8_t *data, size_t len, TxLocation &out);

    State::StateDB &db_;
  };

} // namespace Core