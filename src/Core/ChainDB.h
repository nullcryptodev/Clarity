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
  //    - receipts:         tx_hash (32B)    → serialized Receipt (already exists)
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

    // Store a block. The block's hash is computed from its header.
    // Idempotent: re-storing the same block is a no-op.
    void storeBlock(const Block &block);

    // Store a block with a pre-computed hash. Used for genesis where the
    // hash is derived from the block itself, and for testing.
    void storeBlock(const Block &block, const Crypto::Hash &hash);

    // Txn-aware variants. Writes go through the given txn so the caller
    // can commit block index writes atomically with state writes.
    //
    // Use this from Node::applyCommittedBlock: without it, the state is
    // committed in one txn and the block index in another, and a crash
    // between the two leaves state ahead of the chain head.
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

    void storeReceipt(const Crypto::Hash &tx_hash,
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

    // Txn-aware head update. Same rationale as storeBlockTxn: the head
    // must advance in the same atomic unit as the block it points to.
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

  private:
    static Crypto::Hash computeBlockHash(const BlockHeader &header);

    static std::vector<uint8_t> encodeU64(uint64_t v);
    static bool decodeU64(const uint8_t *data, size_t len, uint64_t &out);
    static std::vector<uint8_t> encodeHash(const Crypto::Hash &h);
    static bool decodeHash(const uint8_t *data, size_t len, Crypto::Hash &out);

    State::StateDB &db_;
  };

} // namespace Core