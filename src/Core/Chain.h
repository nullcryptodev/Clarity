// src/Core/Chain.h

#pragma once

#include <cstdint>
#include <mutex>
#include <optional>

#include "ChainDB.h"
#include "Crypto/Types.h"

namespace Core
{
  //  Chain
  //
  //  High-level chain API. Wraps ChainDB with a mutex, tracks the head,
  //  and provides methods for the node's main loop.

  class Chain
  {
  public:
    explicit Chain(ChainDB &db);

    // ---- Head ----

    ChainDB::ChainHead head() const;

    // Set a new head after a block is confirmed. Validates that the
    // block extends the current head.
    bool setHead(const Crypto::Hash &hash, uint64_t height);

    uint64_t height() const;
    Crypto::Hash headHash() const;

    // ---- Block access ----

    std::optional<Block> getBlock(const Crypto::Hash &hash) const;
    std::optional<Block> getBlockByHeight(uint64_t height) const;

    bool hasBlock(const Crypto::Hash &hash) const;

    // ---- Chain append ----

    // Attempt to append a new block. Checks that it extends the current
    // head. Stores the block and updates the head on success.
    //
    // Returns:
    //   AppendResult::Ok                 — block stored, head updated
    //   AppendResult::AlreadyHave        — block already stored
    //   AppendResult::NotConnected       — parent not in our chain
    //   AppendResult::InvalidParent      — parent hash doesn't match head
    //   AppendResult::StorageError       — DB write failed
    enum class AppendResult
    {
      Ok,
      AlreadyHave,
      NotConnected,
      InvalidParent,
      StorageError,
    };

    AppendResult appendBlock(const Block &block);

    // ---- Best peer height ----

    uint64_t bestPeerHeight() const;
    void setBestPeerHeight(uint64_t height);

    // True if we're behind the best peer by more than a threshold.
    bool isSyncing() const;

  private:
    ChainDB &db_;
    mutable std::mutex mutex_;
  };

} // namespace Core