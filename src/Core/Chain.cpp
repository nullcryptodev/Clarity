// src/Core/Chain.cpp

#include "Chain.h"

namespace Core
{

  Chain::Chain(ChainDB &db)
      : db_(db)
  {
  }

  ChainDB::ChainHead Chain::head() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.getHead();
  }

  bool Chain::setHead(const Crypto::Hash &hash, uint64_t height)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    ChainDB::ChainHead h;
    h.hash = hash;
    h.height = height;
    db_.setHead(h);
    return true;
  }

  uint64_t Chain::height() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.getHead().height;
  }

  Crypto::Hash Chain::headHash() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.getHead().hash;
  }

  std::optional<Block> Chain::getBlock(const Crypto::Hash &hash) const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.getBlock(hash);
  }

  std::optional<Block> Chain::getBlockByHeight(uint64_t height) const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.getBlockByHeight(height);
  }

  bool Chain::hasBlock(const Crypto::Hash &hash) const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.hasBlock(hash);
  }

  Chain::AppendResult Chain::appendBlock(const Block &block)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    Crypto::Hash block_hash = block.hash();

    // Already have it?
    if (db_.hasBlock(block_hash))
    {
      return AppendResult::AlreadyHave;
    }

    // Genesis: height 0, no parent.
    if (block.header.height == 0)
    {
      try
      {
        db_.storeBlock(block, block_hash);
        ChainDB::ChainHead h;
        h.hash = block_hash;
        h.height = 0;
        db_.setHead(h);
        db_.setGenesisHash(block_hash);
        return AppendResult::Ok;
      }
      catch (...)
      {
        return AppendResult::StorageError;
      }
    }

    // Regular block: must extend the current head.
    ChainDB::ChainHead current = db_.getHead();

    if (block.header.parent_hash != current.hash)
    {
      // Parent doesn't match head. Could be a fork, or a block we haven't
      // seen the parent of yet.
      if (db_.hasBlock(block.header.parent_hash))
      {
        // Parent exists but isn't our head — we have a fork, which BFT
        // shouldn't allow. Reject.
        return AppendResult::InvalidParent;
      }
      // Parent unknown. Block arrives before its parent.
      return AppendResult::NotConnected;
    }

    // Height must be current.height + 1.
    if (block.header.height != current.height + 1)
    {
      return AppendResult::InvalidParent;
    }

    // Store.
    try
    {
      db_.storeBlock(block, block_hash);
    }
    catch (...)
    {
      return AppendResult::StorageError;
    }

    // Update head.
    ChainDB::ChainHead h;
    h.hash = block_hash;
    h.height = block.header.height;
    db_.setHead(h);

    return AppendResult::Ok;
  }

  uint64_t Chain::bestPeerHeight() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_.getBestPeerHeight();
  }

  void Chain::setBestPeerHeight(uint64_t height)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    db_.setBestPeerHeight(height);
  }

  bool Chain::isSyncing() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t ours = db_.getHead().height;
    uint64_t theirs = db_.getBestPeerHeight();
    return theirs > ours + 5; // 5 blocks of tolerance
  }

} // namespace Core