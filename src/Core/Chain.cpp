// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Chain.h"

namespace Core
{

  Chain::Chain(ChainDB &db)
      : db_(db)
  {
  }

  //  Reads — no lock.
  //
  //  Every method below reads from ChainDB / StateDB, both of which
  //  use MDBX read transactions. MDBX readers are MVCC and require
  //  no external synchronization. Holding Chain::mutex_ here would
  //  only serialize reads against each other, and — more importantly
  //  — would create a lock that callers into StateDB iteration
  //  visitors would have to acquire while already inside a
  //  StateDB-level operation. That was the shape of the earlier
  //  self-deadlock. Do not re-add.

  ChainDB::ChainHead Chain::head() const
  {
    return db_.getHead();
  }

  uint64_t Chain::height() const
  {
    return db_.getHead().height;
  }

  Crypto::Hash Chain::headHash() const
  {
    return db_.getHead().hash;
  }

  std::optional<Block> Chain::getBlock(const Crypto::Hash &hash) const
  {
    return db_.getBlock(hash);
  }

  std::optional<Block> Chain::getBlockByHeight(uint64_t height) const
  {
    return db_.getBlockByHeight(height);
  }

  bool Chain::hasBlock(const Crypto::Hash &hash) const
  {
    return db_.hasBlock(hash);
  }

  uint64_t Chain::bestPeerHeight() const
  {
    return db_.getBestPeerHeight();
  }

  bool Chain::isSyncing() const
  {
    const uint64_t ours = db_.getHead().height;
    const uint64_t theirs = db_.getBestPeerHeight();
    return theirs > ours + 5;
  }

  //  Writes — mutex_ held.
  //
  //  setHead, setBestPeerHeight, and appendBlock each perform a
  //  read-modify-write against persisted state. mutex_ makes those
  //  atomic with respect to each other within this process.

  bool Chain::setHead(const Crypto::Hash &hash, uint64_t height)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    ChainDB::ChainHead h;
    h.hash = hash;
    h.height = height;
    db_.setHead(h);
    return true;
  }

  Chain::AppendResult Chain::appendBlock(const Block &block)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    Crypto::Hash block_hash = block.hash();

    if (db_.hasBlock(block_hash))
    {
      return AppendResult::AlreadyHave;
    }

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

    ChainDB::ChainHead current = db_.getHead();

    if (block.header.parent_hash != current.hash)
    {
      if (db_.hasBlock(block.header.parent_hash))
      {
        return AppendResult::InvalidParent;
      }
      return AppendResult::NotConnected;
    }

    if (block.header.height != current.height + 1)
    {
      return AppendResult::InvalidParent;
    }

    try
    {
      db_.storeBlock(block, block_hash);
    }
    catch (...)
    {
      return AppendResult::StorageError;
    }

    ChainDB::ChainHead h;
    h.hash = block_hash;
    h.height = block.header.height;
    db_.setHead(h);

    return AppendResult::Ok;
  }

  void Chain::setBestPeerHeight(uint64_t height)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    db_.setBestPeerHeight(height);
  }

} // namespace Core