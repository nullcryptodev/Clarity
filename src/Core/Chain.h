// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
  //  High-level chain API. Wraps ChainDB.
  //
  //  Threading: reads are lock-free (ChainDB / StateDB are MVCC).
  //  mutex_ guards head updates and best_peer_height updates, so the
  //  read-modify-write sequences on those two fields are atomic.
  //
  //  Do NOT re-add mutex_ to the read methods. The RPC layer calls
  //  getBlockByHeight() from inside StateDB iteration visitors; if
  //  that read took mutex_, it would still be safe (different lock),
  //  but it would serialize all chain reads against each other for
  //  no benefit and create a lock-order surface between Chain and
  //  StateDB that produced the earlier self-deadlock.

  class Chain
  {
  public:
    explicit Chain(ChainDB &db);

    // ---- Head ----

    ChainDB::ChainHead head() const;

    bool setHead(const Crypto::Hash &hash, uint64_t height);

    uint64_t height() const;
    Crypto::Hash headHash() const;

    // ---- Block access ----

    std::optional<Block> getBlock(const Crypto::Hash &hash) const;
    std::optional<Block> getBlockByHeight(uint64_t height) const;

    bool hasBlock(const Crypto::Hash &hash) const;

    // ---- Chain append ----

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

    bool isSyncing() const;

  private:
    ChainDB &db_;
    mutable std::mutex mutex_;
  };

} // namespace Core