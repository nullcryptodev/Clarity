// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateDB.h"

#include <array>
#include <cstring>
#include <filesystem>
#include <stdexcept>

namespace State
{

  //  Per-thread read-txn handle. See the comment on the declaration
  //  in StateDB.h. Zero-initialized for every thread by the C++
  //  runtime.
  thread_local MDBX_txn *StateDB::tls_read_txn_ = nullptr;

  //  Table names

  const char *StateDB::tableName(uint32_t id) noexcept
  {
    switch (id)
    {
    case TBL_SMT_NODES:
      return "smt_nodes";
    case TBL_SMT_LEAVES:
      return "smt_leaves";
    case TBL_META:
      return "meta";
    case TBL_ACCOUNTS:
      return "accounts";
    case TBL_TOKEN_BALANCES:
      return "token_balances";
    case TBL_TOKENS:
      return "tokens";
    case TBL_VALIDATORS:
      return "validators";
    case TBL_ORDERS:
      return "orders";
    case TBL_INDEX_STAKERS:
      return "index_stakers";
    case TBL_INDEX_VALIDATORS:
      return "index_validators";
    case TBL_INDEX_ORDERS_EXPIRY:
      return "index_orders_expiry";
    case TBL_RECEIPTS:
      return "receipts";
    case TBL_TX_INDEX:
      return "tx_index";
    case TBL_BLOCKS_BY_HASH:
      return "blocks_by_hash";
    case TBL_BLOCKS_BY_HEIGHT:
      return "blocks_by_height";
    case TBL_MEMPOOL:
      return "mempool";
    case TBL_CONSENSUS_WAL:
      return "consensus_wal";
    case TBL_SMT_NODES_HIST:
      return "smt_nodes_hist";
    case TBL_SMT_LEAVES_HIST:
      return "smt_leaves_hist";
    case TBL_SMT_NODES_BY_VER:
      return "smt_nodes_by_ver";
    case TBL_SMT_LEAVES_BY_VER:
      return "smt_leaves_by_ver";
    case TBL_AMM_POOLS:
      return "amm_pools";
    case TBL_AMM_POSITIONS:
      return "amm_positions";
    case TBL_INDEX_POSITIONS_BY_OWNER:
      return "index_positions_by_owner";
    case TBL_INDEX_ORDERS_BY_OWNER:
      return "index_orders_by_owner";
    case TBL_INDEX_BALANCES_BY_TOKEN:
      return "index_balances_by_token";
    case TBL_INDEX_POOLS_BY_TOKEN:
      return "index_pools_by_token";
    case TBL_INDEX_TX_BY_ADDRESS:
      return "index_tx_by_address";
    case TBL_INDEX_TX_BY_TOKEN:
      return "index_tx_by_token";
    case TBL_INDEX_TX_BY_TYPE:
      return "index_tx_by_type";
    case TBL_INDEX_BLOCKS_BY_PRODUCER:
      return "index_blocks_by_producer";
    case TBL_INDEX_ORDERS_BY_PAIR:
      return "index_orders_by_pair";
    default:
      return "<unknown>";
    }
  }

  //  Helpers

  namespace
  {
    [[noreturn]] void throwMdbx(const char *what, int rc)
    {
      throw StateDBError(std::string(what) + ": " + mdbx_strerror(rc));
    }

    std::array<uint8_t, 40> histKey(const Crypto::Hash &hash, uint64_t version)
    {
      std::array<uint8_t, 40> k{};
      std::memcpy(k.data(), hash.data.data(), 32);
      for (int i = 0; i < 8; ++i)
        k[32 + i] = uint8_t(version >> ((7 - i) * 8));
      return k;
    }

    std::array<uint8_t, 40> byVersionKey(uint64_t version, const Crypto::Hash &hash)
    {
      std::array<uint8_t, 40> k{};
      for (int i = 0; i < 8; ++i)
        k[i] = uint8_t(version >> ((7 - i) * 8));
      std::memcpy(k.data() + 8, hash.data.data(), 32);
      return k;
    }

    uint64_t readVersionBE(const uint8_t *p)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
      return v;
    }

    template <typename ForEachFn, typename DelFn>
    void pruneOneTableImpl(ForEachFn &&forEach,
                           DelFn &&del,
                           uint32_t index_table,
                           uint32_t hist_table,
                           uint64_t keepFrom)
    {
      std::vector<std::array<uint8_t, 40>> to_delete;

      forEach(index_table,
              [&](const std::vector<uint8_t> &key,
                  const std::vector<uint8_t> &) -> bool
              {
                if (key.size() != 40)
                  return true;

                const uint64_t version = readVersionBE(key.data());
                if (version >= keepFrom)
                  return false;

                std::array<uint8_t, 40> k{};
                std::memcpy(k.data(), key.data(), 40);
                to_delete.push_back(k);
                return true;
              });

      for (const auto &k : to_delete)
      {
        del(index_table, k.data(), k.size());

        std::array<uint8_t, 40> hist_key{};
        std::memcpy(hist_key.data(), k.data() + 8, 32);
        std::memcpy(hist_key.data() + 32, k.data(), 8);

        del(hist_table, hist_key.data(), hist_key.size());
      }
    }
  } // anonymous namespace

  MDBX_val StateDB::toVal(const void *data, size_t len)
  {
    MDBX_val v;
    v.iov_base = const_cast<void *>(data);
    v.iov_len = len;
    return v;
  }

  MDBX_val StateDB::toVal(const std::string &s)
  {
    return toVal(s.data(), s.size());
  }

  MDBX_dbi StateDB::tableHandle(uint32_t tableId) const noexcept
  {
    if (tableId >= TBL_COUNT)
      return 0;
    return tables_[tableId];
  }

  // =================================================================
  //  Txn (write)
  // =================================================================

  StateDB::Txn::Txn(MDBX_txn *txn, StateDB *owner) noexcept
      : txn_(txn), owner_(owner), open_(true)
  {
  }

  StateDB::Txn::Txn(Txn &&other) noexcept
      : txn_(other.txn_), owner_(other.owner_), open_(other.open_)
  {
    other.txn_ = nullptr;
    other.owner_ = nullptr;
    other.open_ = false;
  }

  StateDB::Txn &StateDB::Txn::operator=(Txn &&other) noexcept
  {
    if (this != &other)
    {
      if (open_ && txn_)
      {
        mdbx_txn_abort(txn_);
      }
      txn_ = other.txn_;
      owner_ = other.owner_;
      open_ = other.open_;
      other.txn_ = nullptr;
      other.owner_ = nullptr;
      other.open_ = false;
    }
    return *this;
  }

  StateDB::Txn::~Txn()
  {
    if (open_ && txn_)
    {
      mdbx_txn_abort(txn_);
    }
  }

  void StateDB::Txn::put(uint32_t tableId,
                         const void *key, size_t keyLen,
                         const void *value, size_t valueLen)
  {
    if (!open_)
      throw StateDBError("Txn::put on closed txn");

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv = (value != nullptr) ? toVal(value, valueLen) : toVal("", 0);

    int rc = mdbx_put(txn_, owner_->tableHandle(tableId), &mk, &mv, MDBX_UPSERT);
    if (rc != MDBX_SUCCESS)
      throwMdbx("Txn::put", rc);
  }

  bool StateDB::Txn::get(uint32_t tableId,
                         const void *key, size_t keyLen,
                         std::vector<uint8_t> &out) const
  {
    if (!open_)
      throw StateDBError("Txn::get on closed txn");

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv;
    int rc = mdbx_get(txn_, owner_->tableHandle(tableId), &mk, &mv);
    if (rc == MDBX_NOTFOUND)
      return false;
    if (rc != MDBX_SUCCESS)
      throwMdbx("Txn::get", rc);

    out.assign(static_cast<const uint8_t *>(mv.iov_base),
               static_cast<const uint8_t *>(mv.iov_base) + mv.iov_len);
    return true;
  }

  void StateDB::Txn::del(uint32_t tableId, const void *key, size_t keyLen)
  {
    if (!open_)
      throw StateDBError("Txn::del on closed txn");

    MDBX_val mk = toVal(key, keyLen);
    mdbx_del(txn_, owner_->tableHandle(tableId), &mk, nullptr);
  }

  bool StateDB::Txn::has(uint32_t tableId, const void *key, size_t keyLen) const
  {
    std::vector<uint8_t> out;
    return get(tableId, key, keyLen, out);
  }

  void StateDB::Txn::forEach(uint32_t tableId,
                             const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("Txn::forEach on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_FIRST);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);
      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::Txn::forEachWithPrefix(
      uint32_t tableId,
      const std::vector<uint8_t> &prefix,
      const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("Txn::forEachWithPrefix on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_val mkey, mval;
    mkey.iov_base = const_cast<void *>(static_cast<const void *>(prefix.data()));
    mkey.iov_len = prefix.size();
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_SET_RANGE);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);

      if (key.size() < prefix.size() ||
          std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)
      {
        break;
      }

      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::Txn::forEachReverse(
      uint32_t tableId,
      const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("Txn::forEachReverse on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);
      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::Txn::forEachWithPrefixReverse(
      uint32_t tableId,
      const std::vector<uint8_t> &prefix,
      const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("Txn::forEachWithPrefixReverse on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    std::vector<uint8_t> upper = prefix;
    while (!upper.empty() && upper.back() == 0xFF)
      upper.pop_back();
    if (!upper.empty())
      ++upper.back();

    MDBX_val mkey, mval;
    if (upper.empty())
    {
      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);
    }
    else
    {
      mkey.iov_base = const_cast<void *>(static_cast<const void *>(upper.data()));
      mkey.iov_len = upper.size();
      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_SET_RANGE);
      if (rc == MDBX_SUCCESS)
      {
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
      }
      else if (rc == MDBX_NOTFOUND)
      {
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);
      }
    }

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);

      if (key.size() < prefix.size() ||
          std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)
      {
        break;
      }

      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::Txn::commit()
  {
    if (!open_)
      return;

    int rc = mdbx_txn_commit(txn_);
    open_ = false;
    txn_ = nullptr;

    if (rc != MDBX_SUCCESS)
      throwMdbx("Txn::commit", rc);
  }

  void StateDB::Txn::abort()
  {
    if (!open_)
      return;

    mdbx_txn_abort(txn_);
    open_ = false;
    txn_ = nullptr;
  }

  bool StateDB::Txn::isOpen() const noexcept
  {
    return open_;
  }

  // =================================================================
  //  ReadTxn
  // =================================================================

  StateDB::ReadTxn::ReadTxn(MDBX_txn *txn, StateDB *owner,
                            bool owns, MDBX_txn *prev_tls) noexcept
      : txn_(txn), owner_(owner), open_(txn != nullptr),
        owns_txn_(owns), prev_tls_(prev_tls)
  {
  }

  StateDB::ReadTxn::ReadTxn(ReadTxn &&other) noexcept
      : txn_(other.txn_), owner_(other.owner_), open_(other.open_),
        owns_txn_(other.owns_txn_), prev_tls_(other.prev_tls_)
  {
    other.txn_ = nullptr;
    other.owner_ = nullptr;
    other.open_ = false;
    other.owns_txn_ = false;
    other.prev_tls_ = nullptr;
  }

  StateDB::ReadTxn &StateDB::ReadTxn::operator=(ReadTxn &&other) noexcept
  {
    if (this != &other)
    {
      //  Release whatever we currently hold before taking the
      //  other's. If we own the txn, abort it and restore the
      //  thread-local to what it was when we were created.
      if (open_ && owns_txn_ && txn_)
      {
        tls_read_txn_ = prev_tls_;
        mdbx_txn_abort(txn_);
      }

      txn_ = other.txn_;
      owner_ = other.owner_;
      open_ = other.open_;
      owns_txn_ = other.owns_txn_;
      prev_tls_ = other.prev_tls_;

      other.txn_ = nullptr;
      other.owner_ = nullptr;
      other.open_ = false;
      other.owns_txn_ = false;
      other.prev_tls_ = nullptr;
    }
    return *this;
  }

  StateDB::ReadTxn::~ReadTxn()
  {
    if (open_ && owns_txn_ && txn_)
    {
      //  Restore the thread-local to whatever it was before we
      //  opened our own read txn. In the common case that's
      //  nullptr. If a nested ReadTxn was created on top of ours,
      //  that nested one's prev_tls_ points at our txn, but the
      //  nested one doesn't own, so it doesn't touch the
      //  thread-local. Only the owner clears.
      tls_read_txn_ = prev_tls_;
      mdbx_txn_abort(txn_);
    }
    open_ = false;
    txn_ = nullptr;
  }

  bool StateDB::ReadTxn::get(uint32_t tableId,
                             const void *key, size_t keyLen,
                             std::vector<uint8_t> &out) const
  {
    if (!open_)
      throw StateDBError("ReadTxn::get on closed txn");

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv;
    int rc = mdbx_get(txn_, owner_->tableHandle(tableId), &mk, &mv);
    if (rc == MDBX_NOTFOUND)
      return false;
    if (rc != MDBX_SUCCESS)
      throwMdbx("ReadTxn::get", rc);

    out.assign(static_cast<const uint8_t *>(mv.iov_base),
               static_cast<const uint8_t *>(mv.iov_base) + mv.iov_len);
    return true;
  }

  void StateDB::ReadTxn::forEach(uint32_t tableId,
                                 const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("ReadTxn::forEach on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_FIRST);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);
      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::ReadTxn::forEachWithPrefix(
      uint32_t tableId,
      const std::vector<uint8_t> &prefix,
      const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("ReadTxn::forEachWithPrefix on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_val mkey, mval;
    mkey.iov_base = const_cast<void *>(static_cast<const void *>(prefix.data()));
    mkey.iov_len = prefix.size();
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_SET_RANGE);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);

      if (key.size() < prefix.size() ||
          std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)
      {
        break;
      }

      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::ReadTxn::forEachReverse(
      uint32_t tableId,
      const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("ReadTxn::forEachReverse on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);
      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
    }

    mdbx_cursor_close(cursor);
  }

  void StateDB::ReadTxn::forEachWithPrefixReverse(
      uint32_t tableId,
      const std::vector<uint8_t> &prefix,
      const EntryVisitor &visitor) const
  {
    if (!open_)
      throw StateDBError("ReadTxn::forEachWithPrefixReverse on closed txn");

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn_, owner_->tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
      return;

    std::vector<uint8_t> upper = prefix;
    while (!upper.empty() && upper.back() == 0xFF)
      upper.pop_back();
    if (!upper.empty())
      ++upper.back();

    MDBX_val mkey, mval;
    if (upper.empty())
    {
      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);
    }
    else
    {
      mkey.iov_base = const_cast<void *>(static_cast<const void *>(upper.data()));
      mkey.iov_len = upper.size();
      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_SET_RANGE);
      if (rc == MDBX_SUCCESS)
      {
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
      }
      else if (rc == MDBX_NOTFOUND)
      {
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);
      }
    }

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);

      if (key.size() < prefix.size() ||
          std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)
      {
        break;
      }

      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
    }

    mdbx_cursor_close(cursor);
  }

  size_t StateDB::ReadTxn::dbiStat(uint32_t tableId) const
  {
    if (!open_)
      throw StateDBError("ReadTxn::dbiStat on closed txn");

    MDBX_stat stat;
    int rc = mdbx_dbi_stat(txn_, owner_->tableHandle(tableId), &stat, sizeof(stat));
    if (rc != MDBX_SUCCESS)
      throwMdbx("ReadTxn::dbiStat", rc);
    return stat.ms_entries;
  }

  void StateDB::ReadTxn::abort()
  {
    if (!open_)
      return;

    if (owns_txn_ && txn_)
    {
      tls_read_txn_ = prev_tls_;
      mdbx_txn_abort(txn_);
    }

    open_ = false;
    txn_ = nullptr;
  }

  bool StateDB::ReadTxn::isOpen() const noexcept
  {
    return open_;
  }

  // =================================================================
  //  Construction
  // =================================================================

  StateDB::StateDB(const std::string &path, size_t mapSizeBytes)
      : mapSizeBytes_(mapSizeBytes), path_(path)
  {
    openEnv(path, mapSizeBytes);
  }

  StateDB::~StateDB()
  {
    close();
  }

  void StateDB::openEnv(const std::string &path, size_t mapSizeBytes)
  {
    std::filesystem::create_directories(path);

    int rc = mdbx_env_create(&env_);
    if (rc != MDBX_SUCCESS)
      throwMdbx("mdbx_env_create", rc);

    rc = mdbx_env_set_geometry(env_,
                               -1, -1,
                               static_cast<intptr_t>(mapSizeBytes),
                               -1, -1, -1);
    if (rc != MDBX_SUCCESS)
      throwMdbx("mdbx_env_set_geometry", rc);

    rc = mdbx_env_set_maxreaders(env_, 126);
    if (rc != MDBX_SUCCESS)
      throwMdbx("mdbx_env_set_maxreaders", rc);

    rc = mdbx_env_set_maxdbs(env_, TBL_COUNT + 1);
    if (rc != MDBX_SUCCESS)
      throwMdbx("mdbx_env_set_maxdbs", rc);

    const MDBX_env_flags_t flags = MDBX_NOSUBDIR | MDBX_NORDAHEAD | MDBX_LIFORECLAIM;

    rc = mdbx_env_open(env_, path.c_str(), flags, 0664);
    if (rc != MDBX_SUCCESS)
      throwMdbx("mdbx_env_open", rc);

    MDBX_txn *txn = nullptr;
    rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("mdbx_txn_begin", rc);

    try
    {
      openTables(txn);
    }
    catch (...)
    {
      mdbx_txn_abort(txn);
      throw;
    }

    rc = mdbx_txn_commit(txn);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("mdbx_txn_commit(init)", rc);
    }
  }

  void StateDB::openTables(MDBX_txn *txn)
  {
    for (uint32_t i = 0; i < TBL_COUNT; ++i)
    {
      int rc = mdbx_dbi_open(txn, tableName(i), MDBX_CREATE, &tables_[i]);
      if (rc != MDBX_SUCCESS)
      {
        throwMdbx("mdbx_dbi_open", rc);
      }
    }
  }

  StateDB::Txn StateDB::beginWrite()
  {
    //  MDBX refuses to open a write txn on a thread that already
    //  has a read txn open. Release any read txn first — the caller
    //  explicitly wants to write, and the next read will reopen a
    //  read txn transparently.
    releaseReadTxn();

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc == MDBX_BUSY)
    {
      throw StateDBError("beginWrite: another write txn is active");
    }
    if (rc != MDBX_SUCCESS)
      throwMdbx("beginWrite", rc);
    return Txn(txn, this);
  }

  //  Txn-aware raw access

  void StateDB::txnPut(Txn &txn, uint32_t tableId,
                       const void *key, size_t keyLen,
                       const void *value, size_t valueLen)
  {
    txn.put(tableId, key, keyLen, value, valueLen);
  }

  bool StateDB::txnGet(const Txn &txn, uint32_t tableId,
                       const void *key, size_t keyLen,
                       std::vector<uint8_t> &out) const
  {
    return txn.get(tableId, key, keyLen, out);
  }

  void StateDB::txnDel(Txn &txn, uint32_t tableId,
                       const void *key, size_t keyLen)
  {
    txn.del(tableId, key, keyLen);
  }

  // =============================================================
  //  Raw writes — these take write_mutex_ because MDBX permits
  //  only one write txn at a time. They also release any read txn
  //  on this thread first, because MDBX forbids overlapping.
  // =============================================================

  void StateDB::rawPut(uint32_t tableId,
                       const void *key, size_t keyLen,
                       const void *value, size_t valueLen)
  {
    releaseReadTxn();

    std::lock_guard<std::mutex> lock(write_mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("rawPut: txn_begin", rc);

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv = (value != nullptr) ? toVal(value, valueLen) : toVal("", 0);

    rc = mdbx_put(txn, tableHandle(tableId), &mk, &mv, MDBX_UPSERT);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("rawPut: put", rc);
    }

    rc = mdbx_txn_commit(txn);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("rawPut: commit", rc);
    }
  }

  // =============================================================
  //  Raw reads — no write mutex. MDBX readers are MVCC and
  //  concurrent-safe.
  //
  //  If a read txn is already open on this thread, reuse it. This
  //  is required by MDBX: a second overlapping read txn on the
  //  same thread returns MDBX_BUSY.
  // =============================================================

  bool StateDB::rawGet(uint32_t tableId,
                       const void *key, size_t keyLen,
                       std::vector<uint8_t> &out) const
  {
    MDBX_txn *txn = tls_read_txn_;
    const bool own_txn = (txn == nullptr);

    if (own_txn)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("rawGet: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv;
    int rc = mdbx_get(txn, tableHandle(tableId), &mk, &mv);

    bool found = false;
    if (rc == MDBX_SUCCESS)
    {
      out.assign(static_cast<const uint8_t *>(mv.iov_base),
                 static_cast<const uint8_t *>(mv.iov_base) + mv.iov_len);
      found = true;
    }
    else if (rc != MDBX_NOTFOUND)
    {
      if (own_txn)
      {
        tls_read_txn_ = nullptr;
        mdbx_txn_abort(txn);
      }
      throwMdbx("rawGet: mdbx_get", rc);
    }

    if (own_txn)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }

    return found;
  }

  void StateDB::rawDel(uint32_t tableId, const void *key, size_t keyLen)
  {
    releaseReadTxn();

    std::lock_guard<std::mutex> lock(write_mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("rawDel: txn_begin", rc);

    MDBX_val mk = toVal(key, keyLen);
    mdbx_del(txn, tableHandle(tableId), &mk, nullptr);

    rc = mdbx_txn_commit(txn);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("rawDel: commit", rc);
    }
  }

  bool StateDB::rawHas(uint32_t tableId,
                       const void *key, size_t keyLen) const
  {
    MDBX_txn *txn = tls_read_txn_;
    const bool own_txn = (txn == nullptr);

    if (own_txn)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("rawHas: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv;
    int rc = mdbx_get(txn, tableHandle(tableId), &mk, &mv);

    if (own_txn)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }

    if (rc == MDBX_SUCCESS)
      return true;
    if (rc == MDBX_NOTFOUND)
      return false;
    throwMdbx("rawHas: mdbx_get", rc);
  }

  // =============================================================
  //  Iteration — no write mutex. Visitors may re-enter StateDB;
  //  any nested read reuses the read txn opened here.
  // =============================================================

  void StateDB::forEachEntry(uint32_t tableId, const EntryVisitor &visitor) const
  {
    MDBX_txn *outer = tls_read_txn_;
    MDBX_txn *txn = outer;

    if (txn == nullptr)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("forEachEntry: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      if (outer == nullptr)
      {
        tls_read_txn_ = nullptr;
        mdbx_txn_abort(txn);
      }
      return;
    }

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_FIRST);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);
      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);

    if (outer == nullptr)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }
  }

  void StateDB::forEachEntryWithPrefix(uint32_t tableId,
                                       const std::vector<uint8_t> &prefix,
                                       const EntryVisitor &visitor) const
  {
    MDBX_txn *outer = tls_read_txn_;
    MDBX_txn *txn = outer;

    if (txn == nullptr)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("forEachEntryWithPrefix: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      if (outer == nullptr)
      {
        tls_read_txn_ = nullptr;
        mdbx_txn_abort(txn);
      }
      return;
    }

    MDBX_val mkey, mval;
    mkey.iov_base = const_cast<void *>(static_cast<const void *>(prefix.data()));
    mkey.iov_len = prefix.size();
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_SET_RANGE);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);

      if (key.size() < prefix.size() ||
          std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)
      {
        break;
      }

      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);

    if (outer == nullptr)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }
  }

  void StateDB::forEachEntryReverse(uint32_t tableId,
                                    const EntryVisitor &visitor) const
  {
    MDBX_txn *outer = tls_read_txn_;
    MDBX_txn *txn = outer;

    if (txn == nullptr)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("forEachEntryReverse: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      if (outer == nullptr)
      {
        tls_read_txn_ = nullptr;
        mdbx_txn_abort(txn);
      }
      return;
    }

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);
      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
    }

    mdbx_cursor_close(cursor);

    if (outer == nullptr)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }
  }

  void StateDB::forEachEntryWithPrefixReverse(
      uint32_t tableId,
      const std::vector<uint8_t> &prefix,
      const EntryVisitor &visitor) const
  {
    MDBX_txn *outer = tls_read_txn_;
    MDBX_txn *txn = outer;

    if (txn == nullptr)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("forEachEntryWithPrefixReverse: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_cursor *cursor = nullptr;
    int rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      if (outer == nullptr)
      {
        tls_read_txn_ = nullptr;
        mdbx_txn_abort(txn);
      }
      return;
    }

    std::vector<uint8_t> upper = prefix;
    while (!upper.empty() && upper.back() == 0xFF)
      upper.pop_back();
    if (!upper.empty())
      ++upper.back();

    MDBX_val mkey, mval;
    if (upper.empty())
    {
      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);
    }
    else
    {
      mkey.iov_base = const_cast<void *>(static_cast<const void *>(upper.data()));
      mkey.iov_len = upper.size();
      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_SET_RANGE);
      if (rc == MDBX_SUCCESS)
      {
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
      }
      else if (rc == MDBX_NOTFOUND)
      {
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_LAST);
      }
    }

    while (rc == MDBX_SUCCESS)
    {
      std::vector<uint8_t> key(
          static_cast<const uint8_t *>(mkey.iov_base),
          static_cast<const uint8_t *>(mkey.iov_base) + mkey.iov_len);

      if (key.size() < prefix.size() ||
          std::memcmp(key.data(), prefix.data(), prefix.size()) != 0)
      {
        break;
      }

      std::vector<uint8_t> value(
          static_cast<const uint8_t *>(mval.iov_base),
          static_cast<const uint8_t *>(mval.iov_base) + mval.iov_len);

      if (!visitor(key, value))
        break;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
    }

    mdbx_cursor_close(cursor);

    if (outer == nullptr)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }
  }

  // =============================================================
  //  Read txn lifecycle
  // =============================================================

  StateDB::ReadTxn StateDB::beginRead()
  {
    //  If a read txn is already open on this thread, reuse it. This
    //  is required by MDBX: a second overlapping read txn on the
    //  same thread returns MDBX_BUSY.
    if (tls_read_txn_ != nullptr)
      return ReadTxn(tls_read_txn_, this, /*owns=*/false, tls_read_txn_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("beginRead", rc);

    tls_read_txn_ = txn;
    return ReadTxn(txn, this, /*owns=*/true, nullptr);
  }

  void StateDB::releaseReadTxn() noexcept
  {
    //  Close the outermost read txn on this thread, if any. Called
    //  by every write path before opening a write txn, because MDBX
    //  refuses to open a write txn while a read txn is open on the
    //  same thread (MDBX_TXN_OVERLAPPING).
    //
    //  We do not know the previous tls_read_txn_ value here — the
    //  ReadTxn that owns the txn holds it internally. But the
    //  owning ReadTxn's destructor is what clears the thread-local,
    //  so we just abort the txn and clear the thread-local
    //  ourselves. The owning ReadTxn still thinks it has a valid
    //  handle and its destructor will try to abort again; MDBX
    //  tolerates abort on an already-aborted handle? No it does not
    //  — so instead we rely on the caller having destroyed its
    //  ReadTxn before calling us. In practice that's what happens:
    //  rawPut and rawDel are only reached when the StateAccess has
    //  already released its read_txn_ (see StateAccess.cpp's
    //  releaseReadTxnIfHeld()).
    //
    //  For the legacy per-call path (rawGet, forEachEntry*), the
    //  read txn is opened and aborted inside a single call, so it's
    //  never visible to releaseReadTxn.
    //
    //  If anything is still open, abort it and clear the handle.
    if (tls_read_txn_ != nullptr)
    {
      mdbx_txn_abort(tls_read_txn_);
      tls_read_txn_ = nullptr;
    }
  }

  // =============================================================
  //  Meta helpers
  // =============================================================

  bool StateDB::getMeta(const std::string &key, std::vector<uint8_t> &out) const
  {
    return rawGet(TBL_META, key.data(), key.size(), out);
  }

  std::optional<std::vector<uint8_t>> StateDB::getMeta(const std::string &key) const
  {
    std::vector<uint8_t> out;
    if (getMeta(key, out))
      return out;
    return std::nullopt;
  }

  void StateDB::putMeta(const std::string &key, const std::vector<uint8_t> &value)
  {
    rawPut(TBL_META, key.data(), key.size(), value.data(), value.size());
  }

  void StateDB::removeMeta(const std::string &key)
  {
    rawDel(TBL_META, key.data(), key.size());
  }

  // =============================================================
  //  SMT convenience API
  // =============================================================

  void StateDB::putNode(const Crypto::Hash &hash,
                        const std::vector<uint8_t> &children,
                        uint64_t /*version*/)
  {
    rawPut(TBL_SMT_NODES,
           hash.data.data(), hash.data.size(),
           children.data(), children.size());
  }

  bool StateDB::getNode(const Crypto::Hash &hash,
                        std::vector<uint8_t> &out) const
  {
    return rawGet(TBL_SMT_NODES, hash.data.data(), hash.data.size(), out);
  }

  std::optional<std::vector<uint8_t>> StateDB::getNode(const Crypto::Hash &hash) const
  {
    std::vector<uint8_t> out;
    if (getNode(hash, out))
      return out;
    return std::nullopt;
  }

  void StateDB::putLeafData(const Crypto::Hash &leaf_hash,
                            const std::vector<uint8_t> &value,
                            uint64_t /*version*/)
  {
    rawPut(TBL_SMT_LEAVES,
           leaf_hash.data.data(), leaf_hash.data.size(),
           value.data(), value.size());
  }

  bool StateDB::getLeafData(const Crypto::Hash &leaf_hash,
                            std::vector<uint8_t> &out) const
  {
    return rawGet(TBL_SMT_LEAVES, leaf_hash.data.data(), leaf_hash.data.size(), out);
  }

  std::optional<std::vector<uint8_t>> StateDB::getLeafData(const Crypto::Hash &leaf_hash) const
  {
    std::vector<uint8_t> out;
    if (getLeafData(leaf_hash, out))
      return out;
    return std::nullopt;
  }

  // =============================================================
  //  Historical SMT access
  // =============================================================

  void StateDB::putNodeAtVersion(const Crypto::Hash &hash,
                                 uint64_t version,
                                 const std::vector<uint8_t> &children)
  {
    auto hist = histKey(hash, version);
    auto by_ver = byVersionKey(version, hash);

    releaseReadTxn();

    std::lock_guard<std::mutex> lock(write_mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("putNodeAtVersion: txn_begin", rc);

    MDBX_val hk = toVal(hist.data(), hist.size());
    MDBX_val hv = toVal(children.data(), children.size());
    rc = mdbx_put(txn, tableHandle(TBL_SMT_NODES_HIST), &hk, &hv, MDBX_UPSERT);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("putNodeAtVersion: put hist", rc);
    }

    MDBX_val bk = toVal(by_ver.data(), by_ver.size());
    MDBX_val bv = toVal("", 0);
    rc = mdbx_put(txn, tableHandle(TBL_SMT_NODES_BY_VER), &bk, &bv, MDBX_UPSERT);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("putNodeAtVersion: put index", rc);
    }

    rc = mdbx_txn_commit(txn);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("putNodeAtVersion: commit", rc);
    }
  }

  bool StateDB::getNodeAtVersion(const Crypto::Hash &hash,
                                 uint64_t version,
                                 std::vector<uint8_t> &out) const
  {
    auto hist = histKey(hash, version);
    return rawGet(TBL_SMT_NODES_HIST, hist.data(), hist.size(), out);
  }

  void StateDB::putLeafDataAtVersion(const Crypto::Hash &leaf_hash,
                                     uint64_t version,
                                     const std::vector<uint8_t> &value)
  {
    auto hist = histKey(leaf_hash, version);
    auto by_ver = byVersionKey(version, leaf_hash);

    releaseReadTxn();

    std::lock_guard<std::mutex> lock(write_mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("putLeafDataAtVersion: txn_begin", rc);

    MDBX_val hk = toVal(hist.data(), hist.size());
    MDBX_val hv = toVal(value.data(), value.size());
    rc = mdbx_put(txn, tableHandle(TBL_SMT_LEAVES_HIST), &hk, &hv, MDBX_UPSERT);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("putLeafDataAtVersion: put hist", rc);
    }

    MDBX_val bk = toVal(by_ver.data(), by_ver.size());
    MDBX_val bv = toVal("", 0);
    rc = mdbx_put(txn, tableHandle(TBL_SMT_LEAVES_BY_VER), &bk, &bv, MDBX_UPSERT);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("putLeafDataAtVersion: put index", rc);
    }

    rc = mdbx_txn_commit(txn);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("putLeafDataAtVersion: commit", rc);
    }
  }

  bool StateDB::getLeafDataAtVersion(const Crypto::Hash &leaf_hash,
                                     uint64_t version,
                                     std::vector<uint8_t> &out) const
  {
    auto hist = histKey(leaf_hash, version);
    return rawGet(TBL_SMT_LEAVES_HIST, hist.data(), hist.size(), out);
  }

  // =============================================================
  //  Historical pruning
  // =============================================================

  void StateDB::pruneHistoryBefore(uint64_t keepFrom)
  {
    auto txn = beginWrite();

    pruneOneTableImpl(
        [this](uint32_t table, const EntryVisitor &v)
        { forEachEntry(table, v); },
        [&txn](uint32_t table, const void *k, size_t len)
        { txn.del(table, k, len); },
        TBL_SMT_NODES_BY_VER, TBL_SMT_NODES_HIST, keepFrom);

    pruneOneTableImpl(
        [this](uint32_t table, const EntryVisitor &v)
        { forEachEntry(table, v); },
        [&txn](uint32_t table, const void *k, size_t len)
        { txn.del(table, k, len); },
        TBL_SMT_LEAVES_BY_VER, TBL_SMT_LEAVES_HIST, keepFrom);

    txn.commit();
  }

  void StateDB::pruneHistoryBeforeTxn(Txn &txn, uint64_t keepFrom)
  {
    pruneOneTableImpl(
        [&txn](uint32_t table, const EntryVisitor &v)
        { txn.forEach(table, v); },
        [&txn](uint32_t table, const void *k, size_t len)
        { txn.del(table, k, len); },
        TBL_SMT_NODES_BY_VER, TBL_SMT_NODES_HIST, keepFrom);

    pruneOneTableImpl(
        [&txn](uint32_t table, const EntryVisitor &v)
        { txn.forEach(table, v); },
        [&txn](uint32_t table, const void *k, size_t len)
        { txn.del(table, k, len); },
        TBL_SMT_LEAVES_BY_VER, TBL_SMT_LEAVES_HIST, keepFrom);
  }

  void StateDB::wipeConsensusWal()
  {
    releaseReadTxn();

    std::lock_guard<std::mutex> lock(write_mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_READWRITE, &txn);
    if (rc != MDBX_SUCCESS)
      throwMdbx("wipeConsensusWal: txn_begin", rc);

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, tableHandle(TBL_CONSENSUS_WAL), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("wipeConsensusWal: cursor_open", rc);
    }

    MDBX_val mkey, mval;
    rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_FIRST);

    while (rc == MDBX_SUCCESS)
    {
      MDBX_val del_key;
      del_key.iov_base = mkey.iov_base;
      del_key.iov_len = mkey.iov_len;

      rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_NEXT);

      mdbx_del(txn, tableHandle(TBL_CONSENSUS_WAL), &del_key, nullptr);
    }

    mdbx_cursor_close(cursor);

    rc = mdbx_txn_commit(txn);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
      throwMdbx("wipeConsensusWal: commit", rc);
    }
  }

  // =============================================================
  //  Diagnostics
  // =============================================================

  size_t StateDB::entryCount(uint32_t tableId) const
  {
    MDBX_txn *outer = tls_read_txn_;
    MDBX_txn *txn = outer;

    if (txn == nullptr)
    {
      int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
      if (rc != MDBX_SUCCESS)
        throwMdbx("entryCount: txn_begin", rc);
      tls_read_txn_ = txn;
    }

    MDBX_stat stat;
    int rc = mdbx_dbi_stat(txn, tableHandle(tableId), &stat, sizeof(stat));

    if (outer == nullptr)
    {
      tls_read_txn_ = nullptr;
      mdbx_txn_abort(txn);
    }

    if (rc != MDBX_SUCCESS)
      throwMdbx("entryCount: dbi_stat", rc);
    return stat.ms_entries;
  }

  size_t StateDB::mapSize() const noexcept
  {
    return mapSizeBytes_;
  }

  MDBX_env *StateDB::env() const noexcept
  {
    return env_;
  }

  // =============================================================
  //  Lifecycle
  // =============================================================

  void StateDB::flush()
  {
    if (env_)
      mdbx_env_sync(env_);
  }

  void StateDB::close()
  {
    std::lock_guard<std::mutex> lock(write_mutex_);
    if (env_)
    {
      mdbx_env_close(env_);
      env_ = nullptr;
    }
  }

} // namespace State