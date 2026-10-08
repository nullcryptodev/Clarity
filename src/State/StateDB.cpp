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

    // Encode (hash, version) as 40 bytes: 32-byte hash followed by
    // an 8-byte big-endian version. Used for the historical value
    // tables, where lookups are always exact-match.
    std::array<uint8_t, 40> histKey(const Crypto::Hash &hash, uint64_t version)
    {
      std::array<uint8_t, 40> k{};
      std::memcpy(k.data(), hash.data.data(), 32);
      for (int i = 0; i < 8; ++i)
        k[32 + i] = uint8_t(version >> ((7 - i) * 8));
      return k;
    }

    // Encode (version, hash) as 40 bytes: 8-byte big-endian version
    // followed by a 32-byte hash. Used for the by-version index,
    // where the primary access pattern is "scan versions below N in
    // order", so version must sort first and in numeric order.
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

    //  Delete every row in `index_table` whose key's first 8 bytes
    //  (big-endian version) are < keepFrom, plus the matching row in
    //  `hist_table`.
    //
    //  The index is keyed by (version_be || hash), so a single cursor
    //  scan visits rows in version order and can stop at the first
    //  version >= keepFrom. That's O(rows-pruned), not O(rows-total).
    //
    //  The iteration and deletion mechanisms are injected so this can
    //  be used both with a live write txn (txn.forEach / txn.del) and
    //  with the DB's autocommit path (forEachEntry + an outer write
    //  txn's del). Both variants use the same deletion order and the
    //  same key transformation.
    //
    //  Collection is separated from deletion because the DB's
    //  forEachEntry holds the mutex during iteration and cannot be
    //  re-entered; the txn-bound forEach does not, but the two-phase
    //  approach keeps the implementation identical for both callers.
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
                  return false; // stop: keys are ordered by version first

                std::array<uint8_t, 40> k{};
                std::memcpy(k.data(), key.data(), 40);
                to_delete.push_back(k);
                return true;
              });

      for (const auto &k : to_delete)
      {
        // The index row.
        del(index_table, k.data(), k.size());

        // The historical row. Its key is (hash || version_be), which
        // is the reverse of the index key's (version_be || hash).
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

  //  Txn

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

    //  Position the cursor at the first key strictly greater than
    //  everything in the prefix range, then step back one. That lands
    //  on the last key whose prefix matches, if any.
    //
    //  Constructing the exclusive upper bound: the prefix's last byte
    //  incremented by one, with trailing bytes dropped. If the last
    //  byte is 0xFF, we'd have to carry; that requires walking the
    //  prefix from the end. In practice our prefixes never end in
    //  0xFF (they end in addresses, token IDs, or type bytes, none of
    //  which use 0xFF as a terminator), so a simple increment is fine
    //  and we handle the carry case defensively.

    std::vector<uint8_t> upper = prefix;
    while (!upper.empty() && upper.back() == 0xFF)
      upper.pop_back();
    if (!upper.empty())
      ++upper.back();
    // If upper became empty, the prefix was all 0xFF and there's no
    // exclusive bound; use MDBX_LAST directly.

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
        // We're at the first key >= upper. Step back one.
        rc = mdbx_cursor_get(cursor, &mkey, &mval, MDBX_PREV);
      }
      else if (rc == MDBX_NOTFOUND)
      {
        // No key >= upper. The last key in the table is our starting
        // point.
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
        // Walked off the front of the prefix range. Done.
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

  void StateDB::forEachEntryReverse(uint32_t tableId,
                                    const EntryVisitor &visitor) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
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
    mdbx_txn_abort(txn);
  }

  void StateDB::forEachEntryWithPrefixReverse(
      uint32_t tableId,
      const std::vector<uint8_t> &prefix,
      const EntryVisitor &visitor) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
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
    mdbx_txn_abort(txn);
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

  //  Construction

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

  //  Raw access (autocommit)

  void StateDB::rawPut(uint32_t tableId,
                       const void *key, size_t keyLen,
                       const void *value, size_t valueLen)
  {
    std::lock_guard<std::mutex> lock(mutex_);

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

  bool StateDB::rawGet(uint32_t tableId,
                       const void *key, size_t keyLen,
                       std::vector<uint8_t> &out) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return false;

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv;
    rc = mdbx_get(txn, tableHandle(tableId), &mk, &mv);

    if (rc == MDBX_SUCCESS)
    {
      out.assign(static_cast<const uint8_t *>(mv.iov_base),
                 static_cast<const uint8_t *>(mv.iov_base) + mv.iov_len);
      mdbx_txn_abort(txn);
      return true;
    }

    mdbx_txn_abort(txn);
    return false;
  }

  void StateDB::rawDel(uint32_t tableId, const void *key, size_t keyLen)
  {
    std::lock_guard<std::mutex> lock(mutex_);

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
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return false;

    MDBX_val mk = toVal(key, keyLen);
    MDBX_val mv;
    rc = mdbx_get(txn, tableHandle(tableId), &mk, &mv);
    mdbx_txn_abort(txn);
    return rc == MDBX_SUCCESS;
  }

  //  Iteration

  void StateDB::forEachEntry(uint32_t tableId, const EntryVisitor &visitor) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
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
    mdbx_txn_abort(txn);
  }

  void StateDB::forEachEntryWithPrefix(uint32_t tableId,
                                       const std::vector<uint8_t> &prefix,
                                       const EntryVisitor &visitor) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return;

    MDBX_cursor *cursor = nullptr;
    rc = mdbx_cursor_open(txn, tableHandle(tableId), &cursor);
    if (rc != MDBX_SUCCESS)
    {
      mdbx_txn_abort(txn);
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
    mdbx_txn_abort(txn);
  }

  //  Meta helpers

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

  //  SMT convenience API

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

  //  Historical SMT access

  void StateDB::putNodeAtVersion(const Crypto::Hash &hash,
                                 uint64_t version,
                                 const std::vector<uint8_t> &children)
  {
    auto hist = histKey(hash, version);
    auto by_ver = byVersionKey(version, hash);

    std::lock_guard<std::mutex> lock(mutex_);

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

    std::lock_guard<std::mutex> lock(mutex_);

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

  //  Historical pruning

  void StateDB::pruneHistoryBefore(uint64_t keepFrom)
  {
    //  Non-txn path. Opens its own write txn so the scan and the
    //  deletes see a consistent view, and so the outer entry point
    //  matches the txn-bound variant's semantics. The scan uses
    //  forEachEntry (which opens its own read txn under the mutex);
    //  the deletes go through the write txn opened here.
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
    //  Txn-bound path. Uses the caller's write txn for both the scan
    //  and the deletes, so rows that are still uncommitted in that
    //  txn are visible to the scan and are deleted from the same view.
    //  This is the variant the SparseMerkleTree calls when it holds a
    //  txn: a fixture that binds a txn to the SMT writes its
    //  historical rows into that txn, and those rows must be pruned
    //  from the same txn before it commits.
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

  //  Diagnostics

  size_t StateDB::entryCount(uint32_t tableId) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(env_, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS)
      return 0;

    MDBX_stat stat;
    rc = mdbx_dbi_stat(txn, tableHandle(tableId), &stat, sizeof(stat));
    mdbx_txn_abort(txn);

    if (rc != MDBX_SUCCESS)
      return 0;
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

  //  Lifecycle

  void StateDB::flush()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (env_)
      mdbx_env_sync(env_);
  }

  void StateDB::close()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (env_)
    {
      mdbx_env_close(env_);
      env_ = nullptr;
    }
  }

} // namespace State