// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateDB.h"

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