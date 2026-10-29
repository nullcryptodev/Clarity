#pragma once

#include "Crypto/Helpers.h"
#include "Crypto/Types.h"

namespace State
{

  //  Key derivation
  //
  //  Every state object has a unique SMT position determined by
  //  Blake2b(domain4 || payload). The domain tag separates namespaces
  //  so no two object kinds can ever collide, and the payload
  //  determines the object's identity within its namespace.
  //
  //  Domain tags are 4 bytes and are chosen to be visually distinct.
  //  Once deployed, a tag must never change: that would move every key
  //  in the namespace and lose the state.
  //
  //  These derivations are independent of the tree's shape. The
  //  compressed tree reads keys the same way the uncompressed tree
  //  did — bit by bit from MSB to LSB — so the key space is
  //  unchanged. Only the node structure above the keys is different.

  namespace Keys
  {
    inline Crypto::Hash account(const Crypto::Address &address) noexcept
    {
      return Crypto::hashDomain("acct", address.data.data(), 32);
    }

    inline Crypto::Hash tokenBalance(const Crypto::Address &address, Id token_id) noexcept
    {
      uint8_t buf[32 + 4];
      std::memcpy(buf, address.data.data(), 32);
      buf[32] = uint8_t(token_id);
      buf[33] = uint8_t(token_id >> 8);
      buf[34] = uint8_t(token_id >> 16);
      buf[35] = uint8_t(token_id >> 24);
      return Crypto::hashDomain("bal ", buf, 36);
    }

    inline Crypto::Hash token(Id token_id) noexcept
    {
      uint8_t buf[4];
      buf[0] = uint8_t(token_id);
      buf[1] = uint8_t(token_id >> 8);
      buf[2] = uint8_t(token_id >> 16);
      buf[3] = uint8_t(token_id >> 24);
      return Crypto::hashDomain("tok ", buf, 4);
    }

    inline Crypto::Hash tokenSupply(Id token_id) noexcept
    {
      uint8_t buf[4];
      buf[0] = uint8_t(token_id);
      buf[1] = uint8_t(token_id >> 8);
      buf[2] = uint8_t(token_id >> 16);
      buf[3] = uint8_t(token_id >> 24);
      return Crypto::hashDomain("tsup", buf, 4);
    }

    inline Crypto::Hash validator(uint64_t validator_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(validator_id >> (i * 8));
      return Crypto::hashDomain("val ", buf, 8);
    }

    inline Crypto::Hash validatorByAddress(const Crypto::Address &address) noexcept
    {
      return Crypto::hashDomain("vadr", address.data.data(), 32);
    }

    inline Crypto::Hash order(uint64_t order_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(order_id >> (i * 8));
      return Crypto::hashDomain("ord ", buf, 8);
    }

    inline Crypto::Hash orderExpiry(uint64_t height) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(height >> (i * 8));
      return Crypto::hashDomain("oexh", buf, 8);
    }

    inline Crypto::Hash global(const std::string &name) noexcept
    {
      size_t len = name.size();
      if (len > 64)
        len = 64;
      return Crypto::hashDomain("glob",
                                reinterpret_cast<const uint8_t *>(name.data()),
                                len);
    }

    inline Crypto::Hash ammPool(uint64_t pool_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(pool_id >> (i * 8));
      return Crypto::hashDomain("pool", buf, 8);
    }

    inline Crypto::Hash ammPosition(uint64_t position_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(position_id >> (i * 8));
      return Crypto::hashDomain("pos ", buf, 8);
    }

    inline Crypto::Hash ammPositionIndex(const Crypto::Address &owner,
                                         uint64_t pool_id) noexcept
    {
      uint8_t buf[32 + 8];
      std::memcpy(buf, owner.data.data(), 32);
      for (int i = 0; i < 8; ++i)
        buf[32 + i] = uint8_t(pool_id >> (i * 8));
      return Crypto::hashDomain("pidx", buf, 40);
    }

    inline Crypto::Hash receipt(const Crypto::Hash &tx_hash) noexcept
    {
      return Crypto::hashDomain("rcpt", tx_hash.data.data(), 32);
    }

    inline Crypto::Hash orderSequence(uint64_t order_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(order_id >> (i * 8));
      return Crypto::hashDomain("oseq", buf, 8);
    }

    inline Crypto::Hash validatorKeyHistory(uint64_t validator_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(validator_id >> (i * 8));
      return Crypto::hashDomain("vkey", buf, 8);
    }

    inline Crypto::Hash nft(uint64_t nft_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(nft_id >> (i * 8));
      return Crypto::hashDomain("nft ", buf, 8);
    }

    inline Crypto::Hash nftCollection(uint64_t collection_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(collection_id >> (i * 8));
      return Crypto::hashDomain("ncol", buf, 8);
    }

    inline Crypto::Address nftAddress(uint64_t nft_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(nft_id >> (i * 8));

      uint8_t domain_buf[4 + 8];
      std::memcpy(domain_buf, "nfa ", 4);
      std::memcpy(domain_buf + 4, buf, 8);

      Crypto::Address addr;
      Crypto::blake2b(domain_buf, sizeof(domain_buf),
                      addr.data.data(), addr.data.size());
      return addr;
    }

    inline Crypto::Address nftCollectionAddress(uint64_t collection_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(collection_id >> (i * 8));

      uint8_t domain_buf[4 + 8];
      std::memcpy(domain_buf, "nca ", 4);
      std::memcpy(domain_buf + 4, buf, 8);

      Crypto::Address addr;
      Crypto::blake2b(domain_buf, sizeof(domain_buf),
                      addr.data.data(), addr.data.size());
      return addr;
    }

    //  -------------------------------------------------------------------
    //  Bridge
    //  -------------------------------------------------------------------
    //
    //  The bridge's keys. bridgeConsumed, bridgeWithdrawal, and
    //  bridgeChainRegistration are the per-deposit guard, the
    //  withdrawal record, and the per-chain registry. bridgeWatcher
    //  and bridgeWatcherByAddress are the registered-watcher
    //  records (see BridgeWatcherTypes.h).
    //
    //  There is no bridgeSignerSet key. The operational signer set
    //  is the active watcher set, resolved from state on each
    //  verification; it isn't stored under a single key.

    inline Crypto::Hash bridgeConsumed(uint64_t source_chain_id,
                                       const Crypto::Hash &source_tx_hash,
                                       uint32_t source_output_index) noexcept
    {
      uint8_t buf[8 + 32 + 4];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(source_chain_id >> (i * 8));
      std::memcpy(buf + 8, source_tx_hash.data.data(), 32);
      for (int i = 0; i < 4; ++i)
        buf[40 + i] = uint8_t(source_output_index >> (i * 8));
      return Crypto::hashDomain("brgc", buf, sizeof(buf));
    }

    inline Crypto::Hash bridgeWithdrawal(uint64_t withdrawal_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(withdrawal_id >> (i * 8));
      return Crypto::hashDomain("brgw", buf, 8);
    }

    inline Crypto::Hash bridgeChainRegistration(uint64_t source_chain_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(source_chain_id >> (i * 8));
      return Crypto::hashDomain("brgr", buf, 8);
    }

    inline Crypto::Hash bridgeWatcher(uint64_t watcher_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(watcher_id >> (i * 8));
      return Crypto::hashDomain("brwt", buf, 8);
    }

    inline Crypto::Hash bridgeWatcherByAddress(const Crypto::Address &address) noexcept
    {
      return Crypto::hashDomain("brga", address.data.data(), 32);
    }

    //  -------------------------------------------------------------------
    //  AMM farming
    //  -------------------------------------------------------------------
    //
    //  A farm is a companion record to a pool (Keys::ammFarm), the
    //  per-position accrual tracker is a companion record to an
    //  LP position (Keys::ammPositionAccrual), and the farm's
    //  escrow lives at a virtual address derived from the pool id
    //  (Keys::ammFarmAddress), the same pattern nftAddress and
    //  nftCollectionAddress use for NFT custody.

    inline Crypto::Hash ammFarm(uint64_t pool_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(pool_id >> (i * 8));
      return Crypto::hashDomain("farm", buf, 8);
    }

    inline Crypto::Hash ammPositionAccrual(uint64_t position_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(position_id >> (i * 8));
      return Crypto::hashDomain("pacc", buf, 8);
    }

    inline Crypto::Address ammFarmAddress(uint64_t pool_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(pool_id >> (i * 8));

      uint8_t domain_buf[4 + 8];
      std::memcpy(domain_buf, "fma ", 4);
      std::memcpy(domain_buf + 4, buf, 8);

      Crypto::Address addr;
      Crypto::blake2b(domain_buf, sizeof(domain_buf),
                      addr.data.data(), addr.data.size());
      return addr;
    }

    //  ---- Deposit destinations ----
    //
    //  A registration assigns a per-chain, monotonic index to a
    //  (authority, destination) pair. See BridgeDepositRecord in
    //  Core/BridgeTypes.h. The index is what the watcher uses to
    //  derive the CCX subaddress the user deposits to; the record
    //  is what resolves that subaddress back to the destination.
    //
    //  bridgeDepositDestination (indexed by chain+index) is what
    //  the watcher reads. bridgeDepositByAuthority (indexed by
    //  chain+authority+index) is what the wallet's "list my
    //  registrations" RPC reads. Both are needed: the first is
    //  used by the scanner for each deposit it sees, the second
    //  is used once at wallet startup to enumerate the caller's
    //  existing registrations.

    inline Crypto::Hash bridgeDepositDestination(uint64_t source_chain_id,
                                                 uint64_t index) noexcept
    {
      uint8_t buf[8 + 8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(source_chain_id >> (i * 8));
      for (int i = 0; i < 8; ++i)
        buf[8 + i] = uint8_t(index >> (i * 8));
      return Crypto::hashDomain("brgd", buf, sizeof(buf));
    }

    inline Crypto::Hash bridgeDepositByAuthority(
        uint64_t source_chain_id,
        const Crypto::Address &authority,
        uint64_t index) noexcept
    {
      uint8_t buf[8 + 32 + 8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(source_chain_id >> (i * 8));
      std::memcpy(buf + 8, authority.data.data(), 32);
      for (int i = 0; i < 8; ++i)
        buf[40 + i] = uint8_t(index >> (i * 8));
      return Crypto::hashDomain("brgA", buf, sizeof(buf));
    }

  } // namespace Keys
}