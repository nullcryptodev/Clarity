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
  } // namespace Keys
}