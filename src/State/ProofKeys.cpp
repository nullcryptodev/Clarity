// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ProofKeys.h"

#include "SparseMerkleTree.h"

#include <cstring>
#include <string>

namespace State
{
  std::optional<Crypto::Hash> resolveProofKey(
      ProofKeyType type, const std::vector<uint8_t> &key_bytes)
  {
    switch (type)
    {
    case ProofKeyType::Account:
    {
      if (key_bytes.size() != 32)
        return std::nullopt;
      Crypto::Address addr;
      std::memcpy(addr.data.data(), key_bytes.data(), 32);
      return Keys::account(addr);
    }

    case ProofKeyType::TokenBalance:
    {
      if (key_bytes.size() != 36)
        return std::nullopt;
      Crypto::Address addr;
      std::memcpy(addr.data.data(), key_bytes.data(), 32);
      Id token_id = 0;
      for (int i = 0; i < 4; ++i)
        token_id |= uint64_t(key_bytes[32 + i]) << (i * 8);
      return Keys::tokenBalance(addr, token_id);
    }

    case ProofKeyType::Validator:
    {
      if (key_bytes.size() != 8)
        return std::nullopt;
      uint64_t vid = 0;
      for (int i = 0; i < 8; ++i)
        vid |= uint64_t(key_bytes[i]) << (i * 8);
      return Keys::validator(vid);
    }

    case ProofKeyType::Global:
    {
      if (key_bytes.empty() || key_bytes.size() > 64)
        return std::nullopt;
      std::string name(reinterpret_cast<const char *>(key_bytes.data()),
                       key_bytes.size());
      return Keys::global(name);
    }

    case ProofKeyType::AmmPool:
    {
      if (key_bytes.size() != 8)
        return std::nullopt;
      uint64_t pool_id = 0;
      for (int i = 0; i < 8; ++i)
        pool_id |= uint64_t(key_bytes[i]) << (i * 8);
      return Keys::ammPool(pool_id);
    }
    }

    return std::nullopt;
  }

} // namespace State