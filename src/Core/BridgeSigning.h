// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "Crypto/Helpers.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include "State/StateAccess.h"

#include "BridgeTypes.h"
#include "TransactionTypes.h"
#include "ValidatorTypes.h"

namespace Core
{
  //  Shared bridge-signature primitives, used by both the executor
  //  (TransactionExecutor.cpp) and the mempool (via the
  //  Core::GovernanceVerifier function Node supplies). Keeping the
  //  parser and the domain-separated hashing in one header means
  //  the two callers cannot drift.

  struct BridgeSignatureEntry
  {
    uint16_t signer_index{0};
    Crypto::Signature signature{};
  };

  inline bool parseBridgeSignatureBlock(
      const uint8_t *data, size_t len,
      std::vector<BridgeSignatureEntry> &out)
  {
    out.clear();
    if (len < 2)
      return false;

    const uint16_t count =
        uint16_t(data[0]) | (uint16_t(data[1]) << 8);

    if (count > BRIDGE_MAX_WATCHERS)
      return false;

    const size_t expected = 2 + static_cast<size_t>(count) * 66;
    if (len != expected)
      return false;

    out.reserve(count);
    for (uint16_t i = 0; i < count; ++i)
    {
      const uint8_t *p = data + 2 + i * 66;
      BridgeSignatureEntry e;
      e.signer_index = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
      std::memcpy(e.signature.data.data(), p + 2, 64);
      out.push_back(e);
    }
    return true;
  }

  inline Crypto::Hash bridgeSigningHash(
      std::string_view domain,
      const uint8_t *message, size_t message_len)
  {
    return Crypto::hashDomain(domain.data(), message, message_len);
  }

  enum class GovernanceVerifyResult
  {
    Ok,
    BadDomainLength,
    EmptyActiveSet,
    BadSignatureBlock,
    BelowQuorum,
    DuplicateSigner,
    SignerIndexOutOfRange,
    NoConsensusKeyAtHeight,
    BadSignature,
  };

  inline GovernanceVerifyResult verifyGovernanceSignaturesAt(
      State::StateAccess &state,
      const std::vector<Id> &active_sorted,
      std::string_view domain,
      const uint8_t *message, size_t message_len,
      const uint8_t *signatures, size_t signatures_len,
      uint64_t height)
  {
    if (domain.size() != 4)
      return GovernanceVerifyResult::BadDomainLength;

    if (active_sorted.empty())
      return GovernanceVerifyResult::EmptyActiveSet;

    const size_t threshold = Core::bftQuorum(active_sorted.size());

    std::vector<BridgeSignatureEntry> sigs;
    if (!parseBridgeSignatureBlock(signatures, signatures_len, sigs))
      return GovernanceVerifyResult::BadSignatureBlock;

    if (sigs.size() < threshold)
      return GovernanceVerifyResult::BelowQuorum;

    std::vector<bool> seen(active_sorted.size(), false);
    for (const auto &e : sigs)
    {
      if (e.signer_index >= active_sorted.size())
        return GovernanceVerifyResult::SignerIndexOutOfRange;
      if (seen[e.signer_index])
        return GovernanceVerifyResult::DuplicateSigner;
      seen[e.signer_index] = true;
    }

    const Crypto::Hash hash =
        bridgeSigningHash(domain, message, message_len);

    for (const auto &e : sigs)
    {
      const Id vid = active_sorted[e.signer_index];
      auto pk = state.validatorKeyAtHeight(vid, height);
      if (!pk.has_value())
        return GovernanceVerifyResult::NoConsensusKeyAtHeight;

      if (!Crypto::verify(hash, *pk, e.signature))
        return GovernanceVerifyResult::BadSignature;
    }

    return GovernanceVerifyResult::Ok;
  }

  inline std::vector<Id> loadSortedActiveValidators(
      State::StateAccess &state)
  {
    std::vector<Id> out;
    std::vector<uint8_t> set_bytes;
    if (!state.getGlobal("active_set", set_bytes))
      return out;

    size_t count = set_bytes.size() / 8;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t id = 0;
      for (int j = 0; j < 8; ++j)
        id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
      out.push_back(static_cast<Id>(id));
    }

    std::sort(out.begin(), out.end());
    return out;
  }
} // namespace Core