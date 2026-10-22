// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Signing.h"

#include "Crypto/Ed25519.h"
#include "Crypto/Helpers.h"

#include <cstring>

namespace Bridge::Signing
{
  namespace
  {
    void AppendU16(std::vector<uint8_t> &out, uint16_t v)
    {
      out.push_back(uint8_t(v));
      out.push_back(uint8_t(v >> 8));
    }

    void AppendU32(std::vector<uint8_t> &out, uint32_t v)
    {
      out.push_back(uint8_t(v));
      out.push_back(uint8_t(v >> 8));
      out.push_back(uint8_t(v >> 16));
      out.push_back(uint8_t(v >> 24));
    }

    void AppendU64(std::vector<uint8_t> &out, uint64_t v)
    {
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(v >> (i * 8)));
    }
  } // anonymous namespace

  //  ---- Encoders ----

  std::vector<uint8_t> EncodeBridgeMintMessage(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const Crypto::Address &destination,
      uint64_t amount)
  {
    std::vector<uint8_t> out;
    out.reserve(8 + 32 + 4 + 32 + 8);

    AppendU64(out, source_chain_id); // LE
    out.insert(out.end(), source_tx_hash.data.begin(), source_tx_hash.data.end());
    AppendU32(out, source_output_index); // LE
    out.insert(out.end(), destination.data.begin(), destination.data.end());
    AppendU64(out, amount); // LE

    return out;
  }

  std::vector<uint8_t> EncodeBridgeAckMessage(uint64_t withdrawal_id)
  {
    std::vector<uint8_t> out;
    out.reserve(8);
    AppendU64(out, withdrawal_id);
    return out;
  }

  std::vector<uint8_t> EncodeBridgePauseMessage(uint64_t bound_height)
  {
    std::vector<uint8_t> out;
    out.reserve(8);
    AppendU64(out, bound_height);
    return out;
  }

  //  ---- Hash + sign ----

  Crypto::Hash SigningHash(const char *domain,
                           const uint8_t *message,
                           size_t message_len)
  {
    //  Defensive: a non-4-byte domain is a caller bug. Return a
    //  null hash so the caller sees the failure rather than
    //  silently getting a hash over an unexpected domain.
    if (domain == nullptr || std::strlen(domain) != 4)
      return Crypto::Hash{};

    return Crypto::hashDomain(domain, message, message_len);
  }

  std::optional<Attestation> Sign(
      const Crypto::SecretKey &watcher_consensus_key,
      uint16_t signer_index,
      const Crypto::Hash &signing_hash)
  {
    //  Sign the hash with the watcher's consensus key. The
    //  executor verifies against validatorKeyAtHeight, which for
    //  a seed or non-rotated validator returns the same key. A
    //  rotation invalidates old signatures only for heights at or
    //  after the rotation — the caller is responsible for using
    //  the right key for the right height.
    Attestation a;
    a.signer_index = signer_index;
    a.signature = Crypto::sign(signing_hash, watcher_consensus_key);
    return a;
  }

  //  ---- Assemble ----

  std::vector<uint8_t> AssembleBlock(
      const std::vector<Attestation> &attestations)
  {
    std::vector<uint8_t> block;
    block.reserve(2 + attestations.size() * 66);

    //  Count prefix. The executor rejects counts above
    //  BRIDGE_MAX_WATCHERS (100) with a parse failure, so a
    //  caller that feeds more than 100 attestations gets a
    //  rejected transaction rather than a crash.
    AppendU16(block, static_cast<uint16_t>(attestations.size()));

    for (const auto &a : attestations)
    {
      AppendU16(block, a.signer_index);
      block.insert(block.end(),
                   a.signature.data.begin(),
                   a.signature.data.end());
    }

    return block;
  }

  //  ---- One-call builders ----

  namespace
  {
    //  Shared helper: hash the message under the given domain,
    //  sign with every watcher, assemble.
    std::optional<std::vector<uint8_t>> SignAndAssemble(
        const char *domain,
        const std::vector<uint8_t> &message,
        const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
        std::string *error_out)
    {
      if (watchers.empty())
      {
        if (error_out)
          *error_out = "no watchers provided";
        return std::nullopt;
      }

      const Crypto::Hash hash =
          SigningHash(domain, message.data(), message.size());
      if (hash.isNull())
      {
        if (error_out)
          *error_out = "signing hash is null (bad domain?)";
        return std::nullopt;
      }

      std::vector<Attestation> attestations;
      attestations.reserve(watchers.size());

      for (const auto &[idx, key] : watchers)
      {
        auto a = Sign(key, idx, hash);
        if (!a.has_value())
        {
          if (error_out)
            *error_out = "signature failed for signer index " +
                         std::to_string(idx);
          return std::nullopt;
        }
        attestations.push_back(*a);
      }

      return AssembleBlock(attestations);
    }
  } // anonymous namespace

  std::optional<std::vector<uint8_t>> BuildBridgeMintBlock(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const Crypto::Address &destination,
      uint64_t amount,
      const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
      std::string *error_out)
  {
    const auto message = EncodeBridgeMintMessage(
        source_chain_id, source_tx_hash,
        source_output_index, destination, amount);
    return SignAndAssemble("bmin", message, watchers, error_out);
  }

  std::optional<std::vector<uint8_t>> BuildBridgeAckBlock(
      uint64_t withdrawal_id,
      const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
      std::string *error_out)
  {
    const auto message = EncodeBridgeAckMessage(withdrawal_id);
    return SignAndAssemble("back", message, watchers, error_out);
  }

  std::optional<std::vector<uint8_t>> BuildBridgePauseBlock(
      const char *domain,
      uint64_t bound_height,
      const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
      std::string *error_out)
  {
    //  Accept only the two governance domains. Everything else
    //  is a caller bug.
    if (std::strcmp(domain, "bpaul") != 0 &&
        std::strcmp(domain, "bunp") != 0)
    {
      if (error_out)
        *error_out = "BuildBridgePauseBlock: domain must be 'bpaul' or 'bunp'";
      return std::nullopt;
    }

    const auto message = EncodeBridgePauseMessage(bound_height);
    return SignAndAssemble(domain, message, watchers, error_out);
  }

  std::optional<Crypto::Signature> SignSingleBridgeMint(
      const Crypto::SecretKey &watcher_consensus_key,
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const Crypto::Address &destination,
      uint64_t amount)
  {
    const auto message = EncodeBridgeMintMessage(
        source_chain_id, source_tx_hash, source_output_index,
        destination, amount);
    const Crypto::Hash hash =
        SigningHash("bmin", message.data(), message.size());
    if (hash.isNull())
      return std::nullopt;
    return Crypto::sign(hash, watcher_consensus_key);
  }

  std::optional<Crypto::Signature> SignSingleBridgeAck(
      const Crypto::SecretKey &watcher_consensus_key,
      uint64_t withdrawal_id)
  {
    const auto message = EncodeBridgeAckMessage(withdrawal_id);
    const Crypto::Hash hash =
        SigningHash("back", message.data(), message.size());
    if (hash.isNull())
      return std::nullopt;
    return Crypto::sign(hash, watcher_consensus_key);
  }
} // namespace Bridge::Signing