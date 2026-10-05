// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Block.h"
#include "TransactionTypes.h"
#include "RewardTypes.h"

#include "Consensus/Types.h"

#include "Crypto/Blake2b.h"

#include "Common/Wire.h"

#include <cstring>
#include <sstream>

namespace Core
{
  namespace
  {
    // Domain separation.
    constexpr const char *BLOCK_HEADER_DOMAIN = "CLRTY_BLOCKHDR_V1";
    constexpr const char *TX_LEAF_DOMAIN = "CLRTY_TXLEAF_V1";
    constexpr const char *VALIDATOR_LEAF_DOMAIN = "CLRTY_VALSETLEAF_V1";
    constexpr const char *MERKLE_INTERNAL_DOMAIN = "CLRTY_MERKLE_V1";
    constexpr const char *TIMEOUT_CERT_DOMAIN = "CLRTY_TIMEOUTCERT_V1";

    // Blake2b-256 of a domain-tagged byte string.
    Crypto::Hash hashWithDomain(const char *domain,
                                const std::vector<uint8_t> &body)
    {
      size_t dlen = std::strlen(domain);
      std::vector<uint8_t> buf;
      buf.reserve(dlen + body.size());
      buf.insert(buf.end(),
                 reinterpret_cast<const uint8_t *>(domain),
                 reinterpret_cast<const uint8_t *>(domain) + dlen);
      buf.insert(buf.end(), body.begin(), body.end());

      Crypto::Hash h;
      Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
      return h;
    }
  } // anonymous namespace

  // ===========================================================================
  //  Certificate hash
  // ===========================================================================

  Crypto::Hash computeTimeoutCertificateHash(
      const Consensus::TimeoutCertificate &cert)
  {
    if (cert.votes.empty())
      return Crypto::Hash{};

    auto bytes = cert.serialize();
    return hashWithDomain(TIMEOUT_CERT_DOMAIN, bytes);
  }

  //  BlockHeader

  bool BlockHeader::isWellFormed() const noexcept
  {
    if (version != GlobalConfig::CURRENT_BLOCK_VERSION)
      return false;
    if (chain_id == 0)
      return false;

    // Genesis has no proposer; that's expected and valid.
    if (height > 0 && proposer.isNull())
      return false;

    if (active_validator_count == 0)
      return false;
    if (tx_count > 5'000)
      return false; // max_block_txs

    // For non-genesis blocks, the parent must be set.
    if (height > 0 && parent_hash.isNull())
      return false;

    // Non-genesis blocks must have a non-null state root.
    if (height > 0 && state_root.isNull())
      return false;

    // The emergency flag and the certificate must agree:
    //   - emergency_rotation > 0  → non-empty certificate AND a
    //                               matching timeout_certificate_hash
    //   - emergency_rotation == 0 → empty certificate AND null hash
    if (emergency_rotation > 0)
    {
      if (timeout_certificate.votes.empty())
        return false;
      if (timeout_certificate_hash.isNull())
        return false;
    }
    else
    {
      if (!timeout_certificate.votes.empty())
        return false;
      if (!timeout_certificate_hash.isNull())
        return false;
    }

    return true;
  }

  Crypto::Hash BlockHeader::hash() const
  {
    auto body = serializeForHash();
    return hashWithDomain(BLOCK_HEADER_DOMAIN, body);
  }

  std::vector<uint8_t> BlockHeader::serialize() const
  {
    std::vector<uint8_t> out;
    out.reserve(258 + 4 + timeout_certificate.serialize().size());

    Common::Writer w(out);
    w.writeU16(version);
    w.writeU64(chain_id);
    w.writeU64(height);
    w.writeBytes(parent_hash.data.data(), parent_hash.data.size());
    w.writeU64(timestamp_ms);
    w.writeBytes(proposer.data.data(), proposer.data.size());
    w.writeU64(epoch);
    w.writeU64(rotation_index);
    w.writeU64(commit_round);
    w.writeU64(emergency_rotation);
    w.writeBytes(state_root.data.data(), state_root.data.size());
    w.writeBytes(tx_root.data.data(), tx_root.data.size());
    w.writeBytes(receipts_root.data.data(), receipts_root.data.size());
    w.writeBytes(validator_set_root.data.data(), validator_set_root.data.size());
    w.writeU64(total_fees);
    w.writeU32(tx_count);
    w.writeU32(active_validator_count);

    //  Certificate hash. Fixed-width. Always present, zero when
    //  there's no certificate. This is what makes the certificate
    //  part of the block's identity without inflating the hash input
    //  with the variable-length certificate bytes.
    w.writeBytes(timeout_certificate_hash.data.data(),
                 timeout_certificate_hash.data.size());

    //  Length-prefixed certificate bytes. Always present in the wire
    //  format, even when empty (length 0), so the header layout is
    //  fixed for all blocks.
    auto cert_bytes = timeout_certificate.serialize();
    w.writeU32(static_cast<uint32_t>(cert_bytes.size()));
    w.writeBytes(cert_bytes.data(), cert_bytes.size());

    return out;
  }

  std::vector<uint8_t> BlockHeader::serializeForHash() const
  {
    //  Same field order as serialize(), but without commit_round and
    //  without the certificate BYTES. The certificate's HASH is
    //  included — the block's identity commits to the certificate's
    //  contents, but not to the exact byte encoding, which is what
    //  lets the wire format change (e.g. adding a field to the cert
    //  encoder) without changing block hashes.
    std::vector<uint8_t> out;
    out.reserve(250 + 32);

    Common::Writer w(out);
    w.writeU16(version);
    w.writeU64(chain_id);
    w.writeU64(height);
    w.writeBytes(parent_hash.data.data(), parent_hash.data.size());
    w.writeU64(timestamp_ms);
    w.writeBytes(proposer.data.data(), proposer.data.size());
    w.writeU64(epoch);
    w.writeU64(rotation_index);
    // commit_round omitted from the hash.
    w.writeU64(emergency_rotation);
    w.writeBytes(state_root.data.data(), state_root.data.size());
    w.writeBytes(tx_root.data.data(), tx_root.data.size());
    w.writeBytes(receipts_root.data.data(), receipts_root.data.size());
    w.writeBytes(validator_set_root.data.data(), validator_set_root.data.size());
    w.writeU64(total_fees);
    w.writeU32(tx_count);
    w.writeU32(active_validator_count);
    // Certificate hash. Zero when there's no certificate.
    w.writeBytes(timeout_certificate_hash.data.data(),
                 timeout_certificate_hash.data.size());

    return out;
  }

  bool BlockHeader::deserialize(const uint8_t *data, size_t len,
                                BlockHeader &out)
  {
    Common::Reader r(data, len);

    out.version = r.readU16();
    out.chain_id = r.readU64();
    out.height = r.readU64();
    r.readBytes(out.parent_hash.data.data(), out.parent_hash.data.size());
    out.timestamp_ms = r.readU64();
    r.readBytes(out.proposer.data.data(), out.proposer.data.size());
    out.epoch = r.readU64();
    out.rotation_index = r.readU64();
    out.commit_round = r.readU64();
    out.emergency_rotation = r.readU64();
    r.readBytes(out.state_root.data.data(), out.state_root.data.size());
    r.readBytes(out.tx_root.data.data(), out.tx_root.data.size());
    r.readBytes(out.receipts_root.data.data(), out.receipts_root.data.size());
    r.readBytes(out.validator_set_root.data.data(),
                out.validator_set_root.data.size());
    out.total_fees = r.readU64();
    out.tx_count = r.readU32();
    out.active_validator_count = r.readU32();

    if (!r.ok())
      return false;

    //  Certificate hash. Fixed-width, always present.
    r.readBytes(out.timeout_certificate_hash.data.data(),
                out.timeout_certificate_hash.data.size());
    if (!r.ok())
      return false;

    //  Certificate bytes. Length-prefixed; may be zero.
    constexpr uint32_t MAX_CERT_BYTES = 32 * 1024;
    const uint32_t cert_len = r.readU32();
    if (!r.ok() || cert_len > MAX_CERT_BYTES)
      return false;

    if (r.remaining() < cert_len)
      return false;

    std::vector<uint8_t> cert_bytes = r.readVector(cert_len);
    if (!r.ok())
      return false;

    if (!Consensus::TimeoutCertificate::deserialize(
            cert_bytes.data(), cert_bytes.size(), out.timeout_certificate))
    {
      return false;
    }

    // No trailing bytes tolerated after the certificate.
    if (r.remaining() != 0)
      return false;

    return true;
  }

  void BlockHeader::serialize(Serialization::ISerializer &s)
  {
    auto bytes = serialize();
    s.binary(bytes.data(), bytes.size(), "block_header");
  }

  void BlockHeader::serialize(Serialization::ISerializer &s) const
  {
    auto bytes = serialize();
    s.binary(const_cast<uint8_t *>(bytes.data()), bytes.size(), "block_header");
  }

  //  Block

  bool Block::isWellFormed() const noexcept
  {
    if (!header.isWellFormed())
      return false;
    if (transactions.size() != header.tx_count)
      return false;

    for (const auto &tx : transactions)
    {
      if (!tx.isWellFormed())
        return false;
    }

    // Genesis has no quorum signatures.
    if (header.height > 0)
    {
      if (quorum_signatures.size() <
          bftQuorum(header.active_validator_count))
      {
        return false;
      }
    }

    return true;
  }

  std::vector<uint8_t> Block::serialize() const
  {
    std::vector<uint8_t> out;
    out.reserve(serializedSize());

    Common::Writer w(out);

    auto hdr = header.serialize();
    w.writeU32(static_cast<uint32_t>(hdr.size()));
    w.writeBytes(hdr.data(), hdr.size());

    w.writeU32(static_cast<uint32_t>(transactions.size()));
    for (const auto &tx : transactions)
    {
      auto txbytes = tx.serialize();
      w.writeU32(static_cast<uint32_t>(txbytes.size()));
      w.writeBytes(txbytes.data(), txbytes.size());
    }

    w.writeU32(static_cast<uint32_t>(quorum_signatures.size()));
    for (const auto &sig : quorum_signatures)
    {
      w.writeU16(sig.signer_index);
      w.writeBytes(sig.signature.data.data(), sig.signature.data.size());
    }

    w.writeU32(static_cast<uint32_t>(participants.size()));
    for (auto vid : participants)
    {
      w.writeU64(vid);
    }

    return out;
  }

  bool Block::deserialize(const uint8_t *data, size_t len, Block &out)
  {
    Common::Reader r(data, len);

    uint32_t hdr_size = r.readU32();
    if (hdr_size > MAX_HEADER_BYTES || !r.ok())
      return false;

    std::vector<uint8_t> hdr(hdr_size);
    r.readBytes(hdr.data(), hdr_size);
    if (!r.ok())
      return false;

    if (!BlockHeader::deserialize(hdr.data(), hdr.size(), out.header))
    {
      return false;
    }

    uint32_t tx_count = r.readU32();
    if (tx_count > 100'000 || !r.ok())
      return false;

    out.transactions.clear();
    out.transactions.reserve(tx_count);

    for (uint32_t i = 0; i < tx_count; ++i)
    {
      uint32_t tx_size = r.readU32();
      if (tx_size > 1'000'000 || !r.ok())
        return false;

      std::vector<uint8_t> txbytes(tx_size);
      r.readBytes(txbytes.data(), tx_size);
      if (!r.ok())
        return false;

      Transaction tx;
      if (!Transaction::deserialize(txbytes.data(), txbytes.size(), tx))
      {
        return false;
      }
      out.transactions.push_back(std::move(tx));
    }

    uint32_t sig_count = r.readU32();
    if (sig_count > 10'000 || !r.ok())
      return false;

    out.quorum_signatures.clear();
    out.quorum_signatures.reserve(sig_count);

    for (uint32_t i = 0; i < sig_count; ++i)
    {
      Crypto::ValidatorSignature vs;
      vs.signer_index = r.readU16();
      r.readBytes(vs.signature.data.data(), vs.signature.data.size());
      if (!r.ok())
        return false;
      out.quorum_signatures.push_back(vs);
    }

    uint32_t part_count = r.readU32();
    if (part_count > 10'000 || !r.ok())
      return false;

    out.participants.clear();
    out.participants.reserve(part_count);

    for (uint32_t i = 0; i < part_count; ++i)
    {
      uint64_t vid = r.readU64();
      if (!r.ok())
        return false;
      out.participants.push_back(vid);
    }

    // No trailing bytes tolerated after the last section.
    if (r.remaining() != 0)
      return false;

    return true;
  }

  void Block::serialize(Serialization::ISerializer &s)
  {
    auto bytes = serialize();
    s.binary(bytes.data(), bytes.size(), "block");
  }

  void Block::serialize(Serialization::ISerializer &s) const
  {
    auto bytes = serialize();
    s.binary(const_cast<uint8_t *>(bytes.data()), bytes.size(), "block");
  }

  size_t Block::serializedSize() const noexcept
  {
    size_t sz = 4 + header.serialize().size();

    sz += 4;
    for (const auto &tx : transactions)
    {
      sz += 4 + tx.serialize().size();
    }

    sz += 4;
    for (const auto &vs : quorum_signatures)
    {
      sz += 2 + vs.signature.data.size();
    }

    sz += 4 + participants.size() * 8;

    return sz;
  }

  std::string Block::toString() const
  {
    std::ostringstream ss;
    ss << "Block(height=" << header.height
       << " hash=" << hash().toString().substr(0, 16)
       << " txs=" << transactions.size()
       << " validators=" << header.active_validator_count
       << ")";
    return ss.str();
  }

  //  Merkle tree

  Crypto::Hash computeMerkleRoot(const std::vector<Crypto::Hash> &leaves)
  {
    if (leaves.empty())
    {
      return Crypto::Hash{};
    }

    std::vector<Crypto::Hash> level = leaves;

    while (level.size() > 1)
    {
      if (level.size() % 2 == 1)
      {
        level.push_back(level.back());
      }

      std::vector<Crypto::Hash> next;
      next.reserve(level.size() / 2);

      for (size_t i = 0; i < level.size(); i += 2)
      {
        std::vector<uint8_t> buf;
        buf.reserve(std::strlen(MERKLE_INTERNAL_DOMAIN) + 64);
        const char *domain = MERKLE_INTERNAL_DOMAIN;
        buf.insert(buf.end(),
                   reinterpret_cast<const uint8_t *>(domain),
                   reinterpret_cast<const uint8_t *>(domain) +
                       std::strlen(domain));
        buf.insert(buf.end(), level[i].data.begin(), level[i].data.end());
        buf.insert(buf.end(), level[i + 1].data.begin(),
                   level[i + 1].data.end());

        Crypto::Hash parent;
        Crypto::blake2b(buf.data(), buf.size(), parent.data.data(), 32);
        next.push_back(parent);
      }

      level = std::move(next);
    }

    return level[0];
  }

  Crypto::Hash computeTxRoot(const std::vector<Transaction> &txs)
  {
    std::vector<Crypto::Hash> leaves;
    leaves.reserve(txs.size());

    for (const auto &tx : txs)
    {
      Crypto::Hash txid = tx.txid();

      std::vector<uint8_t> buf;
      const char *domain = TX_LEAF_DOMAIN;
      buf.insert(buf.end(),
                 reinterpret_cast<const uint8_t *>(domain),
                 reinterpret_cast<const uint8_t *>(domain) +
                     std::strlen(domain));
      buf.insert(buf.end(), txid.data.begin(), txid.data.end());

      Crypto::Hash leaf;
      Crypto::blake2b(buf.data(), buf.size(), leaf.data.data(), 32);
      leaves.push_back(leaf);
    }

    return computeMerkleRoot(leaves);
  }

  Crypto::Hash computeValidatorSetRoot(const std::vector<Id> &active_set)
  {
    std::vector<Crypto::Hash> leaves;
    leaves.reserve(active_set.size());

    auto sorted = active_set;
    std::sort(sorted.begin(), sorted.end());

    for (auto vid : sorted)
    {
      std::vector<uint8_t> buf;
      const char *domain = VALIDATOR_LEAF_DOMAIN;
      buf.insert(buf.end(),
                 reinterpret_cast<const uint8_t *>(domain),
                 reinterpret_cast<const uint8_t *>(domain) +
                     std::strlen(domain));

      for (int i = 0; i < 8; ++i)
        buf.push_back(uint8_t(vid >> (i * 8)));

      Crypto::Hash leaf;
      Crypto::blake2b(buf.data(), buf.size(), leaf.data.data(), 32);
      leaves.push_back(leaf);
    }

    return computeMerkleRoot(leaves);
  }

} // namespace Core