// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>

#include "Message.h"

#include "Common/Wire.h"

#include "Core/Block.h"

#include "Crypto/Blake2b.h"

namespace Consensus
{
  namespace
  {
    constexpr const char *PROPOSAL_DOMAIN = "CLRTY_PROPOSAL_V1";
    constexpr const char *VOTE_DOMAIN = "CLRTY_VOTE_V1";

    Crypto::Hash hashDomain(const char *domain,
                            const uint8_t *data, size_t len)
    {
      size_t dlen = std::strlen(domain);
      std::vector<uint8_t> buf;
      buf.reserve(dlen + len);
      buf.insert(buf.end(),
                 reinterpret_cast<const uint8_t *>(domain),
                 reinterpret_cast<const uint8_t *>(domain) + dlen);
      buf.insert(buf.end(), data, data + len);

      Crypto::Hash h;
      Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
      return h;
    }

    constexpr uint32_t MAX_BLOCK_BYTES_WIRE = 8 * 1024 * 1024;
  } // anonymous namespace

  std::vector<uint8_t> encodeProposal(const Proposal &p)
  {
    std::vector<uint8_t> out;
    out.reserve(8 + 8 + 8 + 2 + 4 + p.block_bytes.size() + 64);

    Common::Writer w(out);
    w.writeU64(p.height);
    w.writeU64(p.round);
    w.writeU64(p.signer_id);
    w.writeU16(p.signer_index);
    w.writeU32(static_cast<uint32_t>(p.block_bytes.size()));
    w.writeVector(p.block_bytes);
    w.writeBytes(p.signature.data.data(), p.signature.data.size());

    return out;
  }

  bool decodeProposal(const uint8_t *data, size_t len, Proposal &out)
  {
    Common::Reader r(data, len);

    out.height = r.readU64();
    out.round = r.readU64();
    out.signer_id = r.readU64();
    out.signer_index = r.readU16();
    uint32_t bs = r.readU32();

    if (!r.ok() || bs > MAX_BLOCK_BYTES_WIRE)
      return false;

    // Bounds-check the block payload before allocating. Reader::readVector
    // will catch a truncated read on its own, but checking here avoids
    // allocating a huge vector for a bogus length first.
    if (r.remaining() < static_cast<size_t>(bs) + 64)
      return false;

    out.block_bytes = r.readVector(bs);
    r.readBytes(out.signature.data.data(), out.signature.data.size());

    if (!r.ok())
      return false;

    // Derive block_hash from the block bytes. If the block fails to
    // deserialize, leave the hash null (caller will reject).
    Core::Block block;
    if (Core::Block::deserialize(out.block_bytes.data(),
                                 out.block_bytes.size(), block))
    {
      out.block_hash = block.hash();
    }
    else
    {
      out.block_hash = Crypto::Hash{};
    }

    return true;
  }

  std::vector<uint8_t> encodeVote(const Vote &v)
  {
    std::vector<uint8_t> out;
    out.reserve(8 + 8 + 8 + 2 + 1 + 32 + 64);

    Common::Writer w(out);
    w.writeU64(v.height);
    w.writeU64(v.round);
    w.writeU64(v.signer_id);
    w.writeU16(v.signer_index);
    w.writeU8(v.is_nil ? 1 : 0);
    w.writeBytes(v.block_hash.data.data(), v.block_hash.data.size());
    w.writeBytes(v.signature.data.data(), v.signature.data.size());

    return out;
  }

  bool decodeVote(const uint8_t *data, size_t len, Vote &out)
  {
    Common::Reader r(data, len);

    out.height = r.readU64();
    out.round = r.readU64();
    out.signer_id = r.readU64();
    out.signer_index = r.readU16();
    out.is_nil = (r.readU8() != 0);
    r.readBytes(out.block_hash.data.data(), out.block_hash.data.size());
    r.readBytes(out.signature.data.data(), out.signature.data.size());

    return r.ok();
  }

  Crypto::Hash proposalSigningHash(Height height, Round round,
                                   const Crypto::Hash &block_hash)
  {
    uint8_t buf[8 + 8 + 32];
    for (int i = 0; i < 8; ++i)
      buf[i] = uint8_t(height >> (i * 8));
    for (int i = 0; i < 8; ++i)
      buf[8 + i] = uint8_t(round >> (i * 8));
    std::memcpy(buf + 16, block_hash.data.data(), 32);
    return hashDomain(PROPOSAL_DOMAIN, buf, sizeof(buf));
  }

  Crypto::Hash voteSigningHash(Height height, Round round,
                               bool is_nil, const Crypto::Hash &block_hash)
  {
    uint8_t buf[8 + 8 + 1 + 32];
    for (int i = 0; i < 8; ++i)
      buf[i] = uint8_t(height >> (i * 8));
    for (int i = 0; i < 8; ++i)
      buf[8 + i] = uint8_t(round >> (i * 8));
    buf[16] = is_nil ? 1 : 0;
    std::memcpy(buf + 17, block_hash.data.data(), 32);
    return hashDomain(VOTE_DOMAIN, buf, sizeof(buf));
  }

} // namespace Consensus