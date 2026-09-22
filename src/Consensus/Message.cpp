// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Message.h"

#include "Core/Block.h"
#include "Crypto/Blake2b.h"
#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>

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
  } // anonymous namespace

  std::vector<uint8_t> encodeProposal(const Proposal &p)
  {
    std::vector<uint8_t> out;
    out.reserve(8 + 8 + 2 + 4 + p.block_bytes.size() + 64);

    Common::putU64(out, p.height);
    Common::putU64(out, p.round);
    Common::putU16(out, p.signer_index);
    Common::putU32(out, static_cast<uint32_t>(p.block_bytes.size()));
    out.insert(out.end(), p.block_bytes.begin(), p.block_bytes.end());
    out.insert(out.end(), p.signature.data.begin(), p.signature.data.end());

    return out;
  }

  bool decodeProposal(const uint8_t *data, size_t len, Proposal &out)
  {
    if (len < 8 + 8 + 2 + 4 + 64)
      return false;

    size_t off = 0;
    out.height = Common::readU64(data + off);
    off += 8;
    out.round = Common::readU64(data + off);
    off += 8;
    out.signer_index = Common::readU16(data + off);
    off += 2;
    uint32_t bs = Common::readU32(data + off);
    off += 4;

    if (off + bs + 64 > len)
      return false;

    out.block_bytes.assign(data + off, data + off + bs);
    off += bs;

    std::memcpy(out.signature.data.data(), data + off, 64);

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
    out.reserve(8 + 8 + 2 + 1 + 32 + 64);

    Common::putU64(out, v.height);
    Common::putU64(out, v.round);
    Common::putU16(out, v.signer_index);
    out.push_back(v.is_nil ? 1 : 0);
    out.insert(out.end(), v.block_hash.data.begin(), v.block_hash.data.end());
    out.insert(out.end(), v.signature.data.begin(), v.signature.data.end());

    return out;
  }

  bool decodeVote(const uint8_t *data, size_t len, Vote &out)
  {
    if (len < 8 + 8 + 2 + 1 + 32 + 64)
      return false;

    size_t off = 0;
    out.height = Common::readU64(data + off);
    off += 8;
    out.round = Common::readU64(data + off);
    off += 8;
    out.signer_index = Common::readU16(data + off);
    off += 2;
    out.is_nil = (data[off++] != 0);
    std::memcpy(out.block_hash.data.data(), data + off, 32);
    off += 32;
    std::memcpy(out.signature.data.data(), data + off, 64);

    return true;
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