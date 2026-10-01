// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Types.h"

#include "Common/Wire.h"
#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "Core/ValidatorTypes.h"

namespace Consensus
{

  namespace
  {
    //  Domain separation for the signing hash. Kept distinct from the
    //  prevote/precommit domains so a signature over a timeout vote
    //  can never be replayed as a signature over a vote, or vice
    //  versa. The version suffix lets a future protocol change rotate
    //  the domain without ambiguity.
    constexpr const char *TIMEOUT_VOTE_DOMAIN = "CLRTY_TIMEOUT_VOTE_V1";

    //  Fixed wire size of one TimeoutVote:
    //    u64 height      = 8
    //    u64 round       = 8
    //    u16 signer_index= 2
    //    [64] signature  = 64
    //  Total = 82 bytes.
    constexpr size_t TIMEOUT_VOTE_WIRE_SIZE = 8 + 8 + 2 + 64;
  } // anonymous namespace

  const char *stepName(Step s) noexcept
  {
    switch (s)
    {
    case Step::NewHeight:
      return "new-height";
    case Step::Propose:
      return "propose";
    case Step::Prevote:
      return "prevote";
    case Step::Precommit:
      return "precommit";
    case Step::Commit:
      return "commit";
    }
    return "unknown";
  }

  Crypto::Hash timeoutVoteSigningHash(Height height, Round round)
  {
    //  The signing hash covers exactly (height, round) and the domain
    //  tag. It does NOT cover the signer index — the index is a
    //  position in an active set, and the same validator may occupy
    //  different indices in the committed set and the emergency set.
    //  Binding the signature to an index would make it unverifiable
    //  against the other set.
    //
    //  The message is small enough to build on the stack.
    std::vector<uint8_t> buf;
    buf.reserve(std::strlen(TIMEOUT_VOTE_DOMAIN) + 16);

    const char *domain = TIMEOUT_VOTE_DOMAIN;
    buf.insert(buf.end(),
               reinterpret_cast<const uint8_t *>(domain),
               reinterpret_cast<const uint8_t *>(domain) +
                   std::strlen(domain));

    Common::Writer w(buf);
    w.writeU64(height);
    w.writeU64(round);

    Crypto::Hash h;
    Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
    return h;
  }

  std::vector<uint8_t> encodeTimeoutVote(const TimeoutVote &tv)
  {
    std::vector<uint8_t> out;
    out.reserve(TIMEOUT_VOTE_WIRE_SIZE);

    Common::Writer w(out);
    w.writeU64(tv.height);
    w.writeU64(tv.round);
    w.writeU16(tv.signer_index);
    w.writeBytes(tv.signature.data.data(), tv.signature.data.size());

    return out;
  }

  std::optional<TimeoutVote> decodeTimeoutVote(const uint8_t *data, size_t len)
  {
    //  Exact-length check up front. A TimeoutVote is fixed-size on the
    //  wire (82 bytes), so anything else is malformed and we reject
    //  before touching the Reader.
    if (len != TIMEOUT_VOTE_WIRE_SIZE)
      return std::nullopt;

    Common::Reader r(data, len);

    TimeoutVote tv;
    tv.height = r.readU64();
    tv.round = r.readU64();
    tv.signer_index = r.readU16();
    r.readBytes(tv.signature.data.data(), tv.signature.data.size());

    if (!r.ok())
      return std::nullopt;

    //  Range-validate the signer index here so callers that decode
    //  blind (P2P message dispatch, fixture helpers) can't feed an
    //  out-of-range index downstream. INVALID_INDEX is the sentinel
    //  for "no signer"; it never appears in a well-formed vote.
    if (tv.signer_index == INVALID_INDEX)
      return std::nullopt;

    //  The exact-length guard above already proved there are no
    //  trailing bytes; the Reader would also have errored on a short
    //  read. The remaining() check is belt-and-braces.
    if (r.remaining() != 0)
      return std::nullopt;

    return tv;
  }

  //  TimeoutCertificate

  std::vector<uint8_t> TimeoutCertificate::serialize() const
  {
    std::vector<uint8_t> out;
    out.reserve(4 + votes.size() * TIMEOUT_VOTE_WIRE_SIZE);

    //  Length-prefixed vector of fixed-size entries. The count is a
    //  u32; each entry is TIMEOUT_VOTE_WIRE_SIZE bytes. A decoder
    //  that knows the entry size can skip the per-entry length
    //  prefix, which keeps the encoding compact and unambiguous.
    Common::Writer w(out);
    w.writeU32(static_cast<uint32_t>(votes.size()));

    for (const auto &tv : votes)
    {
      w.writeU64(tv.height);
      w.writeU64(tv.round);
      w.writeU16(tv.signer_index);
      w.writeBytes(tv.signature.data.data(), tv.signature.data.size());
    }

    return out;
  }

  bool TimeoutCertificate::deserialize(const uint8_t *data, size_t len,
                                       TimeoutCertificate &out)
  {
    Common::Reader r(data, len);

    const uint32_t count = r.readU32();
    if (!r.ok())
      return false;

    //  Bound the count before allocating. A certificate larger than
    //  the maximum plausible active set is malformed; ACTIVE_SET_MAX
    //  is 100, but allow headroom for future growth and for
    //  certificates assembled across a couple of rounds during a
    //  stall. 4096 prevents a trivial memory amplification from a
    //  hostile peer.
    constexpr uint32_t MAX_CERT_VOTES = 4096;
    if (count > MAX_CERT_VOTES)
      return false;

    out.votes.clear();
    out.votes.reserve(count);

    for (uint32_t i = 0; i < count; ++i)
    {
      //  Fast pre-check: if the buffer can't possibly hold another
      //  full entry, fail now rather than letting readU64/readU16
      //  set the error flag mid-entry. Saves one branch per field on
      //  the happy path and makes the failure mode uniform.
      if (r.remaining() < TIMEOUT_VOTE_WIRE_SIZE)
        return false;

      TimeoutVote tv;
      tv.height = r.readU64();
      tv.round = r.readU64();
      tv.signer_index = r.readU16();
      r.readBytes(tv.signature.data.data(), tv.signature.data.size());

      if (!r.ok())
        return false;

      if (tv.signer_index == INVALID_INDEX)
        return false;

      out.votes.push_back(tv);
    }

    if (!r.ok())
      return false;

    //  No trailing bytes tolerated. A certificate is a self-contained
    //  blob; anything after the last entry is a decoding error, not
    //  padding.
    if (r.remaining() != 0)
      return false;

    return true;
  }

  bool verifyTimeoutCertificate(
      const TimeoutCertificate &cert,
      const std::vector<Id> &committed_set,
      Height cert_height,
      Round cert_round,
      const std::function<bool(Id, Core::ValidatorInfo &)> &lookup_validator,
      std::string &error)
  {
    if (committed_set.size() < 4)
    {
      error = "committed set too small for emergency rotation";
      return false;
    }

    const size_t f = (committed_set.size() - 1) / 3;
    const size_t required = f + 1;

    if (cert_round < Core::EMERGENCY_ROTATION_ROUNDS)
    {
      error = "emergency_rotation below threshold";
      return false;
    }

    if (cert.votes.size() < required)
    {
      error = "timeout certificate has too few attestations";
      return false;
    }

    std::vector<bool> seen(committed_set.size(), false);
    size_t counted = 0;

    const Crypto::Hash signing_hash =
        timeoutVoteSigningHash(cert_height, cert_round);

    for (const auto &tv : cert.votes)
    {
      if (tv.height != cert_height)
      {
        error = "timeout vote for wrong height";
        return false;
      }
      if (tv.round != cert_round)
      {
        error = "timeout vote for wrong round";
        return false;
      }
      if (tv.round < Core::EMERGENCY_ROTATION_ROUNDS)
      {
        error = "timeout vote below threshold round";
        return false;
      }
      if (tv.signer_index >= committed_set.size())
      {
        error = "timeout vote signer out of range";
        return false;
      }
      if (seen[tv.signer_index])
      {
        error = "duplicate timeout vote from same signer";
        return false;
      }
      seen[tv.signer_index] = true;

      const Id vid = committed_set[tv.signer_index];
      Core::ValidatorInfo v;
      if (!lookup_validator(vid, v))
      {
        error = "timeout vote from unknown validator";
        return false;
      }

      if (!Crypto::verify(signing_hash, v.effectiveConsensusKey(), tv.signature))
      {
        error = "invalid timeout vote signature";
        return false;
      }

      ++counted;
      if (counted >= required)
        break;
    }

    if (counted < required)
    {
      error = "timeout certificate below f+1";
      return false;
    }

    return true;
  }
} // namespace Consensus