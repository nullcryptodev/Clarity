// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ProofMessages.h"

#include "State/SparseMerkleTree.h"

#include "Common/Wire.h"

namespace P2P
{
  namespace
  {
    //  Upper bound on key_bytes. The largest layout is a token
    //  balance key (32 + 4 = 36 bytes); the global name is capped at
    //  64 by Keys::global. 64 covers both, with room to spare.
    constexpr uint32_t MAX_KEY_BYTES = 64;
  } // anonymous namespace

  //  GetProof

  std::vector<uint8_t> serializeGetProof(const GetProofMessage &m)
  {
    std::vector<uint8_t> out;
    out.reserve(1 + 4 + 4 + m.key_bytes.size() + 8);

    Common::Writer w(out);
    w.writeU8(static_cast<uint8_t>(m.key_type));
    w.writeU32(0); // reserved
    w.writeU32(static_cast<uint32_t>(m.key_bytes.size()));
    if (!m.key_bytes.empty())
      w.writeBytes(m.key_bytes.data(), m.key_bytes.size());
    w.writeU64(m.version);

    return out;
  }

  bool deserializeGetProof(const uint8_t *data, size_t len,
                           GetProofMessage &out)
  {
    //  Minimum size: type(1) + reserved(4) + key_len(4) + version(8).
    constexpr size_t MIN_SIZE = 1 + 4 + 4 + 8;
    if (len < MIN_SIZE)
      return false;

    Common::Reader r(data, len);

    const uint8_t type_byte = r.readU8();
    if (type_byte > static_cast<uint8_t>(ProofKeyType::AmmPool))
      return false;
    out.key_type = static_cast<ProofKeyType>(type_byte);

    (void)r.readU32(); // reserved

    const uint32_t key_len = r.readU32();
    if (key_len > MAX_KEY_BYTES)
      return false;
    if (r.remaining() < static_cast<size_t>(key_len) + 8)
      return false;

    out.key_bytes = r.readVector(key_len);
    out.version = r.readU64();

    if (!r.ok())
      return false;

    // No trailing bytes tolerated.
    if (r.remaining() != 0)
      return false;

    return true;
  }

  //  Proof

  std::vector<uint8_t> serializeProof(const ProofMessage &m)
  {
    std::vector<uint8_t> out;

    std::vector<uint8_t> proof_bytes;
    if (m.status == ProofMessage::Status::Ok)
      proof_bytes = m.proof.serialize();

    out.reserve(1 + 4 + 32 + 8 + proof_bytes.size());

    Common::Writer w(out);
    w.writeU8(static_cast<uint8_t>(m.status));
    w.writeU32(0); // reserved
    w.writeBytes(m.state_root.data.data(), m.state_root.data.size());
    w.writeU64(m.version);

    if (!proof_bytes.empty())
      w.writeBytes(proof_bytes.data(), proof_bytes.size());

    return out;
  }

  bool deserializeProof(const uint8_t *data, size_t len,
                        ProofMessage &out)
  {
    //  Minimum size: status(1) + reserved(4) + root(32) + version(8).
    constexpr size_t MIN_SIZE = 1 + 4 + 32 + 8;
    if (len < MIN_SIZE)
      return false;

    Common::Reader r(data, len);

    const uint8_t status_byte = r.readU8();
    if (status_byte > static_cast<uint8_t>(ProofMessage::Status::Malformed))
      return false;
    out.status = static_cast<ProofMessage::Status>(status_byte);

    (void)r.readU32(); // reserved

    r.readBytes(out.state_root.data.data(), out.state_root.data.size());
    out.version = r.readU64();

    if (!r.ok())
      return false;

    if (out.status == ProofMessage::Status::Ok)
    {
      //  The proof is the rest of the payload. SmtProof::deserialize
      //  consumes exactly its own size and rejects trailing bytes, so
      //  we hand it the remaining bytes and require exact consumption.
      if (!State::SmtProof::deserialize(data + (len - r.remaining()),
                                        r.remaining(),
                                        out.proof))
        return false;
    }
    else
    {
      //  A non-Ok reply carries no proof. Require the payload to end
      //  here, so a malformed server can't smuggle data past a client
      //  that only inspects the status.
      if (r.remaining() != 0)
        return false;
    }

    return true;
  }

} // namespace P2P