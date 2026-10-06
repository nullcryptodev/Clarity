// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "MessageTypes.h"

#include "Crypto/Types.h"
#include "State/ProofKeys.h"
#include "State/SmtProof.h"

namespace P2P
{
  //  GetProof / Proof message pair.
  //
  //  A light client asks for a proof of a key's value at a specific
  //  version. The server walks the SMT from that version's root,
  //  produces an SmtProof, and returns it alongside the root so the
  //  client can verify independently. The client needs no DB access
  //  and no knowledge of the chain's state beyond the root it's
  //  checking against.
  //
  //  The key descriptor type (ProofKeyType) and its resolver
  //  (resolveProofKey) live in State — the resolution is a state-layer
  //  concern, and both this protocol and the RPC getProof method
  //  consume it. Bring them into scope here so callers of this header
  //  don't need to include State/ProofKeys.h separately.
  using State::PROOF_VERSION_CURRENT;
  using State::ProofKeyType;
  using State::resolveProofKey;

  struct GetProofMessage
  {
    ProofKeyType key_type{ProofKeyType::Account};
    std::vector<uint8_t> key_bytes;
    uint64_t version{PROOF_VERSION_CURRENT};
  };

  struct ProofMessage
  {
    //  Ok means the server produced a proof. The proof may be an
    //  inclusion proof (value present) or a non-inclusion proof
    //  (value absent) — both are "Ok" from the server's point of
    //  view, and the client distinguishes them by inspecting
    //  `proof.value`.
    //
    //  KeyNotFound means the server could not produce a proof for
    //  this key at this version. This should not happen with a
    //  consistent DB, but a server that has pruned the requested
    //  version's nodes will return this.
    //
    //  VersionUnavailable means the requested version has no saved
    //  root. Either it was never written (a version below the chain's
    //  genesis), or it was pruned.
    //
    //  Malformed means the request's key_bytes did not match the
    //  layout its key_type requires. This is a client bug, not a
    //  server error, and the client should not retry it.
    enum class Status : uint8_t
    {
      Ok = 0,
      KeyNotFound = 1,
      VersionUnavailable = 2,
      Malformed = 3,
    };

    Status status{Status::Ok};

    // The state root the proof is against. The client verifies the
    // proof against this root, not against a root it fetched
    // separately — the whole point of returning it here is that the
    // client's verification is self-contained.
    Crypto::Hash state_root{};

    // The version the root was read at. The server resolves
    // PROOF_VERSION_CURRENT to the current head height before
    // replying, so this is always a concrete version, never the
    // sentinel.
    uint64_t version{0};

    // Meaningful only when status == Ok.
    State::SmtProof proof{};
  };

  // ---- Serialization ----
  //
  //  GetProof payload layout:
  //
  //    [1]  key_type
  //    [4]  reserved (zero)
  //    [4]  key_bytes length (LE)
  //    [N]  key_bytes
  //    [8]  version (LE)
  //
  //  Proof payload layout:
  //
  //    [1]  status
  //    [4]  reserved (zero)
  //    [32] state_root
  //    [8]  version (LE)
  //    [N]  serialized SmtProof (present only when status == Ok)
  //
  //  The reserved fields are deliberate: they keep the framing stable
  //  if a future version needs to extend either message with a flag
  //  or a small field, without a breaking wire change.

  std::vector<uint8_t> serializeGetProof(const GetProofMessage &m);
  bool deserializeGetProof(const uint8_t *data, size_t len,
                           GetProofMessage &out);

  std::vector<uint8_t> serializeProof(const ProofMessage &m);
  bool deserializeProof(const uint8_t *data, size_t len,
                        ProofMessage &out);

} // namespace P2P