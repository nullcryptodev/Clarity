// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Types.h"
#include "Transaction.h"
#include "ValidatorTypes.h"
#include "GlobalConfig.h"

#include "Consensus/Types.h"

namespace Core
{
  //  Block Header
  //
  //  Contains everything needed to verify a block except the transactions
  //  themselves. The `tx_root` commits to the transactions; the
  //  `state_root` commits to the resulting state.
  //
  //  Wire format (canonical serialization, little-endian):
  //
  //    [2]  version
  //    [8]  chain_id
  //    [8]  height
  //    [32] parent_hash
  //    [8]  timestamp_ms
  //    [32] proposer
  //    [8]  epoch
  //    [8]  rotation_index
  //    [8]  commit_round          // transmitted, NOT part of the hash
  //    [8]  emergency_rotation    // transmitted, IS part of the hash
  //    [32] state_root
  //    [32] tx_root
  //    [32] receipts_root
  //    [32] validator_set_root
  //    [8]  total_fees
  //    [4]  tx_count
  //    [4]  active_validator_count
  //    [4]  timeout_cert_len       // length of the encoded certificate
  //    [..] timeout_cert_bytes     // encoded TimeoutCertificate
  //
  //  Total: 270 bytes + certificate size.
  //
  //  commit_round is the round in which the precommit quorum formed. It
  //  may differ from the round the block was proposed in when the round
  //  advances between proposal and commit (validators locked on the
  //  original block re-precommit it in a later round).
  //
  //  commit_round is intentionally EXCLUDED from the block's hash. The
  //  block's identity is its header-minus-commit_round, its transactions,
  //  its quorum signatures, and its participants. Validators sign over
  //  the block hash in the round they are voting in, which is the round
  //  that becomes commit_round. If commit_round were part of the hash,
  //  the hash would change between proposal and commit in the
  //  round-crossing case, and every signature would be over the old
  //  hash. Excluding it from the hash keeps the hash stable and lets
  //  commit_round record the truth.
  //
  //  See BlockHeader::hash() in Block.cpp for the exact exclusion.

  struct BlockHeader
  {
    // ---- Versioning ----
    uint16_t version{GlobalConfig::CURRENT_BLOCK_VERSION};
    uint64_t chain_id{0};

    // ---- Position ----
    uint64_t height{0};
    Crypto::Hash parent_hash{};
    uint64_t timestamp_ms{0};

    // ---- Proposer ----
    Crypto::Address proposer{};

    // ---- Epoch info ----
    uint64_t epoch{0};
    uint64_t rotation_index{0};
    uint64_t commit_round{0};

    //  Emergency rotation round.
    //
    //  Zero on a normal block. Nonzero means the block was proposed
    //  on the emergency active set, and the value is the round at
    //  which the emergency decision was made.
    //
    //  Verifiers recompute the emergency set from (committed_set,
    //  registry, current_height) and use it for quorum and set-root
    //  checks. When the block commits, the emergency set is written
    //  to state as the new committed set.
    //
    //  Unlike commit_round, this field IS part of the block hash: it
    //  changes what set the block was validated against, so two blocks
    //  with identical header-except-emergency_rotation are different
    //  blocks.
    uint64_t emergency_rotation{0};

    //  Timeout certificate.
    //
    //  Present only when emergency_rotation > 0. Contains f+1 signed
    //  timeout attestations at rounds >= EMERGENCY_ROTATION_ROUNDS,
    //  drawn from the committed set. Empty otherwise.
    //
    //  Excluded from the block hash. The certificate is evidence
    //  attached to the block, not part of the block's identity — the
    //  same treatment commit_round and quorum_signatures get. If it
    //  were in the hash, a proposer could change the certificate
    //  without changing the block hash, which is exactly the wrong
    //  property.
    //
    //  The certificate IS in the wire format (serialize()), so it
    //  travels with the block. Verifiers read it from the deserialized
    //  header and check it before honouring emergency_rotation.
    Consensus::TimeoutCertificate timeout_certificate{};

    // ---- Commitments ----
    Crypto::Hash state_root{};
    Crypto::Hash tx_root{};
    Crypto::Hash receipts_root{};
    Crypto::Hash validator_set_root{};

    // ---- Accounting ----
    uint64_t total_fees{0};
    uint32_t tx_count{0};
    uint32_t active_validator_count{0};

    // ---- Validation (structural) ----

    bool isWellFormed() const noexcept;

    // Hashing
    //
    // Recomputed on every call. There used to be a mutable cache
    // here, and it was a bug source: BftConsensus::propose() calls
    // simulate_block (which reads block.hash() inside applyBlock),
    // then mutates header.state_root, then calls hash() again. The
    // cache returned the pre-mutation hash; the serialized bytes
    // carried the post-mutation state_root. Receiver and proposer
    // disagreed on the block hash. A cache over a struct with public
    // fields cannot be kept coherent; the cost of rehashing a 258-byte
    // buffer is negligible, so there is no cache.
    //
    // The hash excludes commit_round. See the note at the top of this
    // struct.

    Crypto::Hash hash() const;
    Crypto::Hash hashForSigning() const { return hash(); }

    // Serialization

    std::vector<uint8_t> serialize() const;
    static bool deserialize(const uint8_t *data, size_t len,
                            BlockHeader &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;

  private:
    // Serialization that omits commit_round. Used by hash() only.
    // The wire format via serialize() includes commit_round.
    std::vector<uint8_t> serializeForHash() const;
  };

  //  Block

  struct Block
  {
    BlockHeader header;
    std::vector<Transaction> transactions;
    std::vector<Crypto::ValidatorSignature> quorum_signatures;

    std::vector<Id> participants;

    bool isWellFormed() const noexcept;
    Crypto::Hash hash() const { return header.hash(); }

    std::vector<uint8_t> serialize() const;
    static bool deserialize(const uint8_t *data, size_t len, Block &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;

    size_t serializedSize() const noexcept;
    std::string toString() const;
  };

  //  Merkle tree utilities

  Crypto::Hash computeMerkleRoot(const std::vector<Crypto::Hash> &leaves);
  Crypto::Hash computeTxRoot(const std::vector<Transaction> &txs);
  Crypto::Hash computeValidatorSetRoot(const std::vector<Id> &active_set);

  //  Maximum serialized header size.
  //
  //  The fixed portion of the header is 266 bytes. A timeout
  //  certificate is 4 + 82*(f+1) bytes, where f = (n-1)/3 and n is
  //  the committed-set size. At ACTIVE_SET_MAX = 100, f = 33, so
  //  f+1 = 34, giving 4 + 34*82 = 2792 bytes. Total ~3058.
  //
  //  Allow generous slack for future growth — a larger active set, or
  //  a future change that carries attestations from a couple of
  //  heights during a multi-round stall — without allowing an
  //  unbounded allocation from a hostile peer.
  constexpr uint32_t MAX_HEADER_BYTES = 8 * 1024;
} // namespace Core