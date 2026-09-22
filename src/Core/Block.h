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
  //    [32] state_root
  //    [32] tx_root
  //    [32] receipts_root
  //    [32] validator_set_root
  //    [8]  total_fees
  //    [4]  tx_count
  //    [4]  active_validator_count
  //
  //  Total: 258 bytes.
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

} // namespace Core