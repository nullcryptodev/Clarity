// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"

namespace Bridge::Signing
{
  //  =========================================================================
  //  Bridge signing
  //
  //  Production equivalent of the test fixture's
  //  signBridgeMintMessage. Given a deposit observation and a set
  //  of watcher consensus keys, produces the `[2] count || N*66`
  //  signature block that the executor's verifyBridgeSignatures
  //  consumes.
  //
  //  The block format, the canonical message, and the domain tags
  //  are byte-for-byte identical to the executor side (see
  //  parseBridgeSignatureBlock and encodeBridgeMintMessage in
  //  TransactionExecutor.cpp, and signBridgeMintMessage in the
  //  fixture). Any divergence between this module and the executor
  //  causes every mint to be rejected — the tests around the
  //  builder/executor pair guard against that.
  //
  //  The module is deliberately small:
  //
  //    - Encode* : build the canonical message the executor will
  //                rebuild from the payload.
  //    - Sign*   : produce one watcher's attestation over that
  //                message.
  //    - Assemble*: concatenate attestations into the wire block.
  //    - Build*  : one-call convenience that does all three, used
  //                by the submission loop.
  //
  //  The caller is responsible for knowing which watchers to sign
  //  with and what index each occupies in the sorted active set.
  //  That information comes from chain state (the active watcher
  //  set), which this module deliberately does not read — reading
  //  is the submission loop's job, and keeping it out of the
  //  signing module keeps the module testable without a node.
  //  =========================================================================

  //  A single watcher's attestation: the position in the sorted
  //  active-watcher list, plus the signature over the canonical
  //  message.
  struct Attestation
  {
    uint16_t signer_index{0};
    Crypto::Signature signature{};
  };

  //  Encode the canonical message that a BridgeMint attestation
  //  covers. Matches encodeBridgeMintMessage in
  //  TransactionExecutor.cpp byte-for-byte:
  //
  //    LE64(source_chain_id) || source_tx_hash(32) ||
  //    LE32(source_output_index) || destination(32) ||
  //    LE64(amount)
  //
  //  This is the message the executor rebuilds from the parsed
  //  payload and hashes before verifying signatures.
  std::vector<uint8_t> EncodeBridgeMintMessage(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const Crypto::Address &destination,
      uint64_t amount);

  //  Encode the canonical message for a BridgeAckWithdrawal. The
  //  message is just the withdrawal id as LE64; the domain tag
  //  "back" is prepended at hash time.
  std::vector<uint8_t> EncodeBridgeAckMessage(uint64_t withdrawal_id);

  //  Encode the canonical message for a BridgePause / Unpause.
  //  The message is the bound height as LE64; the domain tag is
  //  "bpaul" for pause, "bunp" for unpause.
  std::vector<uint8_t> EncodeBridgePauseMessage(uint64_t bound_height);

  //  Domain-separated signing hash. `domain` is a 4-byte tag:
  //    "bmin"  — BridgeMint attestation
  //    "back"  — BridgeAckWithdrawal attestation
  //    "bpaul" — BridgePause governance
  //    "bunp"  — BridgeUnpause governance
  //    "brgr"  — BridgeRegisterChain governance
  //
  //  `domain` must be exactly 4 bytes. The caller is expected to
  //  pass a literal or a known constant; anything else is a
  //  programming error and the function returns a null hash.
  Crypto::Hash SigningHash(const char *domain,
                           const uint8_t *message,
                           size_t message_len);

  //  Sign one attestation. `signer_index` is the position of the
  //  signing watcher in the sorted active set (which the caller
  //  fetched from chain state). Returns nullopt on failure — a
  //  signature failure is not recoverable here, so the error is
  //  logged by the caller.
  std::optional<Attestation> Sign(
      const Crypto::SecretKey &watcher_consensus_key,
      uint16_t signer_index,
      const Crypto::Hash &signing_hash);

  //  Assemble the wire-format signature block:
  //
  //    [2]  count (LE)
  //    [N]  each: [2] signer_index (LE) || [64] signature
  //
  //  This is exactly what parseBridgeSignatureBlock in
  //  TransactionExecutor.cpp expects.
  std::vector<uint8_t> AssembleBlock(
      const std::vector<Attestation> &attestations);

  //  One-call convenience for BridgeMint:
  //  encode → hash → sign with every key → assemble.
  //
  //  `watchers` is a vector of (signer_index, consensus_secret_key)
  //  pairs. The caller has fetched the active watcher set from
  //  chain state and paired each watcher's consensus key with its
  //  index in the sorted set. Signing fewer than the quorum is not
  //  an error here — the executor will reject the resulting
  //  transaction — but the submission loop is expected to sign
  //  with at least bftQuorum(active_set_size) watchers.
  //
  //  On success, returns the encoded `[2] count || N*66` block.
  //  On failure, returns nullopt and populates error_out.
  std::optional<std::vector<uint8_t>> BuildBridgeMintBlock(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const Crypto::Address &destination,
      uint64_t amount,
      const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
      std::string *error_out = nullptr);

  //  One-call convenience for BridgeAckWithdrawal.
  std::optional<std::vector<uint8_t>> BuildBridgeAckBlock(
      uint64_t withdrawal_id,
      const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
      std::string *error_out = nullptr);

  //  One-call convenience for BridgePause / BridgeUnpause.
  //  `domain` is "bpaul" for pause, "bunp" for unpause.
  std::optional<std::vector<uint8_t>> BuildBridgePauseBlock(
      const char *domain,
      uint64_t bound_height,
      const std::vector<std::pair<uint16_t, Crypto::SecretKey>> &watchers,
      std::string *error_out = nullptr);

  //  Sign the canonical mint message with one watcher's consensus
  //  key. Returns the signature alone, ready to be wrapped in a
  //  BridgeAttest transaction by Wallet::buildBridgeAttest.
  //
  //  A BridgeAttest carries one of these; a BridgeMint carries a
  //  quorum of them, assembled into the [2] count || N*66 block.
  std::optional<Crypto::Signature> SignSingleBridgeMint(
      const Crypto::SecretKey &watcher_consensus_key,
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const Crypto::Address &destination,
      uint64_t amount);
} // namespace Bridge::Signing