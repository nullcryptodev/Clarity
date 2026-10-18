// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ChainAdapter.h"
#include "Session.h"

#include "Crypto/Types.h"

#include "Wallet/KeyStore.h"
#include "Wallet/RpcClient.h"
#include "Wallet/Signer.h"

namespace Bridge::Submission
{
  //  =========================================================================
  //  Deposit submission
  //
  //  Turns a scanned ObservedDeposit into a signed, submitted
  //  BridgeMint transaction on the Clarity node.
  //
  //  The pipeline is:
  //
  //    1. Check whether the deposit has already been minted
  //       (getBridgeConsumed). Skip if so.
  //    2. Fetch the BridgeChainRegistration for the source chain.
  //       Fail if not registered or disabled.
  //    3. Build the BridgeMint transaction with the given
  //       attestation block. Fail on builder rejection (malformed
  //       block, invalid amount, etc.).
  //    4. Sign the transaction with the watcher's account key.
  //    5. Submit via sendRawTransaction. Record the txid.
  //
  //  The attestation block is supplied by the caller — it comes
  //  from AssembleMintBlock, which in turn reads it from the
  //  on-chain BridgeAttest records. If the block is empty,
  //  submission is disabled and the function returns Disabled.
  //  =========================================================================

  enum class SubmitOutcome
  {
    //  Transaction submitted and accepted into the mempool. The
    //  clarity_tx_hash out-param carries the returned txid.
    Submitted,

    //  The deposit has already been minted. The scan cursor can
    //  advance past this deposit safely. clarity_tx_hash is the
    //  (previously recorded) mint height, not a hash.
    AlreadyConsumed,

    //  Submission is disabled — no attestation block was supplied.
    //  The scan cursor can advance past this deposit (the deposit
    //  is still visible on the source chain; a future run with a
    //  block supplied will retry).
    Disabled,

    //  Submission failed: builder rejection, RPC error, signing
    //  error, or chain registration missing. The caller should
    //  NOT advance past this deposit; a subsequent poll will
    //  retry. error_out carries the reason.
    Failed,
  };

  //  Submit a single BridgeMint against the given attestation
  //  block.
  //
  //  Preconditions:
  //    - rt.adapter and rt.rpc are non-null (checked by caller).
  //    - session.hasKeystore() (checked by caller).
  //    - session.clarity_connected (checked by caller).
  //    - attestation_block is non-empty (checked here; empty
  //      returns Disabled).
  //
  //  On Disabled: the scan cursor can advance (the deposit will
  //  still be seen on the source chain in a future scan with a
  //  block supplied).
  //
  //  On AlreadyConsumed: the scan cursor can advance (the deposit
  //  was minted in an earlier run).
  //
  //  On Submitted: clarity_tx_hash is set. The caller records it
  //  in whatever local journal it maintains and advances the
  //  cursor.
  //
  //  On Failed: the caller must NOT advance the cursor past this
  //  deposit. error_out carries the reason.
  SubmitOutcome SubmitDeposit(
      WatcherSession &session,
      ChainRuntime &rt,
      const ObservedDeposit &deposit,
      const std::vector<uint8_t> &attestation_block,
      Crypto::Hash *clarity_tx_hash,
      std::string *error_out);

  //  =========================================================================
  //  Attestation submission
  //
  //  Each active watcher publishes one BridgeAttest transaction per
  //  deposit. The transactions are recorded on-chain and read back
  //  by the assembler (next section) to build a BridgeMint's
  //  signature block.
  //
  //  SubmitAttestation produces one such transaction: it computes
  //  the deposit's canonical mint hash, asks the signer to sign
  //  it (using the same key path the outer transaction uses),
  //  wraps that signature in a BridgeAttest payload, signs the
  //  outer transaction with the keystore's account key, and
  //  submits. The consensus key never leaves the Signer
  //  abstraction.
  //
  //  The submit is idempotent from the caller's point of view:
  //  resubmitting after a crash is fine, because the executor
  //  rejects duplicate attestations and the bridge treats
  //  AlreadyAttested as "nothing to do, advance the cursor."
  //  =========================================================================

  enum class AttestOutcome
  {
    //  The BridgeAttest transaction was accepted by the node.
    Submitted,

    //  This watcher has already attested to this deposit. Safe to
    //  advance past the deposit.
    AlreadyAttested,

    //  The deposit has already been minted. Attesting to it is
    //  pointless. Safe to advance.
    AlreadyConsumed,

    //  This watcher isn't in the active set for this source chain
    //  at the current height (not registered, inactive, or
    //  session.watcher_id is 0/unresolved). Not an error; just
    //  means this process shouldn't submit attestations. The
    //  caller should log once and skip.
    NotAWriter,

    //  Failure. The caller should NOT advance the cursor past
    //  this deposit; a subsequent poll retries. error_out carries
    //  the reason.
    Failed,
  };

  //  Submit a BridgeAttest for one deposit. The attestation is
  //  signed by session.signer using the same key path the outer
  //  transaction signature uses (Wallet::clrtyPath(0, 0, 0)).
  //
  //  Preconditions (checked here, not by the caller):
  //    - session.watcher_id != 0
  //    - session.hasKeystore() && session.signer
  //    - session.clarity_rpc
  //    - rt.adapter
  //  Any of those missing returns NotAWriter or Failed with a
  //  diagnostic in error_out.
  AttestOutcome SubmitAttestation(
      WatcherSession &session,
      ChainRuntime &rt,
      const ObservedDeposit &deposit,
      Crypto::Hash *attest_tx_hash,
      std::string *error_out);

  //  =========================================================================
  //  Block assembly
  //
  //  Reads the on-chain attestations for one deposit and produces
  //  the [2] count || N*66 block a BridgeMint needs. Verifies
  //  quorum and (destination, amount) agreement.
  //  =========================================================================

  enum class AssembleOutcome
  {
    //  A valid block was assembled. block_out is populated.
    Ok,

    //  Fewer attestations than the quorum threshold. This is the
    //  normal "wait for peers" outcome; retry next poll.
    NotYetQuorum,

    //  Attestations disagree on (destination, amount). This is a
    //  federation split. It cannot be resolved automatically; the
    //  deposit stays pending until the federation resolves the
    //  split offline.
    Conflicting,

    //  The attestations couldn't be parsed, or an attestation's
    //  signer_index is inconsistent with the active set, or the
    //  RPC returned an unexpected shape. Retry.
    StateError,

    //  Transport/RPC failure. Retry.
    RpcError,
  };

  //  Assemble the BridgeMint signature block for one deposit.
  //
  //  Reads the recorded attestations (getBridgeAttestations),
  //  verifies that they agree on (destination, amount) and that
  //  the count meets quorum, and produces the block.
  //
  //  `quorum` is the number of distinct attestations required.
  //  The caller computes it from the active set size; see
  //  bftQuorum in the executor.
  AssembleOutcome AssembleMintBlock(
      Wallet::RpcClient &clarity_rpc,
      Wallet::Network network,
      uint64_t source_chain_id,
      const ObservedDeposit &deposit,
      size_t quorum,
      std::vector<uint8_t> *block_out,
      std::string *error_out);
} // namespace Bridge::Submission