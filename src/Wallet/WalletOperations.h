// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include "Core/Transaction.h"
#include "Crypto/Types.h"
#include "RpcClient.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  WalletOperations
  //
  //  High-level operations that combine an RpcClient with the wallet's
  //  transaction-building and signing. These are the operations the
  //  interactive wallet's command handlers call, and the operations
  //  that a future scripted wallet would call.
  //
  //  Everything here is synchronous. Timeouts are per-operation and
  //  passed explicitly where they matter.

  struct AccountState
  {
    uint64_t balance{0};
    uint64_t nonce{0};
  };

  //  The result of polling for a transaction's receipt. Distinguishes
  //  "committed successfully" from "committed with a Failure receipt"
  //  from "not yet in a block."
  struct ReceiptOutcome
  {
    enum class Kind
    {
      Confirmed, // receipt exists and status == Success
      Failed,    // receipt exists and status == Failure
      Pending,   // timeout expired, transaction not yet in a block
    };

    Kind kind{Kind::Pending};
    Common::Json receipt; // populated iff kind == Confirmed or Failed
  };

  //  Fetch an account's balance and nonce in two RPC calls. If either
  //  fails, returns nullopt and populates error_out.
  //
  //  Note: this is two round trips, not one. The RPC surface doesn't
  //  expose a combined "get account" that returns both. If it ever
  //  does, switch to that.
  std::optional<AccountState> fetchAccountState(
      RpcClient &rpc,
      const std::string &address_bech32m,
      std::string *error_out = nullptr);

  //  Submit a signed transaction. Serializes the transaction, hex-
  //  encodes it, and calls clrty_sendRawTransaction (bare name:
  //  "sendRawTransaction").
  //
  //  On success, returns the tx_hash as a hex string (with 0x prefix).
  //  A successful return means the tx was accepted into the mempool;
  //  it does NOT mean the tx has been confirmed.
  std::optional<std::string> submitSigned(
      RpcClient &rpc,
      const Core::Transaction &tx,
      std::string *error_out = nullptr);

  //  Poll for a transaction receipt until either it appears or the
  //  timeout expires.
  //
  //  Returns:
  //    - ReceiptOutcome with kind == Confirmed : tx is in a block and succeeded
  //    - ReceiptOutcome with kind == Failed    : tx is in a block and failed
  //    - ReceiptOutcome with kind == Pending   : tx is not yet in a block
  //    - std::nullopt                           : the RPC layer failed
  //
  //  On std::nullopt, error_out is populated. On Pending, error_out is
  //  empty — "not yet confirmed" is not an error.
  //
  //  The poll interval starts at 500 ms and doubles up to 4 s, so an
  //  early confirmation is detected quickly and a slow one doesn't
  //  hammer the node.
  std::optional<ReceiptOutcome> waitForReceipt(
      RpcClient &rpc,
      const std::string &txid_hex,
      std::chrono::seconds timeout,
      std::string *error_out = nullptr);

  //  Inspect a receipt object from the server and determine whether it
  //  reports success or failure. Returns true for Success, false for
  //  Failure, throws std::runtime_error for a malformed receipt (which
  //  indicates a server bug, not a transaction outcome).
  bool receiptSucceeded(const Common::Json &receipt);

  //  TrustedRoot
  //
  //  A state root the wallet is willing to verify proofs against.
  //  `peer_verified` is true when two independent endpoints returned
  //  the same root — meaning the wallet is not trusting a single
  //  server. When false, the wallet fell back to single-server trust
  //  (either no peer was configured, or the peer was unreachable and
  //  the caller asked to proceed anyway).
  struct TrustedRoot
  {
    Crypto::Hash root;
    uint64_t height{0};
    bool peer_verified{false};
  };

  //  Fetch a root to verify proofs against. If `peer` is non-null,
  //  the peer's header at the same height must agree with the
  //  primary's, or the fetch fails. If `peer` is null, the primary's
  //  root is returned with `peer_verified == false`.
  //
  //  Returns nullopt on any RPC failure, or on disagreement. The
  //  error_out message distinguishes them.
  std::optional<TrustedRoot> fetchTrustedRoot(
      RpcClient &primary,
      RpcClient *peer,
      std::string *error_out = nullptr);

  //  VerifiedBalance
  //
  //  A balance confirmed by an SMT proof against a trusted root. The
  //  wallet refuses to return a value it couldn't verify.
  //
  //  `is_empty` is true for a non-inclusion proof — the account has
  //  never been touched, so its balance is zero by construction.
  struct VerifiedBalance
  {
    uint64_t balance{0};
    bool is_empty{false};
    Crypto::Hash state_root;
    uint64_t version{0};
    bool peer_verified{false};
  };

  //  Fetch and verify the balance of an account.
  //
  //  Flow:
  //    1. fetchTrustedRoot(primary, peer) — get a root to verify against.
  //    2. getProof(primary, Account, address_bytes, root.height) — get
  //       a proof for the account at that version.
  //    3. If the proof's state_root doesn't match the trusted root,
  //       fail. The server is inconsistent with itself.
  //    4. State::verifyProof(trusted.root, proof.proof) — verify
  //       locally. If it fails, the server lied about the value and
  //       the wallet refuses to return it.
  //    5. Decode the leaf value (a serialized Account) and return the
  //       balance.
  //
  //  On non-inclusion (the account doesn't exist at the version),
  //  returns a VerifiedBalance with balance 0 and is_empty true.
  std::optional<VerifiedBalance> fetchVerifiedBalance(
      RpcClient &primary,
      RpcClient *peer,
      const std::string &address_bech32m,
      Network network,
      std::string *error_out = nullptr);
} // namespace Wallet