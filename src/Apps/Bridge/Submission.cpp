// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Submission.h"
#include "Signing.h"

#include "GlobalConfig.h"

#include "Crypto/Ed25519.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/HdPath.h"
#include "Wallet/TransactionBuilder.h"
#include "Wallet/WalletError.h"

#include <algorithm>
#include <iostream>

namespace Bridge::Submission
{
  namespace
  {
    //  Parse a 0x-prefixed (or bare) hex string into a u64.
    //  Returns nullopt on any malformed input.
    std::optional<uint64_t> parseHexU64(const std::string &s)
    {
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if (i >= s.size())
        return std::nullopt;
      uint64_t v = 0;
      for (; i < s.size(); ++i)
      {
        const char c = s[i];
        int nib;
        if (c >= '0' && c <= '9')
          nib = c - '0';
        else if (c >= 'a' && c <= 'f')
          nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
          nib = c - 'A' + 10;
        else
          return std::nullopt;
        v = (v << 4) | static_cast<uint64_t>(nib);
      }
      return v;
    }

    //  Parse a 0x-prefixed (or bare) hex string into exactly
    //  out_len bytes. Returns false if the length or characters
    //  are wrong.
    bool parseHexBytes(const std::string &s, uint8_t *out, size_t out_len)
    {
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if (s.size() - i != out_len * 2)
        return false;
      auto nib = [](char c) -> int
      {
        if (c >= '0' && c <= '9')
          return c - '0';
        if (c >= 'a' && c <= 'f')
          return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
          return c - 'A' + 10;
        return -1;
      };
      for (size_t j = 0; j < out_len; ++j)
      {
        const int hi = nib(s[i + j * 2]);
        const int lo = nib(s[i + j * 2 + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out[j] = static_cast<uint8_t>((hi << 4) | lo);
      }
      return true;
    }

    //  Read a BridgeChainRegistration from the Clarity RPC and
    //  pull out the wrapped_token_id field. Returns nullopt on any
    //  failure (not registered, malformed response, transport
    //  error).
    std::optional<uint64_t> fetchWrappedTokenId(
        Wallet::RpcClient &clarity_rpc,
        uint64_t source_chain_id,
        std::string *error_out)
    {
      bool not_registered = false;
      std::string err;
      auto reg_json = Wallet::getBridgeChainRegistration(
          clarity_rpc, source_chain_id, &not_registered, &err);

      if (not_registered)
      {
        if (error_out)
          *error_out = "chain not registered: source_chain_id=" +
                       std::to_string(source_chain_id);
        return std::nullopt;
      }
      if (!reg_json.has_value())
      {
        if (error_out)
          *error_out = "getBridgeChainRegistration failed: " + err;
        return std::nullopt;
      }
      if (!reg_json->is_object())
      {
        if (error_out)
          *error_out = "chain registration response is not an object";
        return std::nullopt;
      }

      const auto &obj = *reg_json;
      if (!obj.contains("wrapped_token_id") ||
          !obj["wrapped_token_id"].is_string())
      {
        if (error_out)
          *error_out = "chain registration missing 'wrapped_token_id'";
        return std::nullopt;
      }

      auto v = parseHexU64(obj["wrapped_token_id"].get<std::string>());
      if (!v.has_value())
      {
        if (error_out)
          *error_out = "'wrapped_token_id' is not valid hex";
        return std::nullopt;
      }
      return *v;
    }

    //  Resolve this watcher's position in the sorted active set
    //  for the given source chain. Returns nullopt if the watcher
    //  is not active (not in the set, or the RPC failed). When
    //  error_out is populated, the caller should treat the failure
    //  as an RPC error; when it is empty, the watcher simply
    //  isn't in the set.
    std::optional<std::pair<uint16_t, Id>> findSelfInActiveSet(
        Wallet::RpcClient &clarity_rpc,
        uint64_t source_chain_id,
        uint64_t watcher_id,
        std::string *error_out)
    {
      std::string err;
      auto res = Wallet::getActiveWatchers(
          clarity_rpc, source_chain_id, 0, &err);

      if (!res.has_value())
      {
        if (error_out)
          *error_out = "getActiveWatchers failed: " + err;
        return std::nullopt;
      }
      if (!res->is_object() || !res->contains("watchers") ||
          !(*res)["watchers"].is_array())
      {
        if (error_out)
          *error_out = "getActiveWatchers returned an unexpected shape";
        return std::nullopt;
      }

      //  The RPC returns watchers in owner-address order (the
      //  StateAccess iterates the owner-address index). The
      //  executor sorts by validator_id to assign signer_index,
      //  so the bridge must too.
      struct Row
      {
        uint64_t watcher_id;
        uint64_t validator_id;
      };
      std::vector<Row> rows;
      rows.reserve((*res)["watchers"].size());
      for (const auto &w : (*res)["watchers"])
      {
        if (!w.is_object())
          continue;
        if (!w.contains("watcher_id") || !w.contains("validator_id"))
          continue;
        if (!w["watcher_id"].is_string() || !w["validator_id"].is_string())
          continue;

        auto wid = parseHexU64(w["watcher_id"].get<std::string>());
        auto vid = parseHexU64(w["validator_id"].get<std::string>());
        if (!wid.has_value() || !vid.has_value())
          continue;
        rows.push_back({*wid, *vid});
      }

      std::sort(rows.begin(), rows.end(),
                [](const Row &a, const Row &b)
                { return a.validator_id < b.validator_id; });

      for (size_t i = 0; i < rows.size(); ++i)
      {
        if (rows[i].watcher_id == watcher_id)
          return std::make_pair(static_cast<uint16_t>(i),
                                static_cast<Id>(rows[i].validator_id));
      }

      //  Not in the set. Not an error.
      return std::nullopt;
    }

    //  Serialize a transaction to a 0x-prefixed hex string. Used
    //  by both submit paths.
    std::string transactionToHex(const Core::Transaction &tx)
    {
      auto bytes = tx.serialize();
      static const char HEX[] = "0123456789abcdef";
      std::string hex = "0x";
      hex.reserve(2 + bytes.size() * 2);
      for (uint8_t b : bytes)
      {
        hex.push_back(HEX[b >> 4]);
        hex.push_back(HEX[b & 0xF]);
      }
      return hex;
    }

    //  Parse a "0x"-prefixed 32-byte hash string into a
    //  Crypto::Hash. Leaves the hash zeroed if the parse fails.
    void parseTxidInto(const std::string &txid_str, Crypto::Hash *out)
    {
      if (out == nullptr)
        return;
      uint8_t bytes[32];
      if (!parseHexBytes(txid_str, bytes, 32))
        return;
      std::memcpy(out->data.data(), bytes, 32);
    }

    //  Pick the destination that a mint / attestation should use.
    //
    //  Two paths:
    //
    //    (a) session.mint_destination is set (--mint-destination
    //        flag): use it. All watchers in the federation must
    //        use the same address, otherwise the executor
    //        rejects the second attestation with "conflicting
    //        attestation." This is a test-only shortcut until
    //        the deposit format carries the destination
    //        on-chain.
    //
    //    (b) session.mint_destination is not set: use the
    //        watcher's own keystore address. This only works for
    //        a single-watcher federation; with two or more
    //        watchers, each signs a different destination and
    //        the mint never assembles.
    //
    //  A production deployment needs (c): the destination
    //  embedded in the source-chain deposit, read by every
    //  watcher from chain data. That's a deposit-format change
    //  for a future batch.
    Crypto::Address effectiveDestination(const WatcherSession &session)
    {
      if (session.mint_destination.has_value())
        return *session.mint_destination;
      return *session.address;
    }
  } // anonymous namespace

  //  ===========================================================================
  //  SubmitDeposit
  //  ===========================================================================

  SubmitOutcome SubmitDeposit(
      WatcherSession &session,
      ChainRuntime &rt,
      const ObservedDeposit &deposit,
      const std::vector<uint8_t> &attestation_block,
      Crypto::Hash *clarity_tx_hash,
      std::string *error_out)
  {
    if (clarity_tx_hash)
      clarity_tx_hash->data.fill(0);

    //  ---- Precondition: submission enabled ----

    if (attestation_block.empty())
    {
      //  No attestation block supplied. This is not an error —
      //  the caller doesn't have a quorum yet. Report it as
      //  Disabled and let the caller advance the cursor.
      return SubmitOutcome::Disabled;
    }

    if (!session.hasKeystore() || !session.signer)
    {
      if (error_out)
        *error_out = "no keystore open; cannot sign submission";
      return SubmitOutcome::Failed;
    }

    if (!session.clarity_rpc)
    {
      if (error_out)
        *error_out = "no Clarity RPC client; cannot submit";
      return SubmitOutcome::Failed;
    }

    if (!rt.adapter)
    {
      if (error_out)
        *error_out = "chain adapter is null";
      return SubmitOutcome::Failed;
    }

    Wallet::RpcClient &clarity = *session.clarity_rpc;

    //  ---- Step 1: replay guard ----

    bool is_consumed = false;
    std::string consumed_err;
    auto mint_height = Wallet::getBridgeConsumed(
        clarity,
        deposit.source_chain_id,
        deposit.source_tx_hash,
        deposit.source_output_index,
        &is_consumed,
        &consumed_err);

    if (!mint_height.has_value() && !consumed_err.empty())
    {
      //  The call failed. We don't know whether the deposit is
      //  consumed. Do NOT submit — a blind submit would waste a
      //  fee if it is.
      if (error_out)
        *error_out = "getBridgeConsumed failed: " + consumed_err;
      return SubmitOutcome::Failed;
    }

    if (is_consumed)
    {
      //  Already minted. The scan cursor can advance — the deposit
      //  will still be visible on the source chain, but it doesn't
      //  need to be re-minted.
      return SubmitOutcome::AlreadyConsumed;
    }

    //  ---- Step 2: chain registration ----

    std::string reg_err;
    auto wrapped_token_id =
        fetchWrappedTokenId(clarity, deposit.source_chain_id, &reg_err);
    if (!wrapped_token_id.has_value())
    {
      if (error_out)
        *error_out = reg_err;
      return SubmitOutcome::Failed;
    }

    //  ---- Step 3: convert amount ----

    //  The adapter owns the conversion between source atomic
    //  units and Clarity atomic units, because the ratio and the
    //  rounding policy are chain-specific. We call the adapter
    //  here rather than embedding the ratio in the submission
    //  loop.
    uint64_t clarity_amount = 0;
    try
    {
      clarity_amount = rt.adapter->to_clarity_atomic(
          deposit.amount_source_atomic,
          GlobalConfig::DECIMALS);
    }
    catch (const std::exception &e)
    {
      if (error_out)
        *error_out = std::string("to_clarity_atomic failed: ") + e.what();
      return SubmitOutcome::Failed;
    }

    if (clarity_amount == 0)
    {
      //  Rounding down to zero would produce a zero-amount mint,
      //  which the executor rejects. Skip without advancing the
      //  cursor — the operator may need to look at this deposit
      //  manually (it's a dust amount below the source-to-clarity
      //  resolution).
      if (error_out)
        *error_out = "deposit converts to 0 Clarity atomic units "
                     "(below resolution)";
      return SubmitOutcome::Failed;
    }

    //  ---- Step 4: build the transaction ----

    //  The destination must match what the attestations committed
    //  to. If a shared mint destination was configured, use it;
    //  otherwise fall back to the watcher's own keystore address
    //  (which only works for a single-watcher federation — see
    //  effectiveDestination's comment).
    const Crypto::Address destination = effectiveDestination(session);

    Wallet::BridgeMintParams p;
    p.common.chain_id = session.keystore->chainId();
    p.common.nonce = Wallet::getNonce(
                         clarity,
                         session.address_bech32m)
                         .value_or(0);
    p.common.fee = 100000; // minimum fee; the executor charges it

    p.source_chain_id = deposit.source_chain_id;
    p.source_tx_hash = deposit.source_tx_hash;
    p.source_output_index = deposit.source_output_index;
    p.destination = destination;
    p.amount = clarity_amount;
    p.signature_block = attestation_block;

    Wallet::WalletStatus build_st;
    auto tx = Wallet::buildBridgeMint(session.address.value(), p, &build_st);
    if (!tx.has_value())
    {
      if (error_out)
        *error_out = "buildBridgeMint failed: " +
                     (build_st.detail.empty()
                          ? Wallet::walletErrorMessage(build_st.code)
                          : build_st.detail);
      return SubmitOutcome::Failed;
    }

    //  ---- Step 5: sign the transaction ----

    Wallet::WalletStatus sign_st;
    auto signing_hash = Wallet::signTransaction(
        *tx, *session.signer, Wallet::clrtyPath(0, 0, 0), &sign_st);
    if (!signing_hash.has_value())
    {
      if (error_out)
        *error_out = "signTransaction failed: " +
                     (sign_st.detail.empty()
                          ? Wallet::walletErrorMessage(sign_st.code)
                          : sign_st.detail);
      return SubmitOutcome::Failed;
    }

    //  ---- Step 6: submit ----

    const std::string hex = transactionToHex(*tx);

    std::string submit_err;
    auto txid = Wallet::sendRawTransaction(clarity, hex, &submit_err);
    if (!txid.has_value())
    {
      if (error_out)
        *error_out = "sendRawTransaction failed: " + submit_err;
      return SubmitOutcome::Failed;
    }

    //  ---- Success ----

    parseTxidInto(*txid, clarity_tx_hash);

    std::cerr << "[" << rt.chain_short_name() << "] submitted BridgeMint "
              << "for deposit " << deposit.source_tx_hash.toString().substr(0, 16)
              << "..." << deposit.source_output_index
              << " -> " << *txid << "\n";

    return SubmitOutcome::Submitted;
  }

  //  ===========================================================================
  //  SubmitAttestation
  //
  //  The attestation signature is produced by the same Signer that
  //  signs the outer transaction. The consensus key is assumed to
  //  equal the keystore's signing key for this deployment; the
  //  key never leaves the Signer abstraction.
  //  ===========================================================================

  AttestOutcome SubmitAttestation(
      WatcherSession &session,
      ChainRuntime &rt,
      const ObservedDeposit &deposit,
      Crypto::Hash *attest_tx_hash,
      std::string *error_out)
  {
    if (attest_tx_hash)
      attest_tx_hash->data.fill(0);

    if (!session.hasKeystore() || !session.signer)
    {
      if (error_out)
        *error_out = "no keystore open; cannot sign attestation";
      return AttestOutcome::NotAWriter;
    }
    if (!session.clarity_rpc)
    {
      if (error_out)
        *error_out = "no Clarity RPC client";
      return AttestOutcome::Failed;
    }
    if (!rt.adapter)
    {
      if (error_out)
        *error_out = "chain adapter is null";
      return AttestOutcome::Failed;
    }
    if (session.watcher_id == 0)
    {
      if (error_out)
        *error_out = "watcher_id is unresolved; cannot determine "
                     "active-set position";
      return AttestOutcome::NotAWriter;
    }

    Wallet::RpcClient &clarity = *session.clarity_rpc;

    //  ---- Step 1: deposit already minted? ----

    bool is_consumed = false;
    std::string consumed_err;
    auto mint_height = Wallet::getBridgeConsumed(
        clarity,
        deposit.source_chain_id,
        deposit.source_tx_hash,
        deposit.source_output_index,
        &is_consumed,
        &consumed_err);

    if (!mint_height.has_value() && !consumed_err.empty())
    {
      if (error_out)
        *error_out = "getBridgeConsumed failed: " + consumed_err;
      return AttestOutcome::Failed;
    }
    if (is_consumed)
      return AttestOutcome::AlreadyConsumed;

    //  ---- Step 2: resolve own position in the active set ----

    std::string set_err;
    auto self = findSelfInActiveSet(
        clarity, deposit.source_chain_id, session.watcher_id, &set_err);
    if (!self.has_value())
    {
      if (!set_err.empty())
      {
        if (error_out)
          *error_out = set_err;
        return AttestOutcome::Failed;
      }
      //  Not in the set. Not an error — this watcher just isn't
      //  active for this chain right now.
      return AttestOutcome::NotAWriter;
    }
    const uint16_t signer_index = self->first;

    //  ---- Step 3: already attested? ----

    {
      std::string lookup_err;
      auto res = Wallet::getBridgeAttestations(
          clarity,
          deposit.source_chain_id,
          deposit.source_tx_hash,
          deposit.source_output_index,
          &lookup_err);

      if (res.has_value() && res->is_object() &&
          res->contains("attestations") &&
          (*res)["attestations"].is_array())
      {
        for (const auto &a : (*res)["attestations"])
        {
          if (!a.is_object())
            continue;
          if (!a.contains("signer_index"))
            continue;
          if (!a["signer_index"].is_string())
            continue;
          auto v = parseHexU64(a["signer_index"].get<std::string>());
          if (v.has_value() && *v == signer_index)
            return AttestOutcome::AlreadyAttested;
        }
      }
    }

    //  ---- Step 4: convert amount ----

    uint64_t clarity_amount = 0;
    try
    {
      clarity_amount = rt.adapter->to_clarity_atomic(
          deposit.amount_source_atomic,
          GlobalConfig::DECIMALS);
    }
    catch (const std::exception &e)
    {
      if (error_out)
        *error_out = std::string("to_clarity_atomic failed: ") + e.what();
      return AttestOutcome::Failed;
    }

    if (clarity_amount == 0)
    {
      if (error_out)
        *error_out = "deposit converts to 0 Clarity atomic units "
                     "(below resolution)";
      return AttestOutcome::Failed;
    }

    //  ---- Step 5: compute the canonical mint signing hash ----
    //
    //  The destination must match what every other watcher in
    //  the federation is attesting to. See effectiveDestination's
    //  comment on why: with per-watcher destinations, the
    //  executor rejects the second attestation as a conflict
    //  and no mint ever assembles.
    const Crypto::Address destination = effectiveDestination(session);

    const auto message = Bridge::Signing::EncodeBridgeMintMessage(
        deposit.source_chain_id,
        deposit.source_tx_hash,
        deposit.source_output_index,
        destination,
        clarity_amount);

    const Crypto::Hash attest_hash =
        Bridge::Signing::SigningHash("bmin", message.data(), message.size());
    if (attest_hash.isNull())
    {
      if (error_out)
        *error_out = "SigningHash returned null";
      return AttestOutcome::Failed;
    }

    //  ---- Step 6: sign the attestation hash ----
    //
    //  Two signing paths:
    //
    //    (a) session.consensus_key is set (--consensus-key-file):
    //        use it directly. This is the validator's registered
    //        consensus key — the same one validatorKeyAtHeight
    //        resolves on the executor side.
    //
    //    (b) session.consensus_key is not set: fall back to the
    //        keystore's clrtyPath(0, 0, 0). This only works if
    //        the validator registered with that key.
    //
    //  If neither produces a signature that verifies, the
    //  attestation tx will be accepted by the mempool (the tx
    //  signature is valid) but rejected by the executor.

    std::optional<Crypto::Signature> signature;

    if (session.consensus_key.has_value())
    {
      std::cerr << "[attest-bridge] signing with consensus_key "
                << "(from --consensus-key-file)\n";
      signature = Crypto::sign(attest_hash, *session.consensus_key);
      if (!signature.has_value())
      {
        if (error_out)
          *error_out = "Crypto::sign failed with consensus_key";
        return AttestOutcome::Failed;
      }
    }
    else
    {
      std::cerr << "[attest-bridge] no consensus_key; "
                << "using keystore's clrtyPath(0,0,0)\n";

      Wallet::WalletStatus sig_st;
      auto sig_opt = session.signer->signAtPath(
          Wallet::clrtyPath(0, 0, 0), attest_hash, &sig_st);
      if (!sig_opt.has_value())
      {
        if (error_out)
          *error_out = "signer->signAtPath failed: " +
                       (sig_st.detail.empty()
                            ? Wallet::walletErrorMessage(sig_st.code)
                            : sig_st.detail);
        return AttestOutcome::Failed;
      }
      signature = sig_opt;
    }

    std::cerr << "[attest-bridge] signer_index=" << signer_index
              << " chain=0x" << std::hex << deposit.source_chain_id << std::dec
              << " tx_hash=" << deposit.source_tx_hash.toString().substr(0, 16)
              << " out_idx=" << deposit.source_output_index
              << " amount=" << clarity_amount << "\n";
    std::cerr << "[attest-bridge] hash=" << attest_hash.toString() << "\n";
    std::cerr << "[attest-bridge] sig (first 16B): ";
    for (int i = 0; i < 16; ++i)
      std::cerr << std::hex << (int)signature->data[i];
    std::cerr << std::dec << "\n";

    //  ---- Step 8: build the BridgeAttest transaction ----

    Wallet::BridgeAttestParams p;
    p.common.chain_id = session.keystore->chainId();
    p.common.nonce = Wallet::getNonce(
                         clarity, session.address_bech32m)
                         .value_or(0);
    p.common.fee = 100000; // minimum; same convention as SubmitDeposit
    p.source_chain_id = deposit.source_chain_id;
    p.source_tx_hash = deposit.source_tx_hash;
    p.source_output_index = deposit.source_output_index;
    p.destination = destination;
    p.amount = clarity_amount;
    p.signer_index = signer_index;
    p.signature = *signature;

    Wallet::WalletStatus build_st;
    auto tx = Wallet::buildBridgeAttest(
        session.address.value(), p, &build_st);
    if (!tx.has_value())
    {
      if (error_out)
        *error_out = "buildBridgeAttest failed: " +
                     (build_st.detail.empty()
                          ? Wallet::walletErrorMessage(build_st.code)
                          : build_st.detail);
      return AttestOutcome::Failed;
    }

    //  ---- Step 9: sign the outer tx ----

    Wallet::WalletStatus sign_st;
    auto signing_hash = Wallet::signTransaction(
        *tx, *session.signer, Wallet::clrtyPath(0, 0, 0), &sign_st);
    if (!signing_hash.has_value())
    {
      if (error_out)
        *error_out = "signTransaction failed: " +
                     (sign_st.detail.empty()
                          ? Wallet::walletErrorMessage(sign_st.code)
                          : sign_st.detail);
      return AttestOutcome::Failed;
    }

    //  ---- Step 10: submit ----

    const std::string hex = transactionToHex(*tx);

    std::string submit_err;
    auto txid = Wallet::sendRawTransaction(clarity, hex, &submit_err);
    if (!txid.has_value())
    {
      if (error_out)
        *error_out = "sendRawTransaction failed: " + submit_err;
      return AttestOutcome::Failed;
    }

    parseTxidInto(*txid, attest_tx_hash);

    std::cerr << "[" << rt.chain_short_name() << "] submitted BridgeAttest "
              << "for deposit "
              << deposit.source_tx_hash.toString().substr(0, 16)
              << "..." << deposit.source_output_index
              << " -> " << *txid << "\n";

    return AttestOutcome::Submitted;
  }

  //  ===========================================================================
  //  AssembleMintBlock
  //  ===========================================================================

  AssembleOutcome AssembleMintBlock(
      Wallet::RpcClient &clarity_rpc,
      Wallet::Network network,
      uint64_t source_chain_id,
      const ObservedDeposit &deposit,
      size_t quorum,
      std::vector<uint8_t> *block_out,
      std::string *error_out)
  {
    if (block_out)
      block_out->clear();

    if (quorum == 0)
    {
      if (error_out)
        *error_out = "quorum is zero";
      return AssembleOutcome::StateError;
    }

    //  ---- Step 1: read attestations from chain ----

    std::string err;
    auto res = Wallet::getBridgeAttestations(
        clarity_rpc,
        source_chain_id,
        deposit.source_tx_hash,
        deposit.source_output_index,
        &err);

    if (!res.has_value())
    {
      if (error_out)
        *error_out = "getBridgeAttestations failed: " + err;
      return AssembleOutcome::RpcError;
    }
    if (!res->is_object() || !res->contains("attestations") ||
        !(*res)["attestations"].is_array())
    {
      if (error_out)
        *error_out = "getBridgeAttestations returned an unexpected shape";
      return AssembleOutcome::StateError;
    }

    const auto &arr = (*res)["attestations"];
    if (arr.size() < quorum)
    {
      //  Not an error; wait for peers.
      return AssembleOutcome::NotYetQuorum;
    }

    //  ---- Step 2: parse and check agreement ----

    //  All attestations must agree on (destination, amount) —
    //  same invariant executeBridgeAttest enforces when recording.
    //  We check it again here because chain state can be
    //  replayed, and because we want a clear "federation split"
    //  signal rather than a downstream "invalid block" rejection
    //  at submit time.
    bool have_first = false;
    Crypto::Address first_destination;
    uint64_t first_amount = 0;

    std::vector<uint8_t> entries;
    entries.reserve(arr.size() * 66);

    size_t consumed = 0;
    for (const auto &a : arr)
    {
      if (!a.is_object())
        continue;
      if (!a.contains("signer_index") || !a["signer_index"].is_string())
        continue;
      if (!a.contains("destination") || !a["destination"].is_string())
        continue;
      if (!a.contains("amount") || !a["amount"].is_string())
        continue;
      if (!a.contains("signature") || !a["signature"].is_string())
        continue;

      auto si = parseHexU64(a["signer_index"].get<std::string>());
      auto amt = parseHexU64(a["amount"].get<std::string>());
      if (!si.has_value() || *si > 0xFFFF || !amt.has_value())
      {
        if (error_out)
          *error_out = "attestation has malformed numeric fields";
        return AssembleOutcome::StateError;
      }

      //  Destination: the RPC returns bech32m, but we need the
      //  raw bytes for the canonical message. Decode with the
      //  same codec the wallet uses.
      auto dest = Wallet::decodeAddress(
          a["destination"].get<std::string>(), network);
      if (!dest.has_value())
      {
        if (error_out)
          *error_out = "attestation has undecodable destination: " +
                       a["destination"].get<std::string>();
        return AssembleOutcome::StateError;
      }

      //  Signature: 64 raw bytes.
      uint8_t sig_bytes[64];
      if (!parseHexBytes(a["signature"].get<std::string>(), sig_bytes, 64))
      {
        if (error_out)
          *error_out = "attestation signature has invalid length or "
                       "non-hex characters";
        return AssembleOutcome::StateError;
      }

      if (!have_first)
      {
        have_first = true;
        first_destination = *dest;
        first_amount = *amt;
      }
      else if (first_destination != *dest || first_amount != *amt)
      {
        //  Federation split. This shouldn't happen — the
        //  executor rejects the second one when it's recorded —
        //  but if it does, refuse to assemble.
        if (error_out)
          *error_out = "attestations disagree on (destination, amount) "
                       "for this deposit";
        return AssembleOutcome::Conflicting;
      }

      //  Emit one entry: [2] signer_index LE || [64] signature.
      const uint16_t si16 = static_cast<uint16_t>(*si);
      entries.push_back(uint8_t(si16));
      entries.push_back(uint8_t(si16 >> 8));
      entries.insert(entries.end(), sig_bytes, sig_bytes + 64);

      ++consumed;
    }

    if (consumed < quorum)
    {
      if (error_out)
        *error_out = "after parsing, fewer than quorum attestations remain";
      return AssembleOutcome::StateError;
    }

    //  ---- Step 3: prepend count prefix ----

    std::vector<uint8_t> block;
    block.reserve(2 + entries.size());

    const uint16_t count = static_cast<uint16_t>(consumed);
    block.push_back(uint8_t(count));
    block.push_back(uint8_t(count >> 8));
    block.insert(block.end(), entries.begin(), entries.end());

    if (block_out)
      *block_out = std::move(block);

    return AssembleOutcome::Ok;
  }
} // namespace Bridge::Submission