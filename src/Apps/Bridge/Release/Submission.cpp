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

    //  Resolve this daemon's position in the sorted active
    //  validator set. Returns nullopt if the daemon is not
    //  currently an active validator (its validator_id is absent
    //  from the set, or the RPC failed). When error_out is
    //  populated, the caller should treat the failure as an RPC
    //  error; when it is empty, the daemon simply isn't in the
    //  set at the current tip.
    //
    //  Under the validator-is-watcher model this is the only set
    //  there is: one global active validator set, used for every
    //  source chain's attestations. The `source_chain_id` argument
    //  is retained for logging/attribution only — it does not
    //  scope the lookup. The set returned by getActiveSet is
    //  sorted ascending by the RPC handler
    //  (method_getActiveSet), which is the order the executor's
    //  verifyActiveValidatorSignatures indexes into. We sort again
    //  here defensively: the cost is one vector copy, and it
    //  removes a class of bug where an RPC handler returns unsorted
    //  ids and the daemon silently signs with the wrong index.
    std::optional<std::pair<uint16_t, Id>> findSelfInActiveSet(
        Wallet::RpcClient &clarity_rpc,
        uint64_t /*source_chain_id*/,
        uint64_t validator_id,
        std::string *error_out)
    {
      std::string err;
      auto res = Wallet::getActiveSet(clarity_rpc, &err);

      if (!res.has_value())
      {
        if (error_out)
          *error_out = "getActiveSet failed: " + err;
        return std::nullopt;
      }
      if (!res->is_object() || !res->contains("ids") ||
          !(*res)["ids"].is_array())
      {
        if (error_out)
          *error_out = "getActiveSet returned an unexpected shape";
        return std::nullopt;
      }

      std::vector<Id> ids;
      ids.reserve((*res)["ids"].size());
      for (const auto &entry : (*res)["ids"])
      {
        if (!entry.is_string())
          continue;
        auto v = parseHexU64(entry.get<std::string>());
        if (!v.has_value())
          continue;
        ids.push_back(static_cast<Id>(*v));
      }

      std::sort(ids.begin(), ids.end());

      for (size_t i = 0; i < ids.size(); ++i)
      {
        if (ids[i] == validator_id)
          return std::make_pair(static_cast<uint16_t>(i), ids[i]);
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
    //        flag): use it. All validators in the federation must
    //        use the same address, otherwise the executor
    //        rejects the second attestation with "conflicting
    //        attestation." This is a test-only shortcut until
    //        the deposit format carries the destination
    //        on-chain.
    //
    //    (b) session.mint_destination is not set: use the
    //        daemon's own keystore address. This only works for
    //        a single-validator federation; with two or more
    //        validators, each signs a different destination and
    //        the mint never assembles.
    //
    //  A production deployment needs (c): the destination
    //  embedded in the source-chain deposit, read by every
    //  validator from chain data. That's a deposit-format change
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
      clarity_amount = deposit.amount_source_atomic;
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
  //  The attestation signature is produced by the consensus key if
  //  one was loaded (--consensus-key-file), otherwise by the
  //  keystore's fallback key at clrtyPath(0, 0, 0). The consensus
  //  key path is the correct one under the validator-is-watcher
  //  model: the executor resolves signer_index against the active
  //  validator set and looks up each validator's consensus key at
  //  the attestation height (validatorKeyAtHeight). Falling back
  //  to the keystore key only works if that key is the validator's
  //  registered consensus key.
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
    if (session.validator_id == 0)
    {
      if (error_out)
        *error_out = "validator_id is unresolved; cannot determine "
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
        clarity, deposit.source_chain_id, session.validator_id, &set_err);
    if (!self.has_value())
    {
      if (!set_err.empty())
      {
        if (error_out)
          *error_out = set_err;
        return AttestOutcome::Failed;
      }
      //  Not in the set. Not an error — this validator just isn't
      //  active at the current tip.
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
      clarity_amount = deposit.amount_source_atomic;
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
    //  The destination must match what every other validator in
    //  the federation is attesting to. See effectiveDestination's
    //  comment on why: with per-validator destinations, the
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

    std::optional<Crypto::Signature> signature;

    if (session.consensus_key.has_value())
    {
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

    //  ---- Step 7: build the BridgeAttest transaction ----

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

    //  ---- Step 8: sign the outer tx ----

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

    //  ---- Step 9: submit ----

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
      Wallet::Network /*network*/,
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
      return AssembleOutcome::NotYetQuorum;

    //  ---- Step 2: parse and check agreement ----
    //
    //  Compare destination as the bech32m STRING the RPC returned.
    //  Do not decode to Crypto::Address — the destination's raw
    //  32 bytes already live in the attestation signature's
    //  canonical message, and re-decoding through the wallet's
    //  address codec introduces a network/HRP dependency that has
    //  nothing to do with whether the attestations agree.
    bool have_first = false;
    std::string first_destination;
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

      const std::string dest = a["destination"].get<std::string>();

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
        first_destination = dest;
        first_amount = *amt;
      }
      else if (first_destination != dest || first_amount != *amt)
      {
        if (error_out)
          *error_out = "attestations disagree on (destination, amount) "
                       "for this deposit";
        return AssembleOutcome::Conflicting;
      }

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

  //  ===========================================================================
  //  SubmitAckAttestation
  //
  //  The withdrawal-side counterpart of SubmitAttestation.
  //  Everything is identical except:
  //    - the payload carries only withdrawal_id, signer_index, and
  //      the signature (no destination/amount — those live in the
  //      BridgeWithdrawal record);
  //    - the signing domain is "back", over LE64(withdrawal_id);
  //    - the replay/consumed guard is "is the withdrawal already
  //      released?" rather than "is the deposit already minted?".
  //  ===========================================================================

  AttestOutcome SubmitAckAttestation(
      WatcherSession &session,
      ChainRuntime &rt,
      uint64_t withdrawal_id,
      Crypto::Hash *attest_tx_hash,
      std::string *error_out)
  {
    if (attest_tx_hash)
      attest_tx_hash->data.fill(0);

    if (!session.hasKeystore() || !session.signer)
    {
      if (error_out)
        *error_out = "no keystore open; cannot sign ack attestation";
      return AttestOutcome::NotAWriter;
    }
    if (!session.clarity_rpc)
    {
      if (error_out)
        *error_out = "no Clarity RPC client";
      return AttestOutcome::Failed;
    }
    if (session.validator_id == 0)
    {
      if (error_out)
        *error_out = "validator_id is unresolved; cannot determine "
                     "active-set position";
      return AttestOutcome::NotAWriter;
    }

    Wallet::RpcClient &clarity = *session.clarity_rpc;

    //  ---- Step 1: fetch the withdrawal record ----

    bool not_found = false;
    std::string fetch_err;
    auto w_json = Wallet::getBridgeWithdrawal(
        clarity, withdrawal_id, &not_found, &fetch_err);

    if (not_found)
    {
      if (error_out)
        *error_out = "withdrawal " + std::to_string(withdrawal_id) +
                     " does not exist";
      return AttestOutcome::AlreadyConsumed;
    }
    if (!w_json.has_value())
    {
      if (error_out)
        *error_out = "getBridgeWithdrawal failed: " + fetch_err;
      return AttestOutcome::Failed;
    }
    if (!w_json->is_object())
    {
      if (error_out)
        *error_out = "withdrawal response is not an object";
      return AttestOutcome::Failed;
    }

    const auto &wobj = *w_json;

    if (wobj.contains("is_released") && wobj["is_released"].is_boolean() &&
        wobj["is_released"].get<bool>())
    {
      return AttestOutcome::AlreadyConsumed;
    }

    if (!wobj.contains("source_chain_id") ||
        !wobj["source_chain_id"].is_string())
    {
      if (error_out)
        *error_out = "withdrawal record missing 'source_chain_id'";
      return AttestOutcome::Failed;
    }
    auto scid_opt = parseHexU64(wobj["source_chain_id"].get<std::string>());
    if (!scid_opt.has_value())
    {
      if (error_out)
        *error_out = "'source_chain_id' is not valid hex";
      return AttestOutcome::Failed;
    }
    const uint64_t source_chain_id = *scid_opt;

    //  ---- Step 2: resolve own position in the active set ----

    std::string set_err;
    auto self = findSelfInActiveSet(
        clarity, source_chain_id, session.validator_id, &set_err);
    if (!self.has_value())
    {
      if (!set_err.empty())
      {
        if (error_out)
          *error_out = set_err;
        return AttestOutcome::Failed;
      }
      return AttestOutcome::NotAWriter;
    }
    const uint16_t signer_index = self->first;

    //  ---- Step 3: already attested? ----

    {
      std::string lookup_err;
      auto res = Wallet::getBridgeAckAttestations(
          clarity, withdrawal_id, &lookup_err);

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

    //  ---- Step 4: compute the canonical ack signing hash ----

    const auto message = Bridge::Signing::EncodeBridgeAckMessage(withdrawal_id);
    const Crypto::Hash attest_hash =
        Bridge::Signing::SigningHash("back", message.data(), message.size());
    if (attest_hash.isNull())
    {
      if (error_out)
        *error_out = "SigningHash returned null";
      return AttestOutcome::Failed;
    }

    //  ---- Step 5: sign the attestation hash ----

    std::optional<Crypto::Signature> signature;

    if (session.consensus_key.has_value())
    {
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

    //  ---- Step 6: build the BridgeAckAttest transaction ----

    Wallet::BridgeAckAttestParams p;
    p.common.chain_id = session.keystore->chainId();
    p.common.nonce = Wallet::getNonce(
                         clarity, session.address_bech32m)
                         .value_or(0);
    p.common.fee = 100000;
    p.withdrawal_id = withdrawal_id;
    p.signer_index = signer_index;
    p.signature = *signature;

    Wallet::WalletStatus build_st;
    auto tx = Wallet::buildBridgeAckAttest(
        session.address.value(), p, &build_st);
    if (!tx.has_value())
    {
      if (error_out)
        *error_out = "buildBridgeAckAttest failed: " +
                     (build_st.detail.empty()
                          ? Wallet::walletErrorMessage(build_st.code)
                          : build_st.detail);
      return AttestOutcome::Failed;
    }

    //  ---- Step 7: sign the outer tx ----

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

    //  ---- Step 8: submit ----

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

    std::cerr << "[" << rt.chain_short_name()
              << "] submitted BridgeAckAttest for withdrawal "
              << withdrawal_id << " -> " << *txid << "\n";

    return AttestOutcome::Submitted;
  }

  //  ===========================================================================
  //  AssembleAckBlock
  //
  //  Mirror of AssembleMintBlock. Two differences:
  //    - the attestations carry no (destination, amount) to check
  //      agreement on; there is only the withdrawal_id, so any
  //      quorum-sized set of distinct signer_indices is valid;
  //    - the withdrawal may already have been released (by a peer
  //      racing us), in which case we return AlreadyReleased rather
  //      than pretending a block exists.
  //  ===========================================================================

  AssembleAckOutcome AssembleAckBlock(
      Wallet::RpcClient &clarity_rpc,
      uint64_t withdrawal_id,
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
      return AssembleAckOutcome::StateError;
    }

    //  ---- Step 0: fetch the withdrawal (to confirm not-yet-released) ----

    bool not_found = false;
    std::string fetch_err;
    auto w_json = Wallet::getBridgeWithdrawal(
        clarity_rpc, withdrawal_id, &not_found, &fetch_err);

    if (not_found)
    {
      return AssembleAckOutcome::AlreadyReleased;
    }
    if (!w_json.has_value())
    {
      if (error_out)
        *error_out = "getBridgeWithdrawal failed: " + fetch_err;
      return AssembleAckOutcome::RpcError;
    }
    if (!w_json->is_object())
    {
      if (error_out)
        *error_out = "withdrawal response is not an object";
      return AssembleAckOutcome::StateError;
    }

    if ((*w_json).contains("is_released") &&
        (*w_json)["is_released"].is_boolean() &&
        (*w_json)["is_released"].get<bool>())
    {
      return AssembleAckOutcome::AlreadyReleased;
    }

    //  ---- Step 1: read ack attestations from chain ----

    std::string err;
    auto res = Wallet::getBridgeAckAttestations(
        clarity_rpc, withdrawal_id, &err);

    if (!res.has_value())
    {
      if (error_out)
        *error_out = "getBridgeAckAttestations failed: " + err;
      return AssembleAckOutcome::RpcError;
    }
    if (!res->is_object() || !res->contains("attestations") ||
        !(*res)["attestations"].is_array())
    {
      if (error_out)
        *error_out = "getBridgeAckAttestations returned an unexpected shape";
      return AssembleAckOutcome::StateError;
    }

    const auto &arr = (*res)["attestations"];
    if (arr.size() < quorum)
      return AssembleAckOutcome::NotYetQuorum;

    //  ---- Step 2: parse the attestations into [2] idx || [64] sig ----

    std::vector<uint8_t> entries;
    entries.reserve(arr.size() * 66);

    std::vector<uint16_t> seen_indices;
    seen_indices.reserve(arr.size());

    size_t consumed = 0;
    for (const auto &a : arr)
    {
      if (!a.is_object())
        continue;
      if (!a.contains("signer_index") || !a["signer_index"].is_string())
        continue;
      if (!a.contains("signature") || !a["signature"].is_string())
        continue;

      auto si = parseHexU64(a["signer_index"].get<std::string>());
      if (!si.has_value() || *si > 0xFFFF)
      {
        if (error_out)
          *error_out = "ack attestation has malformed signer_index";
        return AssembleAckOutcome::StateError;
      }
      const uint16_t si16 = static_cast<uint16_t>(*si);

      if (std::find(seen_indices.begin(), seen_indices.end(), si16) !=
          seen_indices.end())
      {
        if (error_out)
          *error_out = "duplicate signer_index " +
                       std::to_string(si16) + " in ack attestations";
        return AssembleAckOutcome::StateError;
      }
      seen_indices.push_back(si16);

      uint8_t sig_bytes[64];
      if (!parseHexBytes(a["signature"].get<std::string>(), sig_bytes, 64))
      {
        if (error_out)
          *error_out = "ack attestation signature has invalid length "
                       "or non-hex characters";
        return AssembleAckOutcome::StateError;
      }

      entries.push_back(uint8_t(si16));
      entries.push_back(uint8_t(si16 >> 8));
      entries.insert(entries.end(), sig_bytes, sig_bytes + 64);

      ++consumed;
    }

    if (consumed < quorum)
    {
      if (error_out)
        *error_out = "after parsing, fewer than quorum ack attestations "
                     "remain";
      return AssembleAckOutcome::StateError;
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

    return AssembleAckOutcome::Ok;
  }

  //  ===========================================================================
  //  SubmitAckWithdrawal
  //  ===========================================================================

  SubmitOutcome SubmitAckWithdrawal(
      WatcherSession &session,
      ChainRuntime &rt,
      uint64_t withdrawal_id,
      const Crypto::Hash &release_tx_hash,
      uint64_t release_height,
      const std::vector<uint8_t> &ack_block,
      Crypto::Hash *clarity_tx_hash,
      std::string *error_out)
  {
    if (clarity_tx_hash)
      clarity_tx_hash->data.fill(0);

    if (ack_block.size() < 2)
    {
      if (error_out)
        *error_out = "ack_block is too short (needs at least a 2-byte "
                     "count prefix)";
      return SubmitOutcome::Failed;
    }
    const uint16_t ack_count =
        uint16_t(ack_block[0]) | (uint16_t(ack_block[1]) << 8);
    if (ack_count == 0)
    {
      if (error_out)
        *error_out = "ack_block has zero signatures";
      return SubmitOutcome::Failed;
    }
    if (ack_block.size() != 2 + static_cast<size_t>(ack_count) * 66)
    {
      if (error_out)
        *error_out = "ack_block length does not match its declared count";
      return SubmitOutcome::Failed;
    }

    if (release_tx_hash.isNull())
    {
      if (error_out)
        *error_out = "release_tx_hash is null";
      return SubmitOutcome::Failed;
    }
    if (release_height == 0)
    {
      if (error_out)
        *error_out = "release_height is zero";
      return SubmitOutcome::Failed;
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

    Wallet::RpcClient &clarity = *session.clarity_rpc;

    bool not_found = false;
    std::string fetch_err;
    auto w_json = Wallet::getBridgeWithdrawal(
        clarity, withdrawal_id, &not_found, &fetch_err);

    if (w_json.has_value() && w_json->is_object() &&
        (*w_json).contains("is_released") &&
        (*w_json)["is_released"].is_boolean() &&
        (*w_json)["is_released"].get<bool>())
    {
      return SubmitOutcome::AlreadyConsumed;
    }

    //  ---- Step 1: build the transaction ----

    Wallet::BridgeAckWithdrawalParams p;
    p.common.chain_id = session.keystore->chainId();
    p.common.nonce = Wallet::getNonce(
                         clarity, session.address_bech32m)
                         .value_or(0);
    p.common.fee = 100000;

    p.withdrawal_id = withdrawal_id;
    p.release_tx_hash = release_tx_hash;
    p.release_height = release_height;
    p.signature_block = ack_block;

    Wallet::WalletStatus build_st;
    auto tx = Wallet::buildBridgeAckWithdrawal(
        session.address.value(), p, &build_st);
    if (!tx.has_value())
    {
      if (error_out)
        *error_out = "buildBridgeAckWithdrawal failed: " +
                     (build_st.detail.empty()
                          ? Wallet::walletErrorMessage(build_st.code)
                          : build_st.detail);
      return SubmitOutcome::Failed;
    }

    //  ---- Step 2: sign the transaction ----

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

    //  ---- Step 3: submit ----

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

    std::cerr << "[" << rt.chain_short_name()
              << "] submitted BridgeAckWithdrawal for withdrawal "
              << withdrawal_id << " (release=" << release_tx_hash.toString().substr(0, 16)
              << "... @ height " << release_height << ") -> " << *txid << "\n";

    return SubmitOutcome::Submitted;
  }
} // namespace Bridge::Submission