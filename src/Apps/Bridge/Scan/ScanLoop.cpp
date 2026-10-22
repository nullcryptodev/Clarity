// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Scan/ScanLoop.h"

#include "Adapters/ChainAdapter.h"
#include "Release/ReleaseTracker.h"
#include "Release/Submission.h"
#include "Session/Session.h"

#include "Core/BridgeTypes.h"

#include "Crypto/Helpers.h"

#include "GlobalConfig.h"

#include "Wallet/RpcClient.h"

#include <chrono>
#include <iostream>
#include <thread>

namespace Bridge
{
  namespace Scan
  {
    namespace
    {
      std::string depositKey(const Crypto::Hash &h, uint32_t index)
      {
        static const char HEX[] = "0123456789abcdef";
        std::string out;
        out.reserve(2 + 64 + 1 + 10);
        out.push_back('0');
        out.push_back('x');
        for (size_t i = 0; i < h.data.size(); ++i)
        {
          out.push_back(HEX[h.data[i] >> 4]);
          out.push_back(HEX[h.data[i] & 0xF]);
        }
        out.push_back(':');
        out += std::to_string(index);
        return out;
      }

      //  Compute the payment ID that ties a CCX release to its
      //  withdrawal. Blake2b("back" || LE64(withdrawal_id)) — the
      //  same preimage the ack-attestation signs. Chain-specific
      //  in the sense that only adapters with a payment-ID concept
      //  will recognise it, but computing it is a pure function of
      //  the withdrawal id, so it's safe to compute unconditionally
      //  and pass to find_existing_release. An adapter that has no
      //  equivalent concept returns nullopt and the caller falls
      //  through.
      Crypto::Hash paymentIdForWithdrawal(uint64_t withdrawal_id)
      {
        uint8_t preimage[8];
        for (int i = 0; i < 8; ++i)
          preimage[i] = uint8_t(withdrawal_id >> (i * 8));
        return Crypto::hashDomain("back", preimage, sizeof(preimage));
      }
    } // anonymous namespace

    //  ---- Deposit scan phase ----

    void runDepositScanPhase(WatcherSession *session,
                             ChainRuntime &rt,
                             const std::string &chain_name,
                             DepositMap &watched,
                             std::set<std::string> &warned_unregistered_chains,
                             const std::shared_ptr<std::atomic<bool>> &stop)
    {
      ChainStatus status;
      try
      {
        status = rt.adapter->fetch_status(*rt.rpc);
      }
      catch (const std::exception &e)
      {
        std::cerr << "[" << chain_name << "] scan: fetch_status "
                  << "failed: " << e.what() << "\n";
        return;
      }

      if (!status.reachable)
      {
        rt.connected = false;
        return;
      }
      rt.connected = true;

      if (status.current_height > rt.last_source_height)
      {
        const uint64_t from = rt.last_source_height + 1;
        const uint64_t to = status.current_height;
        size_t found = 0;

        try
        {
          rt.adapter->scan_deposits(
              *rt.rpc, from, to,
              [&](const ObservedDeposit &d)
              {
                ++found;

                const std::string key =
                    depositKey(d.source_tx_hash, d.source_output_index);

                if (watched.find(key) == watched.end())
                {
                  Crypto::Hash attest_txid;
                  std::string attest_err;
                  const auto outcome =
                      Submission::SubmitAttestation(
                          *session, rt, d, &attest_txid, &attest_err);

                  switch (outcome)
                  {
                  case Submission::AttestOutcome::Submitted:
                    std::cerr << "[" << chain_name
                              << "] scan: attested "
                              << d.source_tx_hash.toString().substr(0, 16)
                              << "..." << d.source_output_index
                              << " -> " << attest_txid.toString() << "\n";
                    watched.emplace(key, d);
                    break;

                  case Submission::AttestOutcome::AlreadyAttested:
                    watched.emplace(key, d);
                    break;

                  case Submission::AttestOutcome::AlreadyConsumed:
                    break;

                  case Submission::AttestOutcome::NotAWriter:
                    break;

                  case Submission::AttestOutcome::Failed:
                    //  If the failure is specifically "the source
                    //  chain is not registered on Clarity," that
                    //  is a permanent condition until the operator
                    //  runs `register-chain`. Log it once per chain
                    //  so the daemon log stays readable while the
                    //  operator is setting up the chain. The
                    //  deposit is NOT added to `watched` on this
                    //  path, which means the next poll re-finds
                    //  and re-attempts it. The moment the
                    //  registration confirms, the retry succeeds
                    //  and the deposit moves into `watched` as a
                    //  normal Submitted attestation.
                    if (attest_err.find("chain not registered") !=
                        std::string::npos)
                    {
                      if (warned_unregistered_chains
                              .insert(chain_name)
                              .second)
                      {
                        std::cerr
                            << "[" << chain_name
                            << "] scan: source chain is not registered "
                               "on Clarity.\n"
                            << "  Run `register-chain " << chain_name
                            << "` once to set it up. Deposits will be "
                               "attested automatically once the "
                               "registration confirms.\n";
                      }
                      break;
                    }
                    std::cerr << "[" << chain_name
                              << "] scan: attest failed for "
                              << d.source_tx_hash.toString().substr(0, 16)
                              << "..." << d.source_output_index
                              << ": " << attest_err << "\n";
                    break;
                  }
                }

                return !stop->load(std::memory_order_acquire);
              });
        }
        catch (const std::exception &e)
        {
          std::cerr << "[" << chain_name << "] scan: scan_deposits "
                    << "failed on [" << from << ", " << to << "]: "
                    << e.what() << "\n";
          return;
        }

        rt.last_source_height = to;
        std::cerr << "[" << chain_name << "] scan: processed heights "
                  << from << ".." << to
                  << ", " << found << " new deposit(s)\n";
      }

      for (auto it = watched.begin(); it != watched.end();)
      {
        const ObservedDeposit &d = it->second;

        std::string assemble_err;
        std::vector<uint8_t> block;
        const auto assemble_outcome =
            Submission::AssembleMintBlock(
                *session->clarity_rpc,
                session->currentNetwork(),
                d.source_chain_id,
                d,
                /*quorum=*/2,
                &block,
                &assemble_err);

        if (assemble_outcome == Submission::AssembleOutcome::Ok)
        {
          std::string submit_err;
          Crypto::Hash mint_txid;
          const auto submit_outcome =
              Submission::SubmitDeposit(
                  *session, rt, d, block, &mint_txid, &submit_err);

          if (submit_outcome == Submission::SubmitOutcome::Submitted)
          {
            std::cerr << "[" << chain_name << "] scan: minted "
                      << d.source_tx_hash.toString().substr(0, 16)
                      << "..." << d.source_output_index
                      << " -> " << mint_txid.toString() << "\n";
            it = watched.erase(it);
            continue;
          }
          else if (submit_outcome ==
                   Submission::SubmitOutcome::AlreadyConsumed)
          {
            it = watched.erase(it);
            continue;
          }
        }
        else if (assemble_outcome ==
                 Submission::AssembleOutcome::Conflicting)
        {
          std::cerr << "[" << chain_name
                    << "] scan: FEDERATION SPLIT on deposit "
                    << d.source_tx_hash.toString().substr(0, 16)
                    << "..." << d.source_output_index
                    << ": " << assemble_err << "\n";
        }
        else if (assemble_outcome ==
                 Submission::AssembleOutcome::StateError)
        {
          std::cerr << "[" << chain_name
                    << "] scan: assemble StateError for deposit "
                    << d.source_tx_hash.toString().substr(0, 16)
                    << "..." << d.source_output_index
                    << ": " << assemble_err << "\n";
        }
        else if (assemble_outcome ==
                 Submission::AssembleOutcome::RpcError)
        {
          std::cerr << "[" << chain_name
                    << "] scan: assemble RpcError for deposit "
                    << d.source_tx_hash.toString().substr(0, 16)
                    << "..." << d.source_output_index
                    << ": " << assemble_err << "\n";
        }

        ++it;
      }
    }

    //  Drain completed background releases. Called at the top of
    //  every withdrawal scan poll, before the phase driver runs.

    void drainCompletedReleases(const std::string &chain_name,
                                ChainRuntime &rt,
                                ReleaseTracker &tracker,
                                WithdrawalMap &tracked)
    {
      for (auto &completed : tracker.drain_completed())
      {
        auto it = tracked.find(completed.withdrawal_id);
        if (it == tracked.end())
        {
          std::cerr << "[" << chain_name
                    << "] withdrawal scan: release completed for "
                    << "untracked withdrawal " << completed.withdrawal_id
                    << "\n";
          continue;
        }

        TrackedWithdrawal &tw = it->second;

        if (completed.succeeded)
        {
          tw.release_tx_hash = completed.tx_hash;
          tw.phase = WithdrawalPhase::Released;
          tw.phase_since = std::chrono::steady_clock::now();
          std::cerr << "[" << chain_name
                    << "] withdrawal scan: release confirmed for "
                    << tw.withdrawal_id << " -> "
                    << tw.release_tx_hash.toString() << "\n";
          continue;
        }

        //  Release failed. Before retrying, check whether a peer
        //  already released this withdrawal — a failure here is
        //  often "walletd refused to build a tx because the inputs
        //  were already spent by the peer's release." Adopt the
        //  peer's hash instead of retrying and racing again.
        //
        //  The double-release check is an adapter capability, not a
        //  CCX-specific branch. An adapter that has no
        //  find-existing-release concept (Bitcoin, an EVM chain whose
        //  release is a contract call) returns nullopt from
        //  find_existing_release and we fall through to the retry
        //  path — which is correct: there's nothing to adopt, so
        //  retrying is the only option.
        if (auto existing = rt.adapter->find_existing_release(
                paymentIdForWithdrawal(completed.withdrawal_id));
            existing.has_value())
        {
          tw.release_tx_hash = *existing;
          tw.phase = WithdrawalPhase::Released;
          tw.phase_since = std::chrono::steady_clock::now();
          std::cerr << "[" << chain_name
                    << "] withdrawal scan: release FAILED but peer "
                    << "released first for " << tw.withdrawal_id
                    << " -> " << tw.release_tx_hash.toString() << "\n";
          continue;
        }

        tw.phase = WithdrawalPhase::Releasable;
        tw.phase_since = std::chrono::steady_clock::now();
        std::cerr << "[" << chain_name
                  << "] withdrawal scan: release FAILED for "
                  << tw.withdrawal_id << ": " << completed.reason
                  << " (will retry)\n";
      }
    }

    //  Withdrawal scan phase. Runs once per poll after the deposit
    //  phase has run.

    void runWithdrawalScanPhase(WatcherSession *session,
                                ChainRuntime &rt,
                                const std::string &chain_name,
                                WithdrawalMap &tracked,
                                ReleaseTracker &release_tracker,
                                const std::shared_ptr<std::atomic<bool>> &stop)
    {
      if (!session->clarity_rpc || !session->clarity_connected)
        return;

      Wallet::RpcClient &clarity = *session->clarity_rpc;

      //  ---- Step 0: drain completed releases ----
      drainCompletedReleases(chain_name, rt, release_tracker, tracked);

      //  ---- Step 1: discover new pending withdrawals ----

      {
        std::string err;
        auto res = Wallet::getPendingWithdrawals(
            clarity,
            /*from_height=*/0,
            /*limit=*/100,
            /*offset=*/0,
            &err);

        if (!res.has_value())
        {
          std::cerr << "[" << chain_name
                    << "] withdrawal scan: getPendingWithdrawals failed: "
                    << err << "\n";
          return;
        }
        if (!res->is_object() ||
            !res->contains("withdrawals") ||
            !(*res)["withdrawals"].is_array())
        {
          std::cerr << "[" << chain_name
                    << "] withdrawal scan: getPendingWithdrawals returned "
                    << "an unexpected shape\n";
          return;
        }

        for (const auto &entry : (*res)["withdrawals"])
        {
          if (!entry.is_object())
            continue;

          uint64_t scid = 0;
          if (entry.contains("source_chain_id") &&
              entry["source_chain_id"].is_string())
          {
            try
            {
              scid = std::stoull(
                  entry["source_chain_id"].get<std::string>(),
                  nullptr, 0);
            }
            catch (...)
            {
              continue;
            }
          }
          if (scid != rt.adapter->source_chain_id())
            continue;

          uint64_t wid = 0;
          if (entry.contains("withdrawal_id") &&
              entry["withdrawal_id"].is_string())
          {
            try
            {
              wid = std::stoull(
                  entry["withdrawal_id"].get<std::string>(),
                  nullptr, 0);
            }
            catch (...)
            {
              continue;
            }
          }
          if (wid == 0)
            continue;

          if (tracked.find(wid) != tracked.end())
            continue;

          TrackedWithdrawal tw;
          tw.withdrawal_id = wid;
          tw.source_chain_id = scid;
          tw.phase = WithdrawalPhase::Observed;
          tw.phase_since = std::chrono::steady_clock::now();

          if (entry.contains("amount") && entry["amount"].is_string())
          {
            try
            {
              tw.amount = std::stoull(
                  entry["amount"].get<std::string>(),
                  nullptr, 0);
            }
            catch (...)
            {
              tw.amount = 0;
            }
          }
          if (entry.contains("created_at_height") &&
              entry["created_at_height"].is_string())
          {
            try
            {
              tw.created_at_height = std::stoull(
                  entry["created_at_height"].get<std::string>(),
                  nullptr, 0);
            }
            catch (...)
            {
              tw.created_at_height = 0;
            }
          }

          //  Parse ack_quorum. The encoder emits it as a hex
          //  string (see Rpc/Encoders.cpp), but accept a JSON
          //  number too so a future encoder change doesn't
          //  silently leave tw.ack_quorum at zero (which would
          //  prevent the Acking → Acked transition forever).
          if (entry.contains("ack_quorum"))
          {
            const auto &q = entry["ack_quorum"];
            if (q.is_number_unsigned())
            {
              tw.ack_quorum = q.get<uint64_t>();
            }
            else if (q.is_string())
            {
              try
              {
                tw.ack_quorum =
                    std::stoull(q.get<std::string>(), nullptr, 0);
              }
              catch (...)
              {
                tw.ack_quorum = 0;
              }
            }
          }

          tracked.emplace(wid, std::move(tw));
        }
      }

      //  ---- Step 2: process each tracked withdrawal ----

      for (auto it = tracked.begin(); it != tracked.end();)
      {
        TrackedWithdrawal &tw = it->second;

        if (stop->load(std::memory_order_acquire))
          return;

        switch (tw.phase)
        {
        case WithdrawalPhase::Observed:
        {
          Crypto::Hash ack_txid;
          std::string err;
          const auto outcome = Submission::SubmitAckAttestation(
              *session, rt, tw.withdrawal_id, &ack_txid, &err);

          switch (outcome)
          {
          case Submission::AttestOutcome::Submitted:
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: ack-attested withdrawal "
                      << tw.withdrawal_id
                      << " -> " << ack_txid.toString() << "\n";
            tw.phase = WithdrawalPhase::Acking;
            tw.phase_since = std::chrono::steady_clock::now();
            break;

          case Submission::AttestOutcome::AlreadyAttested:
            tw.phase = WithdrawalPhase::Acking;
            tw.phase_since = std::chrono::steady_clock::now();
            break;

          case Submission::AttestOutcome::AlreadyConsumed:
            tw.phase = WithdrawalPhase::Done;
            break;

          case Submission::AttestOutcome::NotAWriter:
            break;

          case Submission::AttestOutcome::Failed:
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: ack-attest failed for "
                      << tw.withdrawal_id << ": " << err << "\n";
            break;
          }
          break;
        }

        case WithdrawalPhase::Acking:
        {
          std::string err;
          auto wd = Wallet::getBridgeWithdrawal(
              clarity, tw.withdrawal_id, nullptr, &err);
          if (!wd.has_value() || !wd->is_object())
            break;

          if ((*wd).contains("is_released") &&
              (*wd)["is_released"].is_boolean() &&
              (*wd)["is_released"].get<bool>())
          {
            tw.phase = WithdrawalPhase::Done;
            break;
          }

          auto ack_res = Wallet::getBridgeAckAttestations(
              clarity, tw.withdrawal_id, &err);
          if (!ack_res.has_value() || !ack_res->is_object())
            break;

          size_t count = 0;
          if ((*ack_res).contains("count"))
          {
            const auto &c = (*ack_res)["count"];
            if (c.is_number_unsigned())
            {
              count = static_cast<size_t>(c.get<uint64_t>());
            }
            else if (c.is_string())
            {
              try
              {
                count = static_cast<size_t>(
                    std::stoull(c.get<std::string>(), nullptr, 0));
              }
              catch (...)
              {
                count = 0;
              }
            }
          }

          if (tw.ack_quorum > 0 && count >= tw.ack_quorum)
          {
            tw.phase = WithdrawalPhase::Acked;
            tw.phase_since = std::chrono::steady_clock::now();
          }
          break;
        }

        case WithdrawalPhase::Acked:
        {
          std::string err;
          auto hdr = Wallet::getCurrentHeader(clarity, &err);
          if (!hdr.has_value())
            break;

          const uint16_t burn_finality_depth =
              rt.config.burn_finality_depth > 0
                  ? rt.config.burn_finality_depth
                  : kDefaultBurnFinalityDepth;

          const uint64_t current_height = hdr->height;
          if (current_height <
              tw.created_at_height + burn_finality_depth)
            break;

          std::string assemble_err;
          std::vector<uint8_t> block;
          const auto outcome = Submission::AssembleAckBlock(
              clarity,
              tw.withdrawal_id,
              /*quorum=*/static_cast<size_t>(tw.ack_quorum),
              &block,
              &assemble_err);

          if (outcome == Submission::AssembleAckOutcome::Ok)
          {
            tw.ack_block = std::move(block);
            tw.phase = WithdrawalPhase::Releasable;
            tw.phase_since = std::chrono::steady_clock::now();
          }
          else if (outcome ==
                   Submission::AssembleAckOutcome::AlreadyReleased)
          {
            tw.phase = WithdrawalPhase::Done;
          }
          else if (outcome ==
                   Submission::AssembleAckOutcome::NotYetQuorum)
          {
            tw.phase = WithdrawalPhase::Acking;
            tw.phase_since = std::chrono::steady_clock::now();
          }
          else if (outcome ==
                   Submission::AssembleAckOutcome::StateError)
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: assemble StateError for "
                      << tw.withdrawal_id << ": " << assemble_err << "\n";
          }
          else if (outcome ==
                   Submission::AssembleAckOutcome::RpcError)
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: assemble RpcError for "
                      << tw.withdrawal_id << ": " << assemble_err << "\n";
          }
          break;
        }

        case WithdrawalPhase::Releasable:
        {
          std::string wd_err;
          auto wd = Wallet::getBridgeWithdrawal(
              clarity, tw.withdrawal_id, nullptr, &wd_err);
          if (!wd.has_value() || !wd->is_object())
            break;

          std::vector<uint8_t> dest_blob;
          if ((*wd).contains("destination_blob") &&
              (*wd)["destination_blob"].is_string())
          {
            const std::string hex_str =
                (*wd)["destination_blob"].get<std::string>();
            std::string clean = hex_str;
            if (clean.size() >= 2 && clean[0] == '0' &&
                (clean[1] == 'x' || clean[1] == 'X'))
              clean = clean.substr(2);
            if ((clean.size() & 1) == 0)
            {
              dest_blob.reserve(clean.size() / 2);
              for (size_t i = 0; i + 1 < clean.size(); i += 2)
              {
                try
                {
                  dest_blob.push_back(static_cast<uint8_t>(
                      std::stoul(clean.substr(i, 2), nullptr, 16)));
                }
                catch (...)
                {
                  dest_blob.clear();
                  break;
                }
              }
            }
          }

          //  The destination blob's validity is an adapter
          //  property, not a length constant. CCX wants exactly
          //  64 bytes (spend ‖ view); a Bitcoin adapter wants a
          //  parseable scriptPubKey; an EVM adapter wants whatever
          //  its ABI requires. validate_destination returns false
          //  for "not a valid destination for this chain", and the
          //  scan loop skips the withdrawal either way.
          if (!rt.adapter->validate_destination(dest_blob))
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: withdrawal "
                      << tw.withdrawal_id
                      << " has an invalid destination for chain '"
                      << chain_name << "'; skipping\n";
            break;
          }

          const uint64_t amount_source_atomic = tw.amount;

          ReleaseRequest req;
          req.withdrawal_id = tw.withdrawal_id;
          req.source_chain_id = tw.source_chain_id;
          req.destination_blob = dest_blob;

          //  Also read the base58 string from the record.
          if ((*wd).contains("destination_address") &&
              (*wd)["destination_address"].is_string())
          {
            req.destination_address =
                (*wd)["destination_address"].get<std::string>();
          }

          if (req.destination_address.empty())
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: withdrawal "
                      << tw.withdrawal_id
                      << " has no destination_address on the record; "
                      << "skipping\n";
            break;
          }

          //  Idempotency: has a peer already released this withdrawal?
          //  If so, adopt its hash and skip the launch. This closes the
          //  double-release window from handover §7.5 (both watchers race
          //  past the quorum check and both call walletd's sendTransaction).
          //
          //  The check is an adapter capability. A CCX adapter's
          //  implementation scans its wallet history for a release
          //  with the matching payment ID. An adapter with no such
          //  concept returns nullopt, and we fall through to the
          //  launch — the adapter's submit_release is then the only
          //  defence against a double release, which is correct for
          //  a chain where the source of truth is the release tx
          //  itself, not a payment ID.
          if (auto existing = rt.adapter->find_existing_release(
                  paymentIdForWithdrawal(tw.withdrawal_id));
              existing.has_value())
          {
            tw.release_tx_hash = *existing;
            tw.phase = WithdrawalPhase::Released;
            tw.phase_since = std::chrono::steady_clock::now();
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: release already exists for "
                      << tw.withdrawal_id << " -> "
                      << tw.release_tx_hash.toString() << "\n";
            break;
          }

          if (release_tracker.launch(
                  rt, req, amount_source_atomic, tw.ack_block))
          {
            tw.phase = WithdrawalPhase::Releasing;
            tw.phase_since = std::chrono::steady_clock::now();
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: launched release for withdrawal "
                      << tw.withdrawal_id << "\n";
          }
          break;
        }

        case WithdrawalPhase::Releasing:
        {
          //  Passive: drain step at the top of the next poll
          //  transitions us out of Releasing.
          break;
        }

        case WithdrawalPhase::Released:
        {
          //  Release confirmed on CCX. Fetch the block height,
          //  then record the release on Clarity via a
          //  BridgeAckWithdrawal.
          //
          //  We can only do this once the release has a block
          //  height; if the daemon still says the tx isn't in a
          //  block (mempool, or the wallet RPC returned before
          //  the tx was mined — which it shouldn't, since
          //  `transfer` blocks until confirmed, but the daemon
          //  may be lagging behind the wallet's view of the
          //  network), retry next poll.
          if (tw.release_height == 0)
          {
            auto height = rt.adapter->fetch_release_height(
                *rt.rpc, tw.release_tx_hash);
            if (!height.has_value())
            {
              //  Not yet visible in a block. Retry next poll.
              break;
            }
            tw.release_height = *height;
          }

          Crypto::Hash ack_txid;
          std::string err;
          const auto outcome =
              Submission::SubmitAckWithdrawal(
                  *session, rt,
                  tw.withdrawal_id,
                  tw.release_tx_hash,
                  tw.release_height,
                  tw.ack_block,
                  &ack_txid,
                  &err);

          if (outcome == Submission::SubmitOutcome::Submitted)
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: ack-withdrawal recorded "
                      << tw.withdrawal_id << " -> "
                      << ack_txid.toString()
                      << " (release at CCX height "
                      << tw.release_height << ")\n";
            tw.phase = WithdrawalPhase::Done;
          }
          else if (outcome ==
                   Submission::SubmitOutcome::AlreadyConsumed)
          {
            tw.phase = WithdrawalPhase::Done;
          }
          else
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: ack-withdrawal failed for "
                      << tw.withdrawal_id << ": " << err << "\n";
            //  Retry next poll.
          }
          break;
        }

        case WithdrawalPhase::Done:
        {
          it = tracked.erase(it);
          continue;
        }
        }

        ++it;
      }
    }

    //  ---- The loop entry point ----

    void runScanLoop(WatcherSession *session,
                     std::string chain_name,
                     std::shared_ptr<std::atomic<bool>> stop)
    {
      std::map<std::string, ObservedDeposit> watched_deposits;
      std::map<uint64_t, TrackedWithdrawal> tracked_withdrawals;
      std::set<std::string> warned_unregistered_chains;
      ReleaseTracker release_tracker;

      while (!stop->load(std::memory_order_acquire))
      {
        ChainRuntime *rt = session->findChain(chain_name);
        if (!rt || !rt->enabled || !rt->adapter || !rt->rpc)
        {
          std::cerr << "[" << chain_name << "] scan: runtime vanished; "
                                            "stopping\n";
          break;
        }

        //  ---- Deposit phase ----
        runDepositScanPhase(session, *rt, chain_name,
                            watched_deposits,
                            warned_unregistered_chains,
                            stop);

        //  ---- Withdrawal phase ----
        runWithdrawalScanPhase(session, *rt, chain_name,
                               tracked_withdrawals, release_tracker, stop);

        const auto deadline =
            std::chrono::steady_clock::now() + SCAN_POLL_INTERVAL;
        while (!stop->load(std::memory_order_acquire))
        {
          if (std::chrono::steady_clock::now() >= deadline)
            break;
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
      }

      release_tracker.shutdown();
    }

  } // namespace Scan
} // namespace Bridge