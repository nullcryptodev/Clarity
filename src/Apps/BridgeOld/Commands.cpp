// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Commands.h"

#include "ChainAdapter.h"
#include "ReleaseTracker.h"
#include "Session.h"
#include "Submission.h"
#include "Hex.h"
#include "Adapters/ConcealCCX.h"

#include "Core/BridgeTypes.h"

#include "Crypto/Helpers.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace Bridge
{

  namespace
  {
    constexpr auto SCAN_POLL_INTERVAL = std::chrono::seconds(30);

    //  Burn finality depth for withdrawals: how many Clarity blocks
    //  a BridgeBurn must be buried under before the federation
    //  releases the corresponding CCX. Protects against a reorg of
    //  the burn. Three blocks is conservative for a BFT-finality
    //  chain; a probabilistic-finality chain would want more.
    //
    //  This is per-deployment policy. It reads from
    //  ChainWatcherConfig::burn_finality_depth (default 3); the
    //  constant below is only a fallback for the rare call site
    //  that doesn't have a ChainRuntime.
    constexpr uint16_t kDefaultBurnFinalityDepth = 3;

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

    struct ScanHandle
    {
      std::thread thread;
      std::shared_ptr<std::atomic<bool>> stop_requested;
    };

    std::mutex g_scans_mutex;
    std::map<std::string, ScanHandle> g_scans;

    //  Withdrawal state machine. Each pending withdrawal the scan
    //  loop has discovered lives in exactly one of these states.
    //  Transitions are driven by the corresponding scan phase
    //  functions below.
    //
    //    Observed     — seen on Clarity, no ack submitted yet
    //    Acking       — ack attestation submitted, waiting for peers
    //    Acked        — quorum reached, waiting for burn finality
    //    Releasable   — finality reached, ready to launch release
    //    Releasing    — release handed to ReleaseTracker, waiting
    //                   for the background wallet RPC call to return
    //    Released     — release confirmed on CCX, waiting to record
    //                   the ack-withdrawal on Clarity
    //    Done         — ack-withdrawal recorded, withdrawal complete
    enum class WithdrawalPhase
    {
      Observed,
      Acking,
      Acked,
      Releasable,
      Releasing,
      Released,
      Done,
    };

    struct TrackedWithdrawal
    {
      uint64_t withdrawal_id{0};
      uint64_t source_chain_id{0};
      uint64_t amount{0}; // Clarity atomic units
      uint64_t created_at_height{0};
      uint64_t ack_quorum{0};
      std::vector<uint8_t> ack_block;
      Crypto::Hash release_tx_hash{};
      uint64_t release_height{0};
      WithdrawalPhase phase{WithdrawalPhase::Observed};
      std::chrono::steady_clock::time_point phase_since;
    };

    //  ---- Deposit scan phase ----

    void runDepositScanPhase(WatcherSession *session,
                             ChainRuntime &rt,
                             const std::string &chain_name,
                             std::map<std::string, ObservedDeposit> &watched,
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
              *rt.rpc, Crypto::PublicKey{}, from, to,
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
                      Bridge::Submission::SubmitAttestation(
                          *session, rt, d, &attest_txid, &attest_err);

                  switch (outcome)
                  {
                  case Bridge::Submission::AttestOutcome::Submitted:
                    std::cerr << "[" << chain_name
                              << "] scan: attested "
                              << d.source_tx_hash.toString().substr(0, 16)
                              << "..." << d.source_output_index
                              << " -> " << attest_txid.toString() << "\n";
                    watched.emplace(key, d);
                    break;

                  case Bridge::Submission::AttestOutcome::AlreadyAttested:
                    watched.emplace(key, d);
                    break;

                  case Bridge::Submission::AttestOutcome::AlreadyConsumed:
                    break;

                  case Bridge::Submission::AttestOutcome::NotAWriter:
                    break;

                  case Bridge::Submission::AttestOutcome::Failed:
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
            Bridge::Submission::AssembleMintBlock(
                *session->clarity_rpc,
                session->currentNetwork(),
                d.source_chain_id,
                d,
                /*quorum=*/2,
                &block,
                &assemble_err);

        if (assemble_outcome == Bridge::Submission::AssembleOutcome::Ok)
        {
          std::string submit_err;
          Crypto::Hash mint_txid;
          const auto submit_outcome =
              Bridge::Submission::SubmitDeposit(
                  *session, rt, d, block, &mint_txid, &submit_err);

          if (submit_outcome == Bridge::Submission::SubmitOutcome::Submitted)
          {
            std::cerr << "[" << chain_name << "] scan: minted "
                      << d.source_tx_hash.toString().substr(0, 16)
                      << "..." << d.source_output_index
                      << " -> " << mint_txid.toString() << "\n";
            it = watched.erase(it);
            continue;
          }
          else if (submit_outcome ==
                   Bridge::Submission::SubmitOutcome::AlreadyConsumed)
          {
            it = watched.erase(it);
            continue;
          }
        }
        else if (assemble_outcome ==
                 Bridge::Submission::AssembleOutcome::Conflicting)
        {
          std::cerr << "[" << chain_name
                    << "] scan: FEDERATION SPLIT on deposit "
                    << d.source_tx_hash.toString().substr(0, 16)
                    << "..." << d.source_output_index
                    << ": " << assemble_err << "\n";
        }
        else if (assemble_outcome ==
                 Bridge::Submission::AssembleOutcome::StateError)
        {
          std::cerr << "[" << chain_name
                    << "] scan: assemble StateError for deposit "
                    << d.source_tx_hash.toString().substr(0, 16)
                    << "..." << d.source_output_index
                    << ": " << assemble_err << "\n";
        }
        else if (assemble_outcome ==
                 Bridge::Submission::AssembleOutcome::RpcError)
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
    void drainCompletedReleases(
        const std::string &chain_name,
        ChainRuntime &rt,
        ReleaseTracker &tracker,
        std::map<uint64_t, TrackedWithdrawal> &tracked)
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
        if (auto *ccx = dynamic_cast<CcxAdapter *>(rt.adapter.get()))
        {
          Crypto::Hash payment_id;
          {
            uint8_t preimage[8];
            for (int i = 0; i < 8; ++i)
              preimage[i] = uint8_t(completed.withdrawal_id >> (i * 8));
            payment_id = Crypto::hashDomain(
                "back", preimage, sizeof(preimage));
          }

          if (auto existing = ccx->find_existing_release(payment_id);
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
                                std::map<uint64_t, TrackedWithdrawal> &tracked,
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
          const auto outcome = Bridge::Submission::SubmitAckAttestation(
              *session, rt, tw.withdrawal_id, &ack_txid, &err);

          switch (outcome)
          {
          case Bridge::Submission::AttestOutcome::Submitted:
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: ack-attested withdrawal "
                      << tw.withdrawal_id
                      << " -> " << ack_txid.toString() << "\n";
            tw.phase = WithdrawalPhase::Acking;
            tw.phase_since = std::chrono::steady_clock::now();
            break;

          case Bridge::Submission::AttestOutcome::AlreadyAttested:
            tw.phase = WithdrawalPhase::Acking;
            tw.phase_since = std::chrono::steady_clock::now();
            break;

          case Bridge::Submission::AttestOutcome::AlreadyConsumed:
            tw.phase = WithdrawalPhase::Done;
            break;

          case Bridge::Submission::AttestOutcome::NotAWriter:
            break;

          case Bridge::Submission::AttestOutcome::Failed:
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
          const auto outcome = Bridge::Submission::AssembleAckBlock(
              clarity,
              tw.withdrawal_id,
              /*quorum=*/static_cast<size_t>(tw.ack_quorum),
              &block,
              &assemble_err);

          if (outcome == Bridge::Submission::AssembleAckOutcome::Ok)
          {
            tw.ack_block = std::move(block);
            tw.phase = WithdrawalPhase::Releasable;
            tw.phase_since = std::chrono::steady_clock::now();
          }
          else if (outcome ==
                   Bridge::Submission::AssembleAckOutcome::AlreadyReleased)
          {
            tw.phase = WithdrawalPhase::Done;
          }
          else if (outcome ==
                   Bridge::Submission::AssembleAckOutcome::NotYetQuorum)
          {
            tw.phase = WithdrawalPhase::Acking;
            tw.phase_since = std::chrono::steady_clock::now();
          }
          else if (outcome ==
                   Bridge::Submission::AssembleAckOutcome::StateError)
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: assemble StateError for "
                      << tw.withdrawal_id << ": " << assemble_err << "\n";
          }
          else if (outcome ==
                   Bridge::Submission::AssembleAckOutcome::RpcError)
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

          if (dest_blob.size() != 64)
          {
            std::cerr << "[" << chain_name
                      << "] withdrawal scan: withdrawal "
                      << tw.withdrawal_id
                      << " has a malformed destination_blob; skipping\n";
            break;
          }

          const uint64_t amount_source_atomic =
              rt.adapter->to_source_atomic(tw.amount,
                                           GlobalConfig::DECIMALS);

          Bridge::ReleaseRequest req;
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
          if (auto *ccx = dynamic_cast<CcxAdapter *>(rt.adapter.get()))
          {
            //  Compute the same payment ID submit_release uses:
            //  Blake2b("back" || LE64(withdrawal_id)).
            Crypto::Hash payment_id;
            {
              uint8_t preimage[8];
              for (int i = 0; i < 8; ++i)
                preimage[i] = uint8_t(tw.withdrawal_id >> (i * 8));
              payment_id = Crypto::hashDomain("back", preimage, sizeof(preimage));
            }

            if (auto existing = ccx->find_existing_release(payment_id);
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
              Bridge::Submission::SubmitAckWithdrawal(
                  *session, rt,
                  tw.withdrawal_id,
                  tw.release_tx_hash,
                  tw.release_height,
                  tw.ack_block,
                  &ack_txid,
                  &err);

          if (outcome == Bridge::Submission::SubmitOutcome::Submitted)
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
                   Bridge::Submission::SubmitOutcome::AlreadyConsumed)
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

    void runScanLoop(WatcherSession *session,
                     std::string chain_name,
                     std::shared_ptr<std::atomic<bool>> stop)
    {
      std::map<std::string, ObservedDeposit> watched_deposits;
      std::map<uint64_t, TrackedWithdrawal> tracked_withdrawals;
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
                            watched_deposits, stop);

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

    void startScan(WatcherSession &session, const std::string &chain_name)
    {
      std::lock_guard<std::mutex> lock(g_scans_mutex);

      if (g_scans.find(chain_name) != g_scans.end())
        return;

      auto stop = std::make_shared<std::atomic<bool>>(false);
      ScanHandle handle;
      handle.stop_requested = stop;
      handle.thread = std::thread(runScanLoop, &session, chain_name, stop);

      g_scans.emplace(chain_name, std::move(handle));
    }

    void stopScan(const std::string &chain_name)
    {
      std::thread to_join;
      {
        std::lock_guard<std::mutex> lock(g_scans_mutex);
        auto it = g_scans.find(chain_name);
        if (it == g_scans.end())
          return;

        it->second.stop_requested->store(true, std::memory_order_release);
        to_join = std::move(it->second.thread);
        g_scans.erase(it);
      }
      if (to_join.joinable())
        to_join.join();
    }
  } // anonymous namespace

  void requestStopAllScans()
  {
    std::vector<std::thread> to_join;
    {
      std::lock_guard<std::mutex> lock(g_scans_mutex);
      for (auto &[name, handle] : g_scans)
      {
        (void)name;
        handle.stop_requested->store(true, std::memory_order_release);
        to_join.push_back(std::move(handle.thread));
      }
      g_scans.clear();
    }
    for (auto &t : to_join)
    {
      if (t.joinable())
        t.join();
    }
  }

  namespace
  {
    const Command kCommands[] = {
        {"status", "status",
         "Show all enabled chains, their endpoints, current heights,\n"
         "pending deposit/withdrawal counts, and whether the scan\n"
         "worker is running.",
         cmd_status},

        {"chains", "chains",
         "List every chain adapter compiled into this binary, with\n"
         "whether it is enabled in this session.",
         cmd_chains},

        {"use", "use <chain>",
         "Select the chain that subsequent single-chain commands act\n"
         "on. Use 'chains' to see short names.",
         cmd_use},

        {"enable", "enable <chain>",
         "Enable a chain adapter for this session. By default uses\n"
         "the adapter's defaults; use --rpc and --confirmation-depth\n"
         "to override.",
         cmd_enable},

        {"disable", "disable <chain>",
         "Stop and disable a chain. Its state directory is preserved.\n"
         "Refuses if this is the last enabled chain.",
         cmd_disable},

        {"deposits", "deposits [--limit N]",
         "Scan the current chain from the last processed height to the\n"
         "tip, printing any deposits found. Does not submit mints —\n"
         "that is the signing service's job.",
         cmd_deposits},

        {"withdrawals", "withdrawals",
         "List pending withdrawals on Clarity for the current chain,\n"
         "showing each withdrawal's phase in the ack/release pipeline:\n"
         "Observed, Acking, Acked, Releasable, Releasing, Released,\n"
         "or Done.",
         cmd_withdrawals},

        {"pending", "pending",
         "Show the pending deposit and withdrawal counters for the\n"
         "current chain.",
         cmd_pending},

        {"start", "start [<chain>] [--bridge-address <addr>] "
                  "[--consensus-key <hex> | --consensus-key-file <path>] "
                  "[--mint-destination <addr>]",
         "Start the scan worker for a chain (the current chain if no\n"
         "argument).\n"
         "--bridge-address is the CCX address that deposits must pay\n"
         "to. It is required for the CCX adapter to scan; without it\n"
         "scan_deposits throws on the first poll. The address is a\n"
         "base58 CCX address.\n"
         "--consensus-key / --consensus-key-file provide the 32-byte\n"
         "consensus key that signs deposit attestations. It is\n"
         "distinct from the account key in the keystore. If neither\n"
         "is passed on the start command, a key loaded at process\n"
         "startup (from --consensus-key-file on the main command\n"
         "line) is used.\n"
         "--mint-destination sets the address wrapped tokens are\n"
         "minted to; it must be identical across all federation\n"
         "watchers. If omitted, the watcher's own keystore address\n"
         "is used (only works for a single-watcher federation).",
         cmd_start},

        {"stop", "stop [<chain>]",
         "Stop the scan worker for a chain. Does not disable the\n"
         "chain or affect pending deposits.",
         cmd_stop},

        {"rescan", "rescan [--from <height>]",
         "Reset the current chain's cursor and re-scan from the given\n"
         "height (or genesis). Does not submit mints. Use with care on\n"
         "a chain that has already processed millions of blocks.",
         cmd_rescan},

        {"state", "state [watcher|keystore|chains]",
         "Show the session's state: watcher id and keystore (default),\n"
         "or the per-chain cursors and counters.",
         cmd_state},

        {"connect", "connect <chain> <host:port>",
         "Change the source-chain RPC endpoint for a chain. Re-probes\n"
         "the endpoint after connecting. Does not reset the cursor.",
         cmd_connect},

        {"open", "open <path> [--password-file <path>]",
         "Open and unlock a keystore. Only one keystore may be open\n"
         "per session; the same keystore is used across all chains.",
         cmd_open},

        {"close", "close",
         "Lock and close the currently-open keystore.",
         cmd_close},

        {"help", "help [command]",
         "Show help. With no argument, lists all commands.",
         cmd_help},

        {"exit", "exit",
         "Exit the bridge app. Stops all scan workers cleanly.",
         cmd_exit},

        {"quit", "quit",
         "Exit the bridge app.",
         cmd_exit},

        {nullptr, nullptr, nullptr, nullptr},
    };
  } // anonymous namespace

  const Command *commandTable() { return kCommands; }

  const Command *findCommand(const std::string &name)
  {
    for (const Command *c = kCommands; c->name != nullptr; ++c)
    {
      if (name == c->name)
        return c;
    }
    return nullptr;
  }

  std::vector<std::string> tokenizeCommand(const std::string &line)
  {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok)
      tokens.push_back(std::move(tok));
    return tokens;
  }

  bool dispatchCommand(WatcherSession &session,
                       const std::vector<std::string> &tokens)
  {
    if (tokens.empty())
      return true;

    const Command *cmd = findCommand(tokens[0]);
    if (cmd == nullptr)
    {
      std::cerr << "error: unknown command '" << tokens[0] << "'\n";
      std::cerr << "Type 'help' for a list of commands.\n";
      return false;
    }

    cmd->handler(session, tokens);
    return true;
  }

  namespace
  {
    std::optional<uint64_t> parseU64(const std::string &s)
    {
      if (s.empty())
        return std::nullopt;
      errno = 0;
      char *end = nullptr;
      const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
      if (errno != 0 || end == s.c_str() || *end != '\0')
        return std::nullopt;
      return static_cast<uint64_t>(v);
    }

    bool parseEndpointSpec(const std::string &spec,
                           std::string &host_out,
                           uint16_t &port_out)
    {
      const size_t colon = spec.find(':');
      if (colon == std::string::npos || colon == 0 ||
          colon + 1 >= spec.size())
        return false;

      const std::string host = spec.substr(0, colon);
      const std::string port_str = spec.substr(colon + 1);

      char *end = nullptr;
      const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
      if (end == port_str.c_str() || *end != '\0' ||
          port == 0 || port > 65535)
        return false;

      host_out = host;
      port_out = static_cast<uint16_t>(port);
      return true;
    }

    ChainRuntime *requireCurrent(WatcherSession &session,
                                 const char *command)
    {
      if (session.current_chain.empty())
      {
        std::cerr << "error: no chain selected. Use 'use <chain>' first.\n";
        std::cerr << " (see 'chains' for the available short names)\n";
        (void)command;
        return nullptr;
      }
      ChainRuntime *rt = session.current();
      if (!rt)
      {
        std::cerr << "error: current chain '" << session.current_chain
                  << "' is not enabled\n";
        return nullptr;
      }
      if (!rt->connected)
      {
        std::cerr << "warning: chain '" << session.current_chain
                  << "' is not reachable at "
                  << rt->config.rpc_host << ":" << rt->config.rpc_port
                  << "\n";
        std::cerr << " try 'connect " << session.current_chain
                  << " <host:port>' or check the daemon\n";
      }
      return rt;
    }

    std::string formatAmountWithDecimals(uint64_t atomic, uint8_t decimals)
    {
      if (decimals == 0)
        return std::to_string(atomic);
      uint64_t divisor = 1;
      for (uint8_t i = 0; i < decimals; ++i)
        divisor *= 10;
      const uint64_t whole = atomic / divisor;
      const uint64_t frac = atomic % divisor;
      if (frac == 0)
        return std::to_string(whole);
      std::string frac_str = std::to_string(frac);
      while (frac_str.size() < decimals)
        frac_str.insert(frac_str.begin(), '0');
      return std::to_string(whole) + "." + frac_str;
    }

    std::string formatHashShort(const Crypto::Hash &h)
    {
      static const char HEX[] = "0123456789abcdef";
      std::string out = "0x";
      for (int i = 0; i < 8; ++i)
      {
        out.push_back(HEX[h.data[i] >> 4]);
        out.push_back(HEX[h.data[i] & 0xF]);
      }
      return out + "...";
    }

    std::string formatDuration(int64_t seconds)
    {
      if (seconds <= 0)
        return "0s";
      const int64_t hours = seconds / 3600;
      const int64_t minutes = (seconds % 3600) / 60;
      const int64_t secs = seconds % 60;
      std::ostringstream oss;
      if (hours > 0)
        oss << hours << "h " << minutes << "m";
      else if (minutes > 0)
        oss << minutes << "m " << secs << "s";
      else
        oss << secs << "s";
      return oss.str();
    }

    std::string displayName(const ChainRuntime &rt)
    {
      if (rt.adapter)
        return rt.adapter->name() + " (" + rt.adapter->short_name() + ")";
      return rt.config.chain_short_name;
    }
  } // anonymous namespace

  void cmd_status(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    (void)args;

    std::cout << "Bridge status\n";
    std::cout << "=============\n\n";

    std::cout << "Clarity node: ";
    if (session.clarity_connected)
    {
      std::cout << session.clarity_endpoint.host << ":"
                << session.clarity_endpoint.port
                << " [connected]\n";
    }
    else
    {
      std::cout << session.clarity_endpoint.host << ":"
                << session.clarity_endpoint.port
                << " [offline]\n";
    }

    if (session.hasKeystore())
    {
      std::cout << "Keystore: " << session.address_bech32m << "\n";
      if (session.watcher_id != 0)
        std::cout << "Watcher id: " << session.watcher_id << "\n";
      else
        std::cout << "Watcher id: (unresolved)\n";
    }
    else
    {
      std::cout << "Keystore: (none)\n";
    }

    std::cout << "\nChains:\n";
    if (session.chains.empty())
    {
      std::cout << " (none enabled)\n";
      return;
    }

    std::vector<std::string> names;
    names.reserve(session.chains.size());
    for (const auto &[name, rt] : session.chains)
    {
      if (rt.enabled)
        names.push_back(name);
    }
    std::sort(names.begin(), names.end());

    for (const auto &n : names)
    {
      const auto &rt = session.chains.at(n);
      const bool is_current = (n == session.current_chain);

      std::cout << "\n " << (is_current ? "* " : " ")
                << n << " — " << displayName(rt) << "\n";
      std::cout << " rpc: " << rt.config.rpc_host
                << ":" << rt.config.rpc_port
                << (rt.connected ? " [reachable]" : " [not reachable]")
                << "\n";
      std::cout << " confirmations: " << rt.config.confirmation_depth
                << "\n";

      std::cout << " bridge address: ";
      if (rt.bridge_deposit_address.empty())
        std::cout << "(not configured)\n";
      else
        std::cout << rt.bridge_deposit_address << "\n";

      std::cout << " wallet rpc: ";
      if (rt.config.wallet_rpc_host.empty() ||
          rt.config.wallet_rpc_port == 0)
      {
        std::cout << "(not configured — releases disabled)\n";
      }
      else
      {
        std::cout << rt.config.wallet_rpc_host << ":"
                  << rt.config.wallet_rpc_port << "\n";
      }

      std::cout << " burn finality: " << rt.config.burn_finality_depth
                << " blocks\n";

      std::cout << " cursor: source_height="
                << rt.last_source_height
                << " clarity_height=" << rt.last_clarity_height
                << "\n";
      std::cout << " pending: deposits="
                << rt.pending_deposits
                << " withdrawals=" << rt.pending_withdrawals
                << "\n";

      if (rt.running)
      {
        const int64_t elapsed =
            rt.started_at > 0
                ? static_cast<int64_t>(std::time(nullptr)) - rt.started_at
                : 0;
        std::cout << " status: running";
        if (elapsed > 0)
          std::cout << " (for " << formatDuration(elapsed) << ")";
        std::cout << "\n";
      }
      else
      {
        std::cout << " status: stopped\n";
      }

      std::cout << " state dir: " << rt.config.state_subdir
                << "\n";
    }
  }

  void cmd_chains(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    (void)args;

    auto adapters = ChainAdapterRegistry::all();
    if (adapters.empty())
    {
      std::cout << "No chain adapters compiled into this binary.\n";
      return;
    }

    std::cout << "Available chain adapters:\n\n";
    for (const auto &adapter : adapters)
    {
      const std::string name = adapter->short_name();
      const auto it = session.chains.find(name);
      const bool enabled = (it != session.chains.end() && it->second.enabled);
      const bool is_current = (name == session.current_chain);

      std::cout << " " << (is_current ? "* " : " ")
                << name << " — " << adapter->name()
                << (enabled ? " [enabled]" : "")
                << "\n";
      std::cout << " default rpc: " << adapter->default_rpc_endpoint()
                << "\n";
      std::cout << " default conf: "
                << adapter->default_confirmation_depth() << "\n";
      if (enabled)
      {
        const auto &rt = it->second;
        std::cout << " current rpc: " << rt.config.rpc_host
                  << ":" << rt.config.rpc_port
                  << (rt.connected ? " [reachable]"
                                   : " [not reachable]")
                  << "\n";
        std::cout << " status: "
                  << (rt.running ? "running" : "stopped") << "\n";
      }
    }
  }

  void cmd_use(WatcherSession &session,
               const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      if (session.current_chain.empty())
      {
        std::cout << "no chain selected\n";
      }
      else
      {
        std::cout << "current: " << session.current_chain << "\n";
      }
      return;
    }

    const std::string &name = args[1];
    if (!session.selectChain(name))
    {
      std::cerr << "error: cannot select '" << name << "'\n";
      std::cerr << " 'chains' shows which are enabled.\n";
      return;
    }
    std::cout << "Current chain: " << name << "\n";
  }

  void cmd_enable(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: enable <chain> [--rpc <host:port>] "
                   "[--confirmation-depth N]\n";
      return;
    }

    const std::string &name = args[1];

    auto adapter = ChainAdapterRegistry::find(name);
    if (!adapter)
    {
      std::cerr << "error: unknown chain '" << name << "'\n";
      std::cerr << " 'chains' shows the available adapters.\n";
      return;
    }

    ChainWatcherConfig cfg;
    cfg.chain_short_name = name;
    cfg.enabled = true;
    applyAdapterDefaults(*adapter, cfg);

    for (size_t i = 2; i < args.size(); ++i)
    {
      if (args[i] == "--rpc" && i + 1 < args.size())
      {
        std::string host;
        uint16_t port = 0;
        if (!parseEndpointSpec(args[++i], host, port))
        {
          std::cerr << "error: --rpc: invalid host:port\n";
          return;
        }
        cfg.rpc_host = host;
        cfg.rpc_port = port;
      }
      else if (args[i] == "--confirmation-depth" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value() || *v == 0 || *v > 65535)
        {
          std::cerr << "error: --confirmation-depth: invalid\n";
          return;
        }
        cfg.confirmation_depth = static_cast<uint16_t>(*v);
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    auto *rt = session.enableChain(adapter, cfg);
    if (!rt)
    {
      std::cerr << "error: enableChain failed\n";
      return;
    }

    std::cout << "Probing " << cfg.rpc_host << ":" << cfg.rpc_port
              << "...\n";
    if (probeChain(*rt))
      std::cout << " Reachable.\n";
    else
      std::cout << " Not reachable. Use 'connect " << name
                << " <host:port>' later.\n";

    if (session.current_chain.empty())
      session.current_chain = name;

    std::cout << "Enabled " << name << ".\n";
  }

  void cmd_disable(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: disable <chain>\n";
      return;
    }

    const std::string &name = args[1];

    auto it = session.chains.find(name);
    if (it == session.chains.end() || !it->second.enabled)
    {
      std::cerr << "error: chain '" << name << "' is not enabled\n";
      return;
    }

    if (session.enabledChainCount() <= 1)
    {
      std::cerr << "error: cannot disable the last enabled chain\n";
      return;
    }

    if (it->second.running)
    {
      stopScan(name);
      it->second.running = false;
      it->second.started_at = 0;
    }

    it->second.enabled = false;

    if (session.current_chain == name)
    {
      for (auto &[other_name, rt] : session.chains)
      {
        if (other_name != name && rt.enabled)
        {
          session.current_chain = other_name;
          break;
        }
      }
    }

    std::cout << "Disabled " << name << ".\n";
  }

  void cmd_deposits(WatcherSession &session,
                    const std::vector<std::string> &args)
  {
    ChainRuntime *rt = requireCurrent(session, "deposits");
    if (!rt)
      return;

    if (!rt->connected)
    {
      std::cerr << "error: chain not reachable; scan would fail\n";
      return;
    }

    size_t limit = 20;
    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--limit" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --limit: invalid\n";
          return;
        }
        limit = static_cast<size_t>(*v);
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    ChainStatus status;
    try
    {
      status = rt->adapter->fetch_status(*rt->rpc);
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: fetch_status failed: " << e.what() << "\n";
      return;
    }

    if (!status.reachable)
    {
      std::cerr << "error: chain not reachable\n";
      return;
    }

    const uint64_t from = rt->last_source_height + 1;
    const uint64_t to = status.current_height;

    if (from > to)
    {
      std::cout << "No new blocks since height "
                << rt->last_source_height << ".\n";
      return;
    }

    std::cout << "Scanning heights " << from << ".." << to
              << " (tip " << to << ")...\n";

    size_t found = 0;
    try
    {
      rt->adapter->scan_deposits(
          *rt->rpc,
          Crypto::PublicKey{},
          from, to,
          [&](const ObservedDeposit &d)
          {
            std::cout << " height=" << d.block_height
                      << " tx=" << formatHashShort(d.source_tx_hash)
                      << " amount="
                      << formatAmountWithDecimals(
                             d.amount_source_atomic,
                             rt->adapter->source_decimals())
                      << "\n";
            ++found;
            if (found >= limit)
              return false;
            return true;
          });
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: scan_deposits failed: " << e.what() << "\n";
      return;
    }

    if (found == 0)
    {
      std::cout << "No deposits found in that range.\n";
    }
    else
    {
      std::cout << "\n"
                << found << " deposit(s) found.\n";
      std::cout << "Use 'rescan' to advance the cursor to the tip.\n";
    }
  }

  void cmd_withdrawals(WatcherSession &session,
                       const std::vector<std::string> &args)
  {
    (void)args;

    ChainRuntime *rt = requireCurrent(session, "withdrawals");
    if (!rt)
      return;

    if (!session.clarity_connected)
    {
      std::cerr << "error: Clarity node is not reachable\n";
      return;
    }

    if (!session.clarity_rpc)
    {
      std::cerr << "error: no Clarity RPC client\n";
      return;
    }

    Wallet::RpcClient &clarity = *session.clarity_rpc;

    std::string err;
    auto res = Wallet::getPendingWithdrawals(
        clarity,
        /*from_height=*/0,
        /*limit=*/50,
        /*offset=*/0,
        &err);

    if (!res.has_value())
    {
      std::cerr << "error: getPendingWithdrawals failed: " << err << "\n";
      return;
    }
    if (!res->is_object() ||
        !res->contains("withdrawals") ||
        !(*res)["withdrawals"].is_array())
    {
      std::cerr << "error: getPendingWithdrawals returned an unexpected "
                   "shape\n";
      return;
    }

    const uint64_t my_chain = rt->adapter->source_chain_id();

    std::cout << "Pending withdrawals for " << rt->chain_short_name()
              << ":\n\n";

    size_t shown = 0;
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
      if (scid != my_chain)
        continue;

      ++shown;

      uint64_t wid = 0;
      uint64_t amount = 0;
      uint64_t created_at = 0;
      uint64_t ack_count = 0;
      uint64_t quorum = 0;
      bool quorum_reached = false;
      bool is_released = false;

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
          wid = 0;
        }
      }
      if (entry.contains("amount") && entry["amount"].is_string())
      {
        try
        {
          amount = std::stoull(
              entry["amount"].get<std::string>(),
              nullptr, 0);
        }
        catch (...)
        {
          amount = 0;
        }
      }
      if (entry.contains("created_at_height") &&
          entry["created_at_height"].is_string())
      {
        try
        {
          created_at = std::stoull(
              entry["created_at_height"].get<std::string>(),
              nullptr, 0);
        }
        catch (...)
        {
          created_at = 0;
        }
      }

      if (entry.contains("ack_attestation_count"))
      {
        const auto &c = entry["ack_attestation_count"];
        if (c.is_number_unsigned())
          ack_count = c.get<uint64_t>();
        else if (c.is_string())
        {
          try
          {
            ack_count = std::stoull(c.get<std::string>(), nullptr, 0);
          }
          catch (...)
          {
            ack_count = 0;
          }
        }
      }

      //  ack_quorum is emitted by the encoder as a hex string,
      //  but accept a JSON number too for forward-compatibility.
      if (entry.contains("ack_quorum"))
      {
        const auto &q = entry["ack_quorum"];
        if (q.is_number_unsigned())
          quorum = q.get<uint64_t>();
        else if (q.is_string())
        {
          try
          {
            quorum = std::stoull(q.get<std::string>(), nullptr, 0);
          }
          catch (...)
          {
            quorum = 0;
          }
        }
      }
      if (entry.contains("ack_quorum_reached") &&
          entry["ack_quorum_reached"].is_boolean())
      {
        quorum_reached =
            entry["ack_quorum_reached"].get<bool>();
      }
      if (entry.contains("is_released") &&
          entry["is_released"].is_boolean())
      {
        is_released = entry["is_released"].get<bool>();
      }

      const char *phase_label = "observed";
      if (is_released)
        phase_label = "done (released)";
      else if (quorum_reached)
        phase_label = "acked (awaiting finality/release)";
      else if (ack_count > 0)
        phase_label = "acking";

      std::cout << " withdrawal " << wid
                << "  amount=" << amount
                << "  created_at=" << created_at
                << "  acks=" << ack_count << "/" << quorum
                << "  [" << phase_label << "]\n";
    }

    if (shown == 0)
    {
      std::cout << " (none)\n";
    }
    else
    {
      std::cout << "\n"
                << shown << " pending withdrawal(s) found.\n";
    }
  }

  void cmd_pending(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    (void)args;
    ChainRuntime *rt = requireCurrent(session, "pending");
    if (!rt)
      return;

    std::cout << "Pending for " << rt->chain_short_name() << ":\n";
    std::cout << " deposits: " << rt->pending_deposits << "\n";
    std::cout << " withdrawals: " << rt->pending_withdrawals << "\n";
  }

  void cmd_start(WatcherSession &session,
                 const std::vector<std::string> &args)
  {
    ChainRuntime *rt = nullptr;
    std::string consensus_key_hex;
    std::string bridge_address_str;

    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--consensus-key" && i + 1 < args.size())
      {
        consensus_key_hex = args[++i];
      }
      else if (args[i] == "--consensus-key-file" && i + 1 < args.size())
      {
        std::string path = args[++i];
        std::FILE *f = std::fopen(path.c_str(), "rb");
        if (!f)
        {
          std::cerr << "error: cannot open --consensus-key-file '"
                    << path << "'\n";
          return;
        }
        std::string contents;
        char buf[256];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
          contents.append(buf, n);
        std::fclose(f);
        while (!contents.empty() &&
               (contents.back() == '\n' || contents.back() == '\r' ||
                contents.back() == ' ' || contents.back() == '\t'))
          contents.pop_back();
        consensus_key_hex = contents;
      }
      else if (args[i] == "--bridge-address" && i + 1 < args.size())
      {
        bridge_address_str = args[++i];
      }
      else if (args[i] == "--mint-destination" && i + 1 < args.size())
      {
        auto decoded =
            Wallet::decodeAddress(args[++i], session.currentNetwork());
        if (!decoded.has_value())
        {
          std::cerr << "error: --mint-destination: invalid bech32m address\n";
          return;
        }
        session.mint_destination = *decoded;
      }
      else if (rt == nullptr && args[i].rfind("--", 0) != 0)
      {
        rt = session.findChain(args[i]);
        if (!rt)
        {
          std::cerr << "error: unknown chain '" << args[i] << "'\n";
          return;
        }
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    if (!rt)
      rt = requireCurrent(session, "start");
    if (!rt)
      return;

    if (!rt->enabled)
    {
      std::cerr << "error: chain is not enabled\n";
      return;
    }
    if (rt->running)
    {
      std::cout << rt->chain_short_name() << " is already running\n";
      return;
    }
    if (!rt->connected)
    {
      std::cerr << "error: chain is not reachable; "
                   "use 'connect' first\n";
      return;
    }
    if (!session.hasKeystore() || !session.signer)
    {
      std::cerr << "error: an open keystore is required to sign "
                   "attestations\n";
      return;
    }
    if (!session.address.has_value())
    {
      std::cerr << "error: session address is unresolved\n";
      return;
    }
    if (session.watcher_id == 0)
    {
      std::cerr << "error: watcher_id is unresolved; cannot determine "
                   "signer index\n";
      return;
    }

    if (consensus_key_hex.empty() && !session.consensus_key.has_value())
    {
      std::cerr << "error: a consensus key is required to start the "
                   "scan worker (--consensus-key-file, --consensus-key, "
                   "or --config)\n";
      std::cerr << " (the consensus key signs deposit attestations; "
                   "it is distinct from the account key in the keystore)\n";
      return;
    }

    if (!consensus_key_hex.empty())
    {
      auto bytes = BridgeHex::Decode(consensus_key_hex);
      if (!bytes.has_value() || bytes->size() != 32)
      {
        std::cerr << "error: consensus key must be 32 bytes of hex\n";
        return;
      }
      Crypto::SecretKey key;
      std::copy(bytes->begin(), bytes->end(), key.data.begin());
      session.consensus_key = key;
    }

    //  Resolve the custody address from, in order of preference:
    //    1. --bridge-address on the start command (CLI wins)
    //    2. rt->config.bridge_address (from config file)
    //    3. rt->config.bridge_deposit_address (from config blob)
    //
    //  If (1) and (2) both specify a value and they disagree,
    //  log a warning and use (1) — the operator explicitly
    //  passed a flag on this invocation.
    const std::string configured_address = rt->config.bridge_address;
    if (!bridge_address_str.empty() &&
        !configured_address.empty() &&
        bridge_address_str != configured_address)
    {
      std::cerr << "warning: --bridge-address '" << bridge_address_str
                << "' differs from config 'bridge_address' '"
                << configured_address << "'; using the CLI value\n";
    }

    const std::string effective_bridge_address =
        !bridge_address_str.empty()
            ? bridge_address_str
            : configured_address;

    if (!effective_bridge_address.empty())
    {
      std::string parse_err;
      auto blob = rt->adapter->parse_deposit_address(
          effective_bridge_address, &parse_err);
      if (!blob.has_value())
      {
        std::cerr << "error: bridge address '" << effective_bridge_address
                  << "': " << parse_err << "\n";
        return;
      }
      rt->adapter->set_deposit_address(*blob);
      rt->bridge_deposit_address = effective_bridge_address;

      if (auto *ccx = dynamic_cast<CcxAdapter *>(rt->adapter.get()))
        ccx->set_custody_address_string(effective_bridge_address);
    }
    else if (!rt->config.bridge_deposit_address.empty())
    {
      //  Only the blob was configured. Set it for scanning; the
      //  release path will fail at sendTransaction because walletd
      //  needs a base58 address for sourceAddresses / changeAddress.
      //  Surface that at start time rather than at first release.
      rt->adapter->set_deposit_address(rt->config.bridge_deposit_address);
      std::cerr << "warning: only 'destination_blob' is configured; "
                   "releases will fail because walletd requires a "
                   "base58 custody address. Set 'bridge_address' in "
                   "the config or pass --bridge-address.\n";
    }
    else if (rt->bridge_deposit_address.empty())
    {
      std::cerr << "warning: no bridge address configured; the "
                   "adapter will refuse to scan until one is set\n";
    }

    if (session.custody_view_key.has_value())
    {
      rt->adapter->set_deposit_ident_secret(*session.custody_view_key);
    }
    else
    {
      std::cerr << "warning: no --view-key-file configured; deposit "
                   "amounts may be wrong on multi-output transactions\n";
    }

    //  Configure the withdrawal-release path. The wallet RPC endpoint
    //  and the CCX network prefix are both per-chain; they were
    //  loaded from the config file (or the CLI flags
    //  --ccx-wallet-rpc / --ccx-network-prefix) into rt->config.
    //  Wiring them into the adapter here makes them available to
    //  submit_release, which is called from the scan loop's
    //  Releasable phase via the ReleaseTracker.
    //
    //  If the wallet RPC is not configured, we do not error:
    //  deposits still work, and withdrawals will be marked
    //  Releasable, launched, fail with "no wallet RPC configured",
    //  and retry. The operator sees the error in the scan log.
    //  That's the correct behavior for a deployment that is
    //  deposit-only or that has not yet provisioned a wallet.
    if (!rt->config.wallet_rpc_host.empty() &&
        rt->config.wallet_rpc_port != 0)
    {
      rt->adapter->set_wallet_rpc_endpoint(
          rt->config.wallet_rpc_host,
          rt->config.wallet_rpc_port,
          rt->config.wallet_rpc_user,
          rt->config.wallet_rpc_password);
      std::cout << "Wallet RPC configured: "
                << rt->config.wallet_rpc_host << ":"
                << rt->config.wallet_rpc_port << "\n";
    }
    else
    {
      std::cout << "warning: no CCX wallet RPC configured; "
                   "withdrawals will not be released by this watcher\n";
    }

    rt->adapter->set_network_prefix(
        rt->config.ccx_network_prefix);

    startScan(session, rt->chain_short_name());
    rt->running = true;
    rt->started_at = static_cast<int64_t>(std::time(nullptr));

    std::cout << "Started scan worker for " << rt->chain_short_name()
              << ".\n";
    std::cout << "Deposits will be attested on-chain and minted when a "
                 "quorum of watcher attestations is present.\n";
    std::cout << "Withdrawals will be acked, released, and recorded "
                 "as they progress through the pipeline.\n";
  }

  void cmd_stop(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    ChainRuntime *rt = nullptr;
    if (args.size() >= 2)
    {
      rt = session.findChain(args[1]);
      if (!rt)
      {
        std::cerr << "error: unknown chain '" << args[1] << "'\n";
        return;
      }
    }
    else
    {
      rt = requireCurrent(session, "stop");
    }
    if (!rt)
      return;

    if (!rt->running)
    {
      std::cout << rt->chain_short_name() << " is not running\n";
      return;
    }

    stopScan(rt->chain_short_name());
    rt->running = false;
    rt->started_at = 0;

    std::cout << "Stopped scan worker for " << rt->chain_short_name()
              << ".\n";
  }

  void cmd_rescan(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    ChainRuntime *rt = requireCurrent(session, "rescan");
    if (!rt)
      return;

    uint64_t from = 0;
    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--from" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --from: invalid\n";
          return;
        }
        from = *v;
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    if (rt->running)
    {
      std::cout << "Stopping scan worker for " << rt->chain_short_name()
                << "...\n";
      stopScan(rt->chain_short_name());
      rt->running = false;
      rt->started_at = 0;
    }

    rt->last_source_height = (from == 0) ? 0 : from - 1;

    std::cout << "Cursor for " << rt->chain_short_name()
              << " reset. Next scan will start at " << from << ".\n";
    std::cout << "Use 'start' to resume the scan worker, or "
                 "'deposits' for a one-shot scan.\n";
  }

  void cmd_state(WatcherSession &session,
                 const std::vector<std::string> &args)
  {
    std::string sub = (args.size() >= 2) ? args[1] : "";

    if (sub.empty() || sub == "watcher" || sub == "keystore")
    {
      std::cout << "Watcher:\n";
      if (session.hasKeystore())
      {
        std::cout << " address: " << session.address_bech32m << "\n";
        std::cout << " network: "
                  << Wallet::networkName(session.currentNetwork())
                  << "\n";
        if (session.watcher_id != 0)
          std::cout << " watcher_id: " << session.watcher_id << "\n";
        else
          std::cout << " watcher_id: (unresolved — set with "
                       "--watcher-id or after RegisterBridgeWatcher)\n";
      }
      else
      {
        std::cout << " (no keystore open)\n";
      }

      std::cout << "\nClarity:\n";
      std::cout << " endpoint: " << session.clarity_endpoint.host
                << ":" << session.clarity_endpoint.port
                << (session.clarity_connected ? " [connected]"
                                              : " [offline]")
                << "\n";
      return;
    }

    if (sub == "chains")
    {
      if (session.chains.empty())
      {
        std::cout << "(no chains enabled)\n";
        return;
      }
      std::vector<std::string> names;
      names.reserve(session.chains.size());
      for (const auto &[name, rt] : session.chains)
      {
        if (rt.enabled)
          names.push_back(name);
      }
      std::sort(names.begin(), names.end());

      for (const auto &n : names)
      {
        const auto &rt = session.chains.at(n);
        std::cout << n << ":\n";
        std::cout << " last_source_height: " << rt.last_source_height
                  << "\n";
        std::cout << " last_clarity_height: " << rt.last_clarity_height
                  << "\n";
        std::cout << " pending_deposits: " << rt.pending_deposits
                  << "\n";
        std::cout << " pending_withdrawals: " << rt.pending_withdrawals
                  << "\n";
        std::cout << " state_dir: " << rt.config.state_subdir
                  << "\n";
      }
      return;
    }

    std::cerr << "usage: state [watcher|keystore|chains]\n";
  }

  void cmd_connect(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    if (args.size() < 3)
    {
      std::cerr << "usage: connect <chain> <host:port>\n";
      return;
    }

    const std::string &name = args[1];
    const std::string &spec = args[2];

    ChainRuntime *rt = session.findChain(name);
    if (!rt)
    {
      std::cerr << "error: unknown chain '" << name << "'\n";
      return;
    }

    std::string host;
    uint16_t port = 0;
    if (!parseEndpointSpec(spec, host, port))
    {
      std::cerr << "error: invalid host:port\n";
      return;
    }

    if (rt->running)
    {
      stopScan(name);
      rt->running = false;
      rt->started_at = 0;
    }

    rt->config.rpc_host = host;
    rt->config.rpc_port = port;
    rt->reconnect();

    std::cout << "Connecting " << name << " to "
              << host << ":" << port << "...\n";
    if (probeChain(*rt))
      std::cout << " Reachable.\n";
    else
      std::cout << " Not reachable. Check the daemon and try again.\n";
  }

  void cmd_open(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: open <path> [--password-file <path>]\n";
      return;
    }

    std::string path = args[1];
    std::string password_file;

    for (size_t i = 2; i < args.size(); ++i)
    {
      if (args[i] == "--password-file" && i + 1 < args.size())
      {
        password_file = args[++i];
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    openKeystore(session, path, password_file);
  }

  void cmd_close(WatcherSession &session,
                 const std::vector<std::string> &args)
  {
    (void)args;
    closeKeystore(session);
  }

  void cmd_help(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    (void)session;

    if (args.size() >= 2)
    {
      const Command *c = findCommand(args[1]);
      if (c == nullptr)
      {
        std::cerr << "error: no such command '" << args[1] << "'\n";
        return;
      }
      std::cout << c->usage << "\n\n"
                << c->help << "\n";
      return;
    }

    std::cout << "Commands:\n\n";
    for (const Command *c = commandTable(); c->name != nullptr; ++c)
    {
      if (std::string(c->name) == "quit")
        continue;
      std::cout << " " << c->usage << "\n";
    }
    std::cout << "\nType 'help <command>' for details.\n";
  }

  void cmd_exit(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    (void)args;

    requestStopAllScans();

    session.running = false;
  }

} // namespace Bridge