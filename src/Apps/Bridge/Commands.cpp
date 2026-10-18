// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Commands.h"

#include "ChainAdapter.h"
#include "Session.h"
#include "Submission.h"

#include "Core/BridgeTypes.h"

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

    struct ScanHandle
    {
      std::thread thread;
      std::shared_ptr<std::atomic<bool>> stop_requested;
    };

    std::mutex g_scans_mutex;
    std::map<std::string, ScanHandle> g_scans;

    void runScanLoop(WatcherSession *session,
                     std::string chain_name,
                     std::shared_ptr<std::atomic<bool>> stop)
    {
      std::cerr << "[" << chain_name << "] scan: session state — hasKeystore="
                << (session->hasKeystore() ? "yes" : "no")
                << " signer=" << (session->signer ? "yes" : "no")
                << " watcher_id=" << session->watcher_id
                << "\n";

      while (!stop->load(std::memory_order_acquire))
      {
        ChainRuntime *rt = session->findChain(chain_name);
        if (!rt || !rt->enabled || !rt->adapter || !rt->rpc)
        {
          std::cerr << "[" << chain_name << "] scan: runtime vanished; "
                                            "stopping\n";
          return;
        }

        ChainStatus status;
        try
        {
          status = rt->adapter->fetch_status(*rt->rpc);
        }
        catch (const std::exception &e)
        {
          std::cerr << "[" << chain_name << "] scan: fetch_status "
                    << "failed: " << e.what() << "\n";
          std::this_thread::sleep_for(SCAN_POLL_INTERVAL);
          continue;
        }

        if (!status.reachable)
        {
          rt->connected = false;
          std::this_thread::sleep_for(SCAN_POLL_INTERVAL);
          continue;
        }
        rt->connected = true;

        if (status.current_height > rt->last_source_height)
        {
          const uint64_t from = rt->last_source_height + 1;
          const uint64_t to = status.current_height;

          uint64_t cursor_advanced_to = rt->last_source_height;
          size_t found = 0;
          size_t submitted = 0;
          size_t skipped_consumed = 0;
          size_t skipped_disabled = 0;
          size_t attested = 0;
          size_t waiting_for_quorum = 0;
          bool warned_not_writer = false;
          std::string fail_reason;

          try
          {
            rt->adapter->scan_deposits(
                *rt->rpc, Crypto::PublicKey{},
                from, to,
                [&](const ObservedDeposit &d)
                {
                  ++found;

                  std::cerr << "[" << chain_name
                            << "] scan: processing deposit "
                            << d.source_tx_hash.toString().substr(0, 16)
                            << "..." << d.source_output_index
                            << " height=" << d.block_height
                            << " amount=" << d.amount_source_atomic << "\n";

                  if (!session->hasKeystore() || !session->signer)
                  {
                    ++skipped_disabled;
                    cursor_advanced_to = d.block_height;
                    std::cerr << "[" << chain_name
                              << "] scan: no keystore, deposit counted as disabled\n";
                    return !stop->load(std::memory_order_acquire);
                  }

                  if (session->watcher_id != 0)
                  {
                    Crypto::Hash attest_hash;
                    std::string attest_err;
                    const auto att_outcome =
                        Bridge::Submission::SubmitAttestation(
                            *session, *rt, d, &attest_hash, &attest_err);

                    switch (att_outcome)
                    {
                    case Bridge::Submission::AttestOutcome::Submitted:
                      ++attested;
                      std::cerr << "[" << chain_name
                                << "] attestation submitted: 0x"
                                << attest_hash.toString().substr(0, 16)
                                << "...\n";
                      break;
                    case Bridge::Submission::AttestOutcome::AlreadyAttested:
                      std::cerr << "[" << chain_name
                                << "] attestation already present\n";
                      break;
                    case Bridge::Submission::AttestOutcome::AlreadyConsumed:
                      std::cerr << "[" << chain_name
                                << "] deposit already consumed\n";
                      ++skipped_consumed;
                      cursor_advanced_to = d.block_height;
                      return !stop->load(std::memory_order_acquire);
                    case Bridge::Submission::AttestOutcome::NotAWriter:
                      if (!warned_not_writer)
                      {
                        std::cerr << "[" << chain_name
                                  << "] scan: not in active set; "
                                     "skipping attestation\n";
                        warned_not_writer = true;
                      }
                      break;
                    case Bridge::Submission::AttestOutcome::Failed:
                      fail_reason = "attestation failed: " + attest_err;
                      std::cerr << "[" << chain_name << "] "
                                << fail_reason << "\n";
                      return false;
                    }
                  }
                  else
                  {
                    std::cerr << "[" << chain_name
                              << "] scan: watcher_id is 0; "
                                 "skipping attestation\n";
                  }

                  uint64_t active_count = 0;
                  {
                    std::string set_err;
                    auto set = Wallet::getActiveWatchers(
                        *session->clarity_rpc,
                        d.source_chain_id, 0, &set_err);
                    if (set.has_value() && set->is_object() &&
                        set->contains("watchers") &&
                        (*set)["watchers"].is_array())
                    {
                      active_count = (*set)["watchers"].size();
                    }
                    else if (!set_err.empty())
                    {
                      std::cerr << "[" << chain_name
                                << "] getActiveWatchers failed: "
                                << set_err << "\n";
                    }
                  }

                  if (active_count == 0)
                  {
                    fail_reason = "could not fetch active watcher set";
                    std::cerr << "[" << chain_name << "] "
                              << fail_reason << "\n";
                    return false;
                  }

                  const size_t quorum = Core::bftQuorum(active_count);

                  std::vector<uint8_t> block;
                  std::string asm_err;
                  const auto asm_outcome =
                      Bridge::Submission::AssembleMintBlock(
                          *session->clarity_rpc,
                          session->currentNetwork(),
                          d.source_chain_id,
                          d,
                          quorum,
                          &block,
                          &asm_err);

                  if (asm_outcome ==
                      Bridge::Submission::AssembleOutcome::NotYetQuorum)
                  {
                    ++waiting_for_quorum;
                    std::cerr << "[" << chain_name
                              << "] waiting for quorum (need " << quorum
                              << " of " << active_count << ")\n";
                    return !stop->load(std::memory_order_acquire);
                  }

                  if (asm_outcome ==
                      Bridge::Submission::AssembleOutcome::Conflicting)
                  {
                    std::cerr << "[" << chain_name
                              << "] FEDERATION SPLIT on deposit "
                              << d.source_tx_hash.toString().substr(0, 16)
                              << "...: " << asm_err << "\n";
                    fail_reason = "federation split: " + asm_err;
                    return false;
                  }

                  if (asm_outcome !=
                      Bridge::Submission::AssembleOutcome::Ok)
                  {
                    fail_reason = "assemble failed: " + asm_err;
                    std::cerr << "[" << chain_name << "] "
                              << fail_reason << "\n";
                    return false;
                  }

                  std::cerr << "[" << chain_name
                            << "] assembled block of " << block.size()
                            << " bytes\n";

                  Crypto::Hash clarity_hash;
                  std::string submit_err;
                  const auto sub_outcome =
                      Bridge::Submission::SubmitDeposit(
                          *session, *rt, d, block,
                          &clarity_hash, &submit_err);

                  switch (sub_outcome)
                  {
                  case Bridge::Submission::SubmitOutcome::Submitted:
                    ++submitted;
                    cursor_advanced_to = d.block_height;
                    std::cerr << "[" << chain_name
                              << "] mint submitted: 0x"
                              << clarity_hash.toString().substr(0, 16)
                              << "...\n";
                    break;
                  case Bridge::Submission::SubmitOutcome::AlreadyConsumed:
                    ++skipped_consumed;
                    cursor_advanced_to = d.block_height;
                    std::cerr << "[" << chain_name
                              << "] mint already consumed\n";
                    break;
                  case Bridge::Submission::SubmitOutcome::Disabled:
                    fail_reason =
                        "submit returned Disabled with non-empty block";
                    std::cerr << "[" << chain_name << "] "
                              << fail_reason << "\n";
                    return false;
                  case Bridge::Submission::SubmitOutcome::Failed:
                    fail_reason = "submit failed: " + submit_err;
                    std::cerr << "[" << chain_name << "] "
                              << fail_reason << "\n";
                    return false;
                  }

                  return !stop->load(std::memory_order_acquire);
                });
          }
          catch (const std::exception &e)
          {
            std::cerr << "[" << chain_name << "] scan: scan_deposits "
                      << "failed on [" << from << ", " << to << "]: "
                      << e.what() << "\n";
            std::this_thread::sleep_for(SCAN_POLL_INTERVAL);
            continue;
          }

          rt->last_source_height =
              (fail_reason.empty() && waiting_for_quorum == 0
                   ? to
                   : cursor_advanced_to);

          std::cerr << "[" << chain_name << "] scan: processed heights "
                    << from << ".." << cursor_advanced_to
                    << ", " << found << " new deposit(s)"
                    << " (attested=" << attested
                    << " submitted=" << submitted
                    << " consumed=" << skipped_consumed
                    << " disabled=" << skipped_disabled
                    << " waiting=" << waiting_for_quorum << ")\n";

          if (!fail_reason.empty())
          {
            std::cerr << "[" << chain_name << "] scan: submission failed "
                      << "at height " << (cursor_advanced_to + 1)
                      << ": " << fail_reason << "\n";
            std::cerr << "[" << chain_name << "] scan: cursor held at "
                      << cursor_advanced_to << "; will retry next poll\n";
            std::this_thread::sleep_for(SCAN_POLL_INTERVAL);
            continue;
          }
        }

        const auto deadline =
            std::chrono::steady_clock::now() + SCAN_POLL_INTERVAL;
        while (!stop->load(std::memory_order_acquire))
        {
          if (std::chrono::steady_clock::now() >= deadline)
            break;
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
      }
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

        {"withdrawals", "withdrawals [--limit N]",
         "List pending withdrawals on Clarity for the current chain,\n"
         "and the release submission state for each.",
         cmd_withdrawals},

        {"pending", "pending",
         "Show the pending deposit and withdrawal counters for the\n"
         "current chain.",
         cmd_pending},

        {"start", "start [<chain>] [--bridge-address <addr>]",
         "Start the scan worker for a chain (the current chain if no\n"
         "argument). The bridge address is required — it is the\n"
         "destination that deposits must pay to. If omitted, the\n"
         "value set when the chain was enabled is used.",
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

    std::string formatHashFull(const Crypto::Hash &h)
    {
      static const char HEX[] = "0123456789abcdef";
      std::string out = "0x";
      for (size_t i = 0; i < h.data.size(); ++i)
      {
        out.push_back(HEX[h.data[i] >> 4]);
        out.push_back(HEX[h.data[i] & 0xF]);
      }
      return out;
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
        std::cout << "configured (" << rt.bridge_deposit_address.size()
                  << " bytes)\n";

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
    ChainRuntime *rt = requireCurrent(session, "withdrawals");
    if (!rt)
      return;

    if (!session.clarity_connected)
    {
      std::cerr << "error: Clarity node is not reachable\n";
      return;
    }

    std::cout << "Pending withdrawals for " << rt->chain_short_name()
              << ":\n\n";
    std::cout << " (query not yet exposed by Clarity RPC)\n\n";
    std::cout << " Local counter: " << rt->pending_withdrawals << "\n";
    std::cout << " Chain cursor (source): " << rt->last_source_height
              << ", (clarity): " << rt->last_clarity_height << "\n";
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
    std::string bridge_address_str;
    bool bridge_address_set = false;

    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--bridge-address" && i + 1 < args.size())
      {
        bridge_address_str = args[++i];
        bridge_address_set = true;
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

    if (bridge_address_set)
    {
      std::string addr_err;
      auto decoded =
          rt->adapter->parse_deposit_address(bridge_address_str, &addr_err);
      if (!decoded.has_value())
      {
        std::cerr << "error: --bridge-address: " << addr_err << "\n";
        return;
      }
      rt->bridge_deposit_address = std::move(*decoded);
    }

    if (rt->bridge_deposit_address.empty() &&
        !rt->config.bridge_deposit_address.empty())
    {
      rt->bridge_deposit_address = rt->config.bridge_deposit_address;
    }

    if (rt->bridge_deposit_address.empty())
    {
      std::cerr << "error: no bridge address configured for "
                << rt->chain_short_name() << ".\n";
      std::cerr << "  Use: start " << rt->chain_short_name()
                << " --bridge-address <address>\n";
      std::cerr << "  Or set it in the wizard when enabling the chain.\n";
      return;
    }

    if (!rt->adapter->validate_deposit_address(rt->bridge_deposit_address))
    {
      std::cerr << "error: bridge address for " << rt->chain_short_name()
                << " is not valid for this adapter\n";
      return;
    }

    rt->adapter->set_deposit_address(rt->bridge_deposit_address);

    if (session.custody_view_key.has_value())
    {
      rt->adapter->set_deposit_ident_secret(*session.custody_view_key);
    }

    startScan(session, rt->chain_short_name());
    rt->running = true;
    rt->started_at = static_cast<int64_t>(std::time(nullptr));

    std::cout << "Started scan worker for " << rt->chain_short_name()
              << ".\n";
    if (!session.hasKeystore())
    {
      std::cout << "Deposits will be detected but not submitted — "
                   "open a keystore to enable submission.\n";
    }
    else
    {
      std::cout << "Deposits to the configured custody address will be "
                   "attested and submitted.\n";
    }
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