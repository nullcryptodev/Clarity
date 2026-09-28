// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//  GenesisHash
//
//  Computes the genesis block hash for each network (mainnet, testnet,
//  regtest) by applying the network's GenesisConfig to a fresh state
//  DB and building the genesis block.
//
//  Why this exists:
//
//  The genesis hash is a pinned constant — it must match across every
//  node on a network, because a difference means two nodes disagree
//  about block 0. Pinning it catches accidental changes to genesis
//  construction at build time. This tool regenerates the pinned values
//  after an intentional change.
//
//  Usage:
//    GenesisHash                 # all three networks, human-readable
//    GenesisHash --paste         # only the paste-ready block
//    GenesisHash --network mainnet
//    GenesisHash --network=regtest
//
//  Output discipline:
//    stdout  — the data (hashes, paste-ready block). Redirectable.
//    stderr  — progress and summary narration. Not redirectable by
//              accident; kept out of any file a user pipes stdout to.
//
//  Exit code is 0 on success, 1 on any network's failure.

#include "Core/Genesis.h"
#include "GlobalConfig.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
  namespace fs = std::filesystem;

  struct Result
  {
    std::string network_name;
    uint64_t chain_id = 0;
    std::string block_hash; // hex, no 0x
    std::string state_root; // hex, no 0x
    std::string validator_root;
    bool ok = false;
    std::string error;
  };

  // Apply the given genesis config to a temp StateDB and return the
  // resulting block hash and state root.
  //
  // Uses a per-network temp path so concurrent invocations (e.g. from
  // a build script running all three in parallel) don't collide.
  Result computeForNetwork(const std::string &name,
                           const Core::GenesisConfig &cfg)
  {
    Result r;
    r.network_name = name;
    r.chain_id = cfg.chain_id;

    fs::path tmp = fs::temp_directory_path() /
                   ("clrty_genesis_hash_" + name);
    std::error_code ec;
    fs::remove_all(tmp, ec);

    std::cerr << "  [" << name << "] applying genesis to " << tmp << "\n";

    try
    {
      State::StateDB db(tmp.string(), 64ULL * 1024 * 1024);
      State::StateAccess state(db, /*version=*/0);

      Core::applyGenesis(state, cfg);
      state.commit(0);

      std::cerr << "  [" << name << "] building genesis block\n";
      Core::Block genesis = Core::makeGenesisBlock(state, cfg);
      Crypto::Hash hash = genesis.hash();

      r.block_hash = hash.toString();
      r.state_root = genesis.header.state_root.toString();
      r.validator_root = genesis.header.validator_set_root.toString();
      r.ok = true;

      std::cerr << "  [" << name << "] done: " << r.block_hash << "\n";

      db.close();
    }
    catch (const std::exception &e)
    {
      r.ok = false;
      r.error = e.what();
      std::cerr << "  [" << name << "] ERROR: " << e.what() << "\n";
    }

    fs::remove_all(tmp, ec);
    return r;
  }

  void printHuman(const std::vector<Result> &results)
  {
    std::cout << "Genesis hashes\n";
    std::cout << "==============\n\n";

    for (const auto &r : results)
    {
      std::cout << r.network_name << ":\n";
      if (!r.ok)
      {
        std::cout << "  ERROR: " << r.error << "\n\n";
        continue;
      }
      std::cout << "  chain_id        = 0x"
                << std::hex << r.chain_id << std::dec << "\n";
      std::cout << "  block_hash      = " << r.block_hash << "\n";
      std::cout << "  state_root      = " << r.state_root << "\n";
      std::cout << "  validator_root  = " << r.validator_root << "\n";
      std::cout << "\n";
    }
  }

  // Print a one-line summary to stderr. Called after every run so the
  // user can see at a glance whether anything failed without having to
  // scan the stdout output.
  void printSummary(const std::vector<Result> &results)
  {
    size_t ok = 0;
    size_t failed = 0;
    for (const auto &r : results)
      (r.ok ? ok : failed)++;

    std::cerr << "\n";
    std::cerr << "Summary: " << ok << " succeeded, "
              << failed << " failed, "
              << results.size() << " total\n";

    if (failed > 0)
    {
      for (const auto &r : results)
      {
        if (!r.ok)
          std::cerr << "  " << r.network_name << ": " << r.error << "\n";
      }
    }
  }

  void printUsage()
  {
    std::cout
        << "Usage: GenesisHash [options]\n"
        << "\n"
        << "  --network <name>   compute only for the given network\n"
        << "                     (mainnet, testnet, regtest); may be\n"
        << "                     repeated, or use --network=<name>\n"
        << "  --quiet            suppress progress output\n"
        << "  --help, -h         this message\n"
        << "\n";
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  std::vector<std::string> want_networks;
  bool quiet = false;

  // Disable nonvital logs from mdbx.
  setenv("MDBX_LOG", "ERROR", 1);
  setenv("MDBX_DEBUG", "none", 1);
  mdbx_setup_debug(MDBX_LOG_ERROR, MDBX_DBG_NONE, nullptr);

  for (int i = 1; i < argc; ++i)
  {
    std::string arg = argv[i];

    if (arg == "--quiet")
    {
      quiet = true;
    }
    else if (arg == "--network" && i + 1 < argc)
    {
      want_networks.push_back(argv[++i]);
    }
    else if (arg.rfind("--network=", 0) == 0)
    {
      want_networks.push_back(arg.substr(10));
    }
    else if (arg == "--help" || arg == "-h")
    {
      printUsage();
      return 0;
    }
    else
    {
      std::cerr << "error: unknown argument '" << arg << "'\n\n";
      printUsage();
      return 1;
    }
  }

  // When --quiet is given, silence the progress lines but keep the
  // summary. If you want a fully silent stderr, pipe it to /dev/null.
  // We don't add a second flag for that — the shell handles it.
  std::streambuf *saved_cerr = nullptr;
  if (quiet)
    saved_cerr = std::cerr.rdbuf(nullptr);

  // Build the list of (name, config) to compute.
  struct Job
  {
    std::string name;
    Core::GenesisConfig cfg;
  };

  std::vector<Job> jobs;
  auto add_if_wanted = [&](const std::string &name,
                           Core::GenesisConfig cfg)
  {
    if (want_networks.empty() ||
        std::find(want_networks.begin(), want_networks.end(), name) !=
            want_networks.end())
    {
      jobs.push_back({name, std::move(cfg)});
    }
  };

  add_if_wanted("mainnet", Core::mainnetGenesis());
  add_if_wanted("testnet", Core::testnetGenesis());
  add_if_wanted("regtest", Core::regtestGenesis());

  if (jobs.empty())
  {
    if (saved_cerr)
      std::cerr.rdbuf(saved_cerr);
    std::cerr << "error: no networks matched the requested filter\n";
    return 1;
  }

  std::cerr << "Computing genesis hashes for "
            << jobs.size() << " network(s)\n";

  std::vector<Result> results;
  results.reserve(jobs.size());

  bool any_failed = false;
  for (auto &j : jobs)
  {
    Result r = computeForNetwork(j.name, j.cfg);
    if (!r.ok)
      any_failed = true;
    results.push_back(std::move(r));
  }

  // Restore stderr before the summary, so the summary is always
  // visible even with --quiet.
  if (saved_cerr)
    std::cerr.rdbuf(saved_cerr);

  printSummary(results);

  printHuman(results);

  std::cout << "\n";

  return any_failed ? 1 : 0;
}