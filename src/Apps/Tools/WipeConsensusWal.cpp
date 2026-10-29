// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//  WipeConsensusWal — operator recovery tool
//
//  Deletes every row in TBL_CONSENSUS_WAL from an existing StateDB.
//
//  This is the recovery path for a chain that is stuck because the
//  consensus WAL replayed enough votes to push consecutive_timeouts_
//  past EMERGENCY_ROTATION_ROUNDS, at which point useEmergencySet()
//  returns true and the emergency path is blocked by
//  committed.size() < 4. Restarting the daemon does NOT recover: the
//  WAL is only wiped from Node::initGenesis, which returns early on
//  an already-initialized DB.
//
//  Usage:
//
//    WipeConsensusWal <state-dir> [--apply] [--map-size N]
//
//  <state-dir> is the directory that contains the MDBX environment
//  files (mdbx.dat / mdbx.lck, or data.mdb / lock.mdb depending on
//  the MDBX build). For a daemon started with --data-dir <d>, that
//  is <d>/state.
//
//  Default is a dry run: it opens the DB, reports how many WAL
//  entries are present and which heights they span, and exits
//  without modifying anything.
//
//  Pass --apply to actually delete the rows.
//
//  The daemon MUST be stopped. MDBX takes an exclusive write lock on
//  the environment; if the daemon is running, either the open fails
//  with a MDBX_BUSY-family error, or (worse) a concurrent write
//  corrupts state. This tool cannot detect a running daemon on its
//  own; it can only surface MDBX's refusal. Verify with pgrep before
//  running --apply.
//
//  Exit codes:
//    0  success (dry run, or wipe applied and verified)
//    1  bad arguments
//    2  DB open failed (missing DB, locked by another process, etc.)
//    3  wipe applied but post-wipe verification found residual rows
//    4  unexpected exception
//
//  Output discipline:
//    stdout — the report (counts, height range, verification result)
//    stderr — errors, warnings, and the "daemon must be stopped" hint

#include "State/StateDB.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace
{
  constexpr size_t DEFAULT_MAP_SIZE = 1ULL << 34; // matches NodeConfig

  constexpr uint32_t WAL_KIND_VOTE = 0;
  constexpr uint32_t WAL_KIND_LOCK = 1;

  //  The MDBX environment files. Which pair exists depends on whether
  //  the linked MDBX was built with MDBX_NOSUBDIR. Checking for both
  //  means the tool works regardless.
  const char *const MDBX_DATA_FILES[] = {
      "mdbx.dat", // default (subdir layout)
      "data.mdb", // MDBX_NOSUBDIR layout
  };

  struct WalSummary
  {
    size_t total = 0;
    size_t votes = 0;
    size_t locks = 0;
    size_t malformed = 0; // keys shorter than 12 bytes, or unknown kind
    uint64_t min_height = UINT64_MAX;
    uint64_t max_height = 0;
    std::set<uint64_t> heights; // distinct heights
  };

  //  WAL key layout, from Node::walVoteKey / Node::walLockKey:
  //
  //    height(8 BE) || kind(4 BE) || round(8 BE) [|| signer_id(8 BE)]
  //
  //  The summary only needs height and kind; it does not decode the
  //  round or signer fields, because it does not replay anything.
  uint64_t readU64BE(const uint8_t *p)
  {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v = (v << 8) | p[i];
    return v;
  }

  uint32_t readU32BE(const uint8_t *p)
  {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
  }

  WalSummary summarizeWal(State::StateDB &db)
  {
    WalSummary s;

    db.forEachEntry(State::StateDB::TBL_CONSENSUS_WAL,
                    [&](const std::vector<uint8_t> &key,
                        const std::vector<uint8_t> &) -> bool
                    {
                      ++s.total;

                      if (key.size() < 12)
                      {
                        ++s.malformed;
                        return true;
                      }

                      const uint64_t h = readU64BE(key.data());
                      const uint32_t kind = readU32BE(key.data() + 8);

                      if (h < s.min_height)
                        s.min_height = h;
                      if (h > s.max_height)
                        s.max_height = h;
                      s.heights.insert(h);

                      switch (kind)
                      {
                      case WAL_KIND_VOTE:
                        ++s.votes;
                        break;
                      case WAL_KIND_LOCK:
                        ++s.locks;
                        break;
                      default:
                        ++s.malformed;
                        break;
                      }

                      return true;
                    });

    if (s.total == 0)
    {
      s.min_height = 0;
      s.max_height = 0;
    }
    return s;
  }

  void printSummary(const WalSummary &s)
  {
    std::cout << "  consensus_wal entries : " << s.total << "\n";

    if (s.total == 0)
    {
      std::cout << "  (table is empty)\n";
      return;
    }

    std::cout << "  votes                 : " << s.votes << "\n";
    std::cout << "  locks                 : " << s.locks << "\n";
    if (s.malformed != 0)
      std::cout << "  malformed / unknown   : " << s.malformed << "\n";

    std::cout << "  heights               : " << s.heights.size()
              << " distinct, " << s.min_height
              << " .. " << s.max_height << "\n";

    //  Print the height list if it is short enough to be useful. A
    //  normally-stuck chain has one height (the one that could not
    //  commit); a WAL that spans many heights suggests the daemon is
    //  not actually stuck and the wipe is unnecessary.
    if (s.heights.size() <= 16)
    {
      std::cout << "  heights (list)        : ";
      bool first = true;
      for (uint64_t h : s.heights)
      {
        if (!first)
          std::cout << ", ";
        std::cout << h;
        first = false;
      }
      std::cout << "\n";
    }
  }

  //  Return the path to the MDBX data file inside `dir`, or an empty
  //  path if neither expected layout is present.
  std::filesystem::path findMdbxDataFile(const std::string &dir)
  {
    namespace fs = std::filesystem;
    const fs::path base(dir);
    for (const char *name : MDBX_DATA_FILES)
    {
      const fs::path candidate = base / name;
      if (fs::exists(candidate))
        return candidate;
    }
    return {};
  }

  void printUsage()
  {
    std::cout
        << "Usage: WipeConsensusWal <state-dir> [--apply] [--map-size N]\n"
        << "\n"
        << "Deletes every row in TBL_CONSENSUS_WAL from an existing StateDB.\n"
        << "This is the recovery path for a chain stuck in emergency rotation\n"
        << "because the WAL keeps replaying votes past EMERGENCY_ROTATION_ROUNDS.\n"
        << "\n"
        << "Arguments:\n"
        << "  <state-dir>       directory containing the MDBX environment files\n"
        << "                    (mdbx.dat/mdbx.lck, or data.mdb/lock.mdb).\n"
        << "                    For a daemon started with --data-dir <d>, this\n"
        << "                    is <d>/state.\n"
        << "\n"
        << "Options:\n"
        << "  --apply           actually delete the rows. Without it, the tool\n"
        << "                    is a dry run and modifies nothing.\n"
        << "  --map-size N      MDBX map size in bytes (default: 17179869184,\n"
        << "                    matching NodeConfig::state_map_size).\n"
        << "\n"
        << "The daemon must be stopped. MDBX takes an exclusive write lock on\n"
        << "the environment; a running daemon will either make the open fail\n"
        << "or, worse, race with the wipe. Verify with pgrep first.\n"
        << "\n"
        << "Exit codes: 0 ok, 1 bad args, 2 open failed, 3 verify failed,\n"
        << "            4 unexpected exception.\n";
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  std::string state_dir;
  bool apply = false;
  size_t map_size = DEFAULT_MAP_SIZE;

  for (int i = 1; i < argc; ++i)
  {
    std::string a = argv[i];

    if (a == "--help" || a == "-h")
    {
      printUsage();
      return 0;
    }
    if (a == "--apply")
    {
      apply = true;
      continue;
    }
    if (a == "--map-size" && i + 1 < argc)
    {
      try
      {
        map_size = static_cast<size_t>(std::stoull(argv[++i], nullptr, 0));
      }
      catch (const std::exception &)
      {
        std::cerr << "error: --map-size expects a number, got '"
                  << argv[i] << "'\n";
        return 1;
      }
      continue;
    }
    if (!a.empty() && a[0] == '-')
    {
      std::cerr << "error: unknown option '" << a << "'\n";
      return 1;
    }
    if (!state_dir.empty())
    {
      std::cerr << "error: more than one state-dir given ('"
                << state_dir << "' and '" << a << "')\n";
      return 1;
    }
    state_dir = a;
  }

  if (state_dir.empty())
  {
    std::cerr << "error: <state-dir> is required\n\n";
    printUsage();
    return 1;
  }

  //  Refuse to create a new empty DB at a wrong path. StateDB's
  //  constructor calls create_directories() and then mdbx_env_open(),
  //  which will happily create an empty environment if the directory
  //  exists but no DB file does. For a recovery tool that is exactly
  //  the wrong behavior: it silently "succeeds" against a path that
  //  was never a chain DB, and the operator walks away thinking the
  //  wipe worked. Check for the MDBX data file first.
  {
    const std::filesystem::path db_file = findMdbxDataFile(state_dir);
    if (db_file.empty())
    {
      std::cerr << "error: no MDBX database in " << state_dir << "\n";
      std::cerr << "  expected one of:";
      for (const char *name : MDBX_DATA_FILES)
        std::cerr << " " << name;
      std::cerr << "\n";
      std::cerr << "  The daemon puts its StateDB at <data-dir>/state/.\n";
      std::cerr << "  Refusing to create a new empty DB at this path.\n";
      return 2;
    }
  }

  std::cout << "WipeConsensusWal\n";
  std::cout << "  state dir : " << state_dir << "\n";
  std::cout << "  mode      : " << (apply ? "APPLY (will delete)" : "dry run")
            << "\n";
  std::cout << "\n";

  try
  {
    State::StateDB db(state_dir, map_size);

    std::cout << "Opened StateDB.\n\n";

    const WalSummary before = summarizeWal(db);

    std::cout << "Before:\n";
    printSummary(before);
    std::cout << "\n";

    if (before.total == 0)
    {
      std::cout << "Nothing to do.\n";
      return 0;
    }

    if (!apply)
    {
      std::cout << "Dry run: no rows modified.\n";
      std::cout << "Re-run with --apply to delete the "
                << before.total << " entries above.\n";
      return 0;
    }

    std::cout << "Wiping consensus WAL...\n";
    db.wipeConsensusWal();
    db.flush();

    const WalSummary after = summarizeWal(db);

    std::cout << "\nAfter:\n";
    printSummary(after);
    std::cout << "\n";

    if (after.total != 0)
    {
      std::cerr << "error: wipe reported success but "
                << after.total << " entries remain\n";
      return 3;
    }

    std::cout << "Wipe verified: consensus_wal is empty.\n";
    return 0;
  }
  catch (const State::StateDBError &e)
  {
    std::cerr << "error: StateDB: " << e.what() << "\n";
    std::cerr << "\n";
    std::cerr << "If this says the DB is busy, the daemon is still running.\n";
    std::cerr << "Stop it and re-run.\n";
    return 2;
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: " << e.what() << "\n";
    return 4;
  }
}