// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Startup.h"

#include "Common/PasswordPrompt.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/RpcClient.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace Wallet
{

  namespace fs = std::filesystem;

  // ===========================================================================
  //  Input helpers
  // ===========================================================================

  namespace
  {
    //  Read a line of input from stdin, with a prompt. Runs before
    //  the linenoise REPL starts, so plain std::getline is used.
    //  The prompt goes to stderr so stdout stays clean for piping.
    //
    //  Returns std::nullopt on EOF (Ctrl+D).
    std::optional<std::string> readInput(const char *prompt)
    {
      std::fputs(prompt, stderr);
      std::fflush(stderr);

      std::string line;
      if (!std::getline(std::cin, line))
        return std::nullopt;

      return line;
    }

    std::string trim(const std::string &s)
    {
      size_t start = 0;
      while (start < s.size() &&
             (s[start] == ' ' || s[start] == '\t' ||
              s[start] == '\r' || s[start] == '\n'))
        ++start;

      size_t end = s.size();
      while (end > start &&
             (s[end - 1] == ' ' || s[end - 1] == '\t' ||
              s[end - 1] == '\r' || s[end - 1] == '\n'))
        --end;

      return s.substr(start, end - start);
    }

    void printRule()
    {
      std::cout << "───────────────────────────────────────────────\n";
    }

    void section(const char *title)
    {
      std::cout << "\n"
                << title << "\n";
    }

    //  Expand a leading "~" to the user's home directory. Returns
    //  the input unchanged if it doesn't start with "~", or if HOME
    //  isn't set.
    std::string expandHome(const std::string &path)
    {
      if (path.empty() || path[0] != '~')
        return path;

      const char *home = std::getenv("HOME");
      if (home == nullptr)
        return path;

      return std::string(home) + path.substr(1);
    }
  } // anonymous namespace

  // ===========================================================================
  //  Keystore discovery
  // ===========================================================================

  namespace
  {
    struct DiscoveredKeystore
    {
      std::string path;
      std::string address;
      Network network;
    };

    enum class ProbeResult
    {
      Ok,
      NotFound,
      NotAKeystore,
    };

    //  Probe a path to see whether it's a keystore. Returns Ok on
    //  success, NotFound if the file doesn't exist, NotAKeystore if
    //  it exists but doesn't parse.
    ProbeResult probeKeystore(const std::string &path, DiscoveredKeystore &out)
    {
      std::error_code ec;
      if (!fs::is_regular_file(path, ec) || ec)
        return ProbeResult::NotFound;

      //  Keystores are tiny — a few KB. If the file is larger than
      //  a megabyte, it isn't a keystore; skip the parse.
      const auto size = fs::file_size(path, ec);
      if (ec || size > 1024 * 1024)
        return ProbeResult::NotAKeystore;

      WalletStatus st;
      auto ks = EncryptedKeyStore::open(path, &st);
      if (!ks.has_value())
        return ProbeResult::NotAKeystore;

      out.path = path;
      out.address = (*ks)->address();
      out.network = (*ks)->network();
      return ProbeResult::Ok;
    }

    //  Scan a directory for keystores. Every regular file is tried;
    //  the extension is not considered. This handles the case where
    //  a keystore was saved without an extension — either by an
    //  older version of the Address tool, or by a user who renamed
    //  the file.
    std::vector<DiscoveredKeystore> discoverKeystoresIn(
        const std::string &directory)
    {
      std::vector<DiscoveredKeystore> found;

      std::error_code ec;
      for (const auto &entry : fs::directory_iterator(directory, ec))
      {
        if (ec)
          break;
        if (!entry.is_regular_file())
          continue;

        DiscoveredKeystore dk;
        if (probeKeystore(entry.path().string(), dk) == ProbeResult::Ok)
          found.push_back(std::move(dk));
      }

      std::sort(found.begin(), found.end(),
                [](const DiscoveredKeystore &a, const DiscoveredKeystore &b)
                {
                  return a.path < b.path;
                });

      return found;
    }

    std::vector<DiscoveredKeystore> discoverKeystores()
    {
      return discoverKeystoresIn(fs::current_path().string());
    }
  } // anonymous namespace

  // ===========================================================================
  //  RPC connection
  // ===========================================================================

  namespace
  {
    bool probeConnection(RpcClient &rpc)
    {
      Common::Json params = Common::Json::object();
      auto result = rpc.call("chainId", params);
      return result.ok();
    }

    bool parseEndpointSpec(const std::string &spec, RpcEndpoint &out)
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

      out.host = host;
      out.port = static_cast<uint16_t>(port);
      return true;
    }

    std::optional<RpcEndpoint> promptForEndpoint()
    {
      auto line = readInput("Endpoint (host:port): ");
      if (!line.has_value())
        return std::nullopt;

      RpcEndpoint ep;
      if (!parseEndpointSpec(trim(*line), ep))
      {
        std::cerr << "  Invalid format. Expected host:port.\n";
        return std::nullopt;
      }
      return ep;
    }
  } // anonymous namespace

  // ===========================================================================
  //  Step 1: RPC connection
  // ===========================================================================

  namespace
  {
    bool stepConnect(WalletSession &session, const std::string &rpc_spec)
    {
      section("RPC connection");

      if (!rpc_spec.empty())
      {
        RpcEndpoint ep;
        if (!parseEndpointSpec(rpc_spec, ep))
        {
          std::cerr << "  Invalid --rpc spec: " << rpc_spec << "\n";
          return false;
        }
        session.rpc_endpoint = ep;
      }

      if (!session.rpc)
        session.rpc = std::make_unique<RpcClient>(session.rpc_endpoint);

      while (true)
      {
        std::cout << "Connecting to " << session.rpc_endpoint.host
                  << ":" << session.rpc_endpoint.port << "...\n";

        if (probeConnection(*session.rpc))
        {
          std::cout << "  Connected.\n";
          session.rpc_connected = true;
          return true;
        }

        std::cout << "  Could not connect.\n\n";
        std::cout << "  [r] Retry\n";
        std::cout << "  [c] Connect to a different endpoint\n";
        std::cout << "  [s] Skip — continue offline\n";

        auto choice = readInput("Choice [r/c/s]: ");
        if (!choice.has_value())
          return false;

        std::string c = trim(*choice);
        if (c == "r" || c == "R" || c.empty())
        {
          continue;
        }
        if (c == "c" || c == "C")
        {
          auto ep = promptForEndpoint();
          if (ep.has_value())
          {
            session.rpc_endpoint = *ep;
            session.rpc = std::make_unique<RpcClient>(session.rpc_endpoint);
          }
          continue;
        }
        if (c == "s" || c == "S" || c == "skip")
        {
          std::cout << "  Continuing offline. Use 'connect host:port' "
                       "when ready.\n";
          session.rpc_connected = false;
          return true;
        }

        std::cerr << "  Unrecognized choice. Try again.\n";
      }
    }
  } // anonymous namespace

  // ===========================================================================
  //  Step 2: Keystore selection
  // ===========================================================================

  namespace
  {
    //  Prompt for a keystore path. Handles a leading "~", and if the
    //  path is a directory, scans inside it and prompts for which
    //  keystore.
    //
    //  Returns the chosen path, or an empty string if the user
    //  cancelled, or nullopt on EOF.
    std::optional<std::string> promptForKeystorePath()
    {
      auto line = readInput("Keystore path: ");
      if (!line.has_value())
        return std::nullopt;

      std::string path = expandHome(trim(*line));
      if (path.empty())
        return std::string();

      //  If the path is a directory, scan inside it.
      std::error_code ec;
      if (fs::is_directory(path, ec) && !ec)
      {
        auto found = discoverKeystoresIn(path);

        if (found.empty())
        {
          std::cerr << "  No keystores found in " << path << "\n";
          return std::string();
        }

        if (found.size() == 1)
        {
          std::cout << "  Found one keystore: " << found[0].path << "\n";
          return found[0].path;
        }

        std::cout << "  Found " << found.size() << " keystores in "
                  << path << ":\n\n";
        for (size_t i = 0; i < found.size(); ++i)
        {
          std::cout << "    [" << (i + 1) << "] " << found[i].path << "\n";
          std::cout << "        " << found[i].address << "\n";
        }
        std::cout << "\n";

        auto choice = readInput("  Choice: ");
        if (!choice.has_value())
          return std::nullopt;

        const std::string c = trim(*choice);
        char *end = nullptr;
        const unsigned long idx = std::strtoul(c.c_str(), &end, 10);
        if (end != c.c_str() && *end == '\0' &&
            idx >= 1 && idx <= found.size())
        {
          return found[idx - 1].path;
        }

        std::cerr << "  Invalid choice.\n";
        return std::string();
      }

      return path;
    }

    //  Show a list of discovered keystores and let the user pick one.
    //  Returns the selected path, an empty string on cancel, or
    //  nullopt on EOF.
    std::optional<std::string> promptKeystoreChoice(
        const std::vector<DiscoveredKeystore> &found)
    {
      std::cout << "Found " << found.size() << " keystore"
                << (found.size() == 1 ? "" : "s") << " in "
                << fs::current_path().string() << ":\n\n";

      for (size_t i = 0; i < found.size(); ++i)
      {
        std::cout << "  [" << (i + 1) << "] "
                  << found[i].path << "\n";
        std::cout << "      " << found[i].address
                  << " (" << networkName(found[i].network) << ")\n";
      }

      std::cout << "\n";
      std::cout << "  [o] Open a different path\n";
      std::cout << "  [s] Skip — no keystore for now\n";

      auto line = readInput("Choice: ");
      if (!line.has_value())
        return std::nullopt;

      std::string c = trim(*line);
      if (c.empty())
        return std::string();

      char *end = nullptr;
      const unsigned long idx = std::strtoul(c.c_str(), &end, 10);
      if (end != c.c_str() && *end == '\0' &&
          idx >= 1 && idx <= found.size())
      {
        return found[idx - 1].path;
      }

      if (c == "o" || c == "O")
      {
        auto path = promptForKeystorePath();
        if (!path.has_value())
          return std::nullopt;
        return *path;
      }

      if (c == "s" || c == "S" || c == "skip")
      {
        return std::string();
      }

      std::cerr << "  Unrecognized choice.\n";
      return std::string();
    }

    std::optional<std::string> selectKeystore()
    {
      auto found = discoverKeystores();

      if (found.empty())
      {
        section("Keystore");

        std::cout << "No keystores found in "
                  << fs::current_path().string() << ".\n\n";
        std::cout << "  [o] Open a keystore by path\n";
        std::cout << "  [s] Skip — no keystore for now\n";

        auto line = readInput("Choice [o/s]: ");
        if (!line.has_value())
          return std::nullopt;

        std::string c = trim(*line);
        if (c == "o" || c == "O" || c == "open")
        {
          return promptForKeystorePath();
        }
        if (c == "s" || c == "S" || c == "skip" || c.empty())
        {
          return std::string();
        }

        std::cerr << "  Unrecognized choice.\n";
        return std::string();
      }

      section("Keystore");
      return promptKeystoreChoice(found);
    }
  } // anonymous namespace

  // ===========================================================================
  //  Step 3: Confirm keystore
  // ===========================================================================

  namespace
  {
    std::optional<bool> confirmKeystore(const std::string &path)
    {
      DiscoveredKeystore dk;
      const ProbeResult result = probeKeystore(path, dk);

      switch (result)
      {
      case ProbeResult::NotFound:
      {
        std::error_code ec;
        if (fs::is_directory(path, ec) && !ec)
        {
          std::cerr << "  Path is a directory: " << path << "\n";
          std::cerr << "  Provide the path to a keystore file, or a "
                       "directory containing keystores.\n";
        }
        else
        {
          std::cerr << "  No such file: " << path << "\n";
        }
        return false;
      }

      case ProbeResult::NotAKeystore:
        std::cerr << "  Not a valid keystore: " << path << "\n";
        std::cerr << "  (File exists but is not an encrypted CLRTY "
                     "keystore.)\n";
        return false;

      case ProbeResult::Ok:
        break;
      }

      std::cout << "\n";
      std::cout << "  Path:     " << dk.path << "\n";
      std::cout << "  Address:  " << dk.address << "\n";
      std::cout << "  Network:  " << networkName(dk.network) << "\n";

      auto line = readInput("\nUse this keystore? [y/n]: ");
      if (!line.has_value())
        return std::nullopt;

      std::string c = trim(*line);
      return (c == "y" || c == "Y" || c == "yes" || c.empty());
    }
  } // anonymous namespace

  // ===========================================================================
  //  Step 4: Unlock
  // ===========================================================================

  namespace
  {
    std::optional<bool> unlockKeystore(WalletSession &session,
                                       const std::string &path,
                                       const std::string &password_file)
    {
      WalletStatus st;
      auto ks = EncryptedKeyStore::open(path, &st);
      if (!ks.has_value())
      {
        std::cerr << "  Cannot open keystore: ";
        if (!st.detail.empty())
          std::cerr << st.detail;
        else
          std::cerr << walletErrorMessage(st.code);
        std::cerr << "\n";
        return false;
      }

      std::string password;
      if (!password_file.empty())
      {
        auto pw = Apps::readPasswordFile(password_file);
        if (!pw.has_value())
        {
          std::cerr << "  Cannot read password file: "
                    << password_file << "\n";
          return false;
        }
        password = *pw;
      }
      else
      {
        auto pw = Apps::promptForPassword("  Keystore password: ");
        if (!pw.has_value())
          return std::nullopt;
        password = *pw;
      }

      const WalletError err = (*ks)->unlock(password);
      if (!password.empty())
      {
        for (auto &c : password)
          c = '\0';
      }

      if (err != WalletError::Ok)
      {
        WalletStatus unlock_err = WalletStatus::fail(err, "");
        std::cerr << "  Wrong password.";
        if (!unlock_err.detail.empty())
          std::cerr << " " << unlock_err.detail;
        std::cerr << "\n";
        return false;
      }

      auto from_addr = decodeAddress((*ks)->address(), (*ks)->network());
      if (!from_addr.has_value())
      {
        std::cerr << "  Keystore address is not decodable: "
                  << (*ks)->address() << "\n";
        return false;
      }

      session.keystore_path = path;
      session.keystore = std::move(*ks);
      session.signer = std::make_unique<LocalSigner>(*session.keystore);
      session.address = *from_addr;
      session.address_bech32m = session.keystore->address();
      session.network = session.keystore->network();

      std::cout << "  Unlocked " << path
                << " (" << session.address_bech32m
                << ") — " << networkName(session.currentNetwork()) << "\n";
      return true;
    }
  } // anonymous namespace

  // ===========================================================================
  //  Summary banner
  // ===========================================================================

  namespace
  {
    void printSummaryBanner(const WalletSession &session)
    {
      std::cout << "\n";
      printRule();
      std::cout << "Clarity wallet\n\n";

      if (session.hasKeystore())
      {
        std::cout << "  Address:    " << session.address_bech32m << "\n";
        std::cout << "  Network:    "
                  << networkName(session.currentNetwork()) << "\n";
        std::cout << "  Chain ID:   0x" << std::hex << session.chainId()
                  << std::dec << "\n";
      }
      else
      {
        std::cout << "  (no keystore open)\n";
      }

      if (session.rpc_connected)
      {
        std::cout << "  RPC:        connected to "
                  << session.rpc_endpoint.host << ":"
                  << session.rpc_endpoint.port << "\n";
      }
      else
      {
        std::cout << "  RPC:        offline (use 'connect host:port')\n";
      }

      std::cout << "\nType 'help' for commands, 'exit' to quit.\n";
      printRule();
      std::cout << "\n";
    }
  } // anonymous namespace

  // ===========================================================================
  //  The wizard
  // ===========================================================================

  bool runStartupWizard(WalletSession &session,
                        const StartupOptions &options)
  {
    printRule();
    std::cout << "Clarity wallet — setup\n";

    //  ---- Step 1: RPC connection ----
    if (!stepConnect(session, options.rpc_spec))
      return false;

    //  ---- If a keystore was provided, skip the wizard and open it ----
    if (!options.keystore_path.empty())
    {
      std::cout << "\nOpening provided keystore: "
                << options.keystore_path << "\n";

      while (true)
      {
        auto result = unlockKeystore(session,
                                     options.keystore_path,
                                     options.password_file);
        if (!result.has_value())
          return false;

        if (*result)
          break;

        std::cout << "\n  [r] Retry password\n";
        std::cout << "  [a] Abort — run the wallet without a keystore\n";

        auto line = readInput("Choice [r/a]: ");
        if (!line.has_value())
          return false;

        std::string c = trim(*line);
        if (c == "a" || c == "A" || c == "abort")
        {
          std::cout << "  Continuing without a keystore.\n";
          break;
        }
        //  Retry is the default.
      }

      printSummaryBanner(session);
      return true;
    }

    //  ---- Step 2: Keystore discovery ----
    std::string chosen_path;

    while (true)
    {
      auto result = selectKeystore();
      if (!result.has_value())
        return false;

      chosen_path = *result;
      if (chosen_path.empty())
      {
        std::cout << "\n  No keystore opened. You can use 'open <path>' "
                     "later.\n";
        break;
      }

      //  ---- Step 3: Confirm ----
      auto confirmed = confirmKeystore(chosen_path);
      if (!confirmed.has_value())
        return false;

      if (!*confirmed)
      {
        continue;
      }

      //  ---- Step 4: Unlock ----
      auto unlock_result = unlockKeystore(session, chosen_path, "");
      if (!unlock_result.has_value())
        return false;

      if (*unlock_result)
        break;

      //  Unlock failed. Offer retry or back to keystore selection.
      std::cout << "\n  [r] Retry password\n";
      std::cout << "  [b] Back to keystore selection\n";

      auto line = readInput("Choice [r/b]: ");
      if (!line.has_value())
        return false;

      std::string c = trim(*line);
      if (c == "b" || c == "B" || c == "back")
      {
        continue;
      }
      //  Retry is the default.
      auto retry = unlockKeystore(session, chosen_path, "");
      if (!retry.has_value())
        return false;
      if (*retry)
        break;
    }

    //  ---- Step 5: Summary ----
    printSummaryBanner(session);
    return true;
  }

} // namespace Wallet