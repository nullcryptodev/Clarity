// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Commands.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/TransactionBuilder.h"
#include "Wallet/WalletOperations.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace Wallet
{

  // ===========================================================================
  //  Command table
  // ===========================================================================

  namespace
  {
    const Command kCommands[] = {
        {"balance", "balance [address]",
         "Show the balance of an address, or of the open keystore's address.",
         cmd_balance},

        {"nonce", "nonce [address]",
         "Show the current nonce of an address, or of the open keystore's address.",
         cmd_nonce},

        {"info", "info",
         "Show details about the currently-open keystore.",
         cmd_info},

        {"status", "status [txid]",
         "Show the receipt for a transaction. With no argument, uses the\n"
         "last txid submitted in this session.",
         cmd_status},

        {"send", "send <to> <amount> <fee> [--token <id>] [--wait] [--dry-run]",
         "Build, sign, and submit a transfer. Amounts are in CLRTY (e.g.\n"
         "100 or 0.001). With --wait, poll until the transaction is\n"
         "confirmed or the timeout expires.",
         cmd_send},

        {"claim", "claim <fee> [--wait]",
         "Claim pending staking rewards into the account balance.",
         cmd_claim},

        {"stake", "stake <opt-in|opt-out> <fee> [--wait]",
         "Toggle auto-staking for this account.",
         cmd_stake},

        {"validator",
         "validator <info|register|update-reward|unregister> ...",
         "Validator operations:\n"
         "  validator info\n"
         "  validator register <node-key-hex> <stake> <fee> [--wait]\n"
         "  validator update-reward <new-address> <fee> [--wait]\n"
         "  validator unregister <fee> [--wait]",
         cmd_validator},

        {"open", "open <path> [--password-file <path>]",
         "Open and unlock a keystore.",
         cmd_open},

        {"close", "close",
         "Lock and close the currently-open keystore.",
         cmd_close},

        {"connect", "connect <host:port>",
         "Change the RPC endpoint.",
         cmd_connect},

        {"help", "help [command]",
         "Show help. With no argument, lists all commands.",
         cmd_help},

        {"exit", "exit",
         "Exit the wallet.",
         cmd_exit},

        {"quit", "quit",
         "Exit the wallet.",
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

  // ===========================================================================
  //  Tokenizer
  // ===========================================================================

  std::vector<std::string> tokenizeCommand(const std::string &line)
  {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok)
      tokens.push_back(std::move(tok));
    return tokens;
  }

  // ===========================================================================
  //  Dispatch
  // ===========================================================================

  bool dispatchCommand(WalletSession &session,
                       const std::vector<std::string> &tokens)
  {
    if (tokens.empty())
      return true; // empty line: no-op

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

  // ===========================================================================
  //  Helpers (anonymous namespace)
  // ===========================================================================

  namespace
  {
    //  ---- Parsing ----

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

    std::optional<Crypto::Address> parseAddress(WalletSession &session,
                                                const std::string &s,
                                                const char *flag)
    {
      auto addr = Wallet::decodeAddress(s, session.currentNetwork());
      if (!addr.has_value())
        std::cerr << "error: " << flag
                  << ": not a valid address for this network: " << s << "\n";
      return addr;
    }

    std::optional<Crypto::PublicKey> parsePublicKeyHex(const std::string &s,
                                                       const char *flag)
    {
      if (s.size() != 64)
      {
        std::cerr << "error: " << flag << ": must be 64 hex characters\n";
        return std::nullopt;
      }

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

      Crypto::PublicKey pk;
      for (size_t i = 0; i < 32; ++i)
      {
        const int hi = nib(s[i * 2]);
        const int lo = nib(s[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
          std::cerr << "error: " << flag
                    << ": contains non-hex characters\n";
          return std::nullopt;
        }
        pk.data[i] = static_cast<uint8_t>((hi << 4) | lo);
      }
      return pk;
    }

    //  ---- Error reporting ----

    void reportWalletError(const char *prefix, const WalletStatus &st)
    {
      std::cerr << "error: " << prefix << ": ";
      if (!st.detail.empty())
        std::cerr << st.detail;
      else
        std::cerr << walletErrorMessage(st.code);
      std::cerr << "\n";
    }

    //  Report a failed transaction submission. Distinguishes a
    //  transport failure (couldn't reach the node) from an RPC
    //  rejection (the node accepted the connection but refused the
    //  transaction).
    void reportSubmitFailure(const std::string &message)
    {
      std::cerr << "error: submission failed: " << message << "\n";
    }

    //  ---- Preconditions ----

    bool requireKeystore(WalletSession &session)
    {
      if (!session.hasKeystore())
      {
        std::cerr << "error: no keystore open. Use 'open <path>' first.\n";
        return false;
      }
      if (!session.rpc)
      {
        std::cerr << "error: no RPC connection\n";
        return false;
      }
      return true;
    }

    bool requireRpc(WalletSession &session)
    {
      if (!session.rpc)
      {
        std::cerr << "error: no RPC connection\n";
        return false;
      }
      return true;
    }

    //  ---- Common flags ----

    struct CommonFlags
    {
      bool wait{false};
      bool dry_run{false};
      uint32_t token_id{0};
      std::string password_file;
    };

    //  Parse common flags starting at `start_index`. Positional
    //  arguments are appended to `positional`. Returns false if an
    //  unknown flag was seen or a flag was missing its value.
    bool parseCommonFlags(const std::vector<std::string> &args,
                          size_t start_index,
                          CommonFlags &out,
                          std::vector<std::string> &positional)
    {
      for (size_t i = start_index; i < args.size(); ++i)
      {
        const std::string &a = args[i];

        if (a == "--wait")
        {
          out.wait = true;
        }
        else if (a == "--dry-run")
        {
          out.dry_run = true;
        }
        else if (a == "--token")
        {
          if (i + 1 >= args.size())
          {
            std::cerr << "error: --token requires a value\n";
            return false;
          }
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --token: invalid integer\n";
            return false;
          }
          out.token_id = static_cast<uint32_t>(*v);
        }
        else if (a == "--password-file")
        {
          if (i + 1 >= args.size())
          {
            std::cerr << "error: --password-file requires a value\n";
            return false;
          }
          out.password_file = args[++i];
        }
        else if (!a.empty() && a[0] == '-')
        {
          std::cerr << "error: unknown flag '" << a << "'\n";
          return false;
        }
        else
        {
          positional.push_back(a);
        }
      }
      return true;
    }

    //  ---- Nonce fetch + transaction submit ----

    //  Fetch the account's current nonce, printing an error on
    //  failure and returning nullopt.
    std::optional<uint64_t> fetchNonce(WalletSession &session)
    {
      std::string err;
      auto nonce = Wallet::getNonce(*session.rpc, session.address_bech32m, &err);
      if (!nonce.has_value())
      {
        std::cerr << "error: cannot fetch nonce: " << err << "\n";
        return std::nullopt;
      }
      return nonce;
    }

    //  Sign a built transaction with the session's signer. Prints an
    //  error on failure and returns false. On success, tx is signed
    //  in place.
    bool signBuiltTransaction(WalletSession &session, Core::Transaction &tx)
    {
      WalletStatus st;
      auto signing_hash = Wallet::signTransaction(
          tx, *session.signer, Wallet::clrtyPath(0, 0, 0), &st);

      if (!signing_hash.has_value())
      {
        reportWalletError("cannot sign transaction", st);
        return false;
      }
      return true;
    }

    //  Submit a signed transaction, optionally wait for confirmation,
    //  and report the outcome. Updates the session's last_txid.
    //
    //  Uses the ReceiptOutcome from waitForReceipt so that a
    //  committed-but-failed transaction is reported honestly rather
    //  than as "Confirmed."
    void submitAndReport(WalletSession &session,
                         const Core::Transaction &signed_tx,
                         bool wait)
    {
      std::string submit_err;
      auto txid = Wallet::submitSigned(*session.rpc, signed_tx, &submit_err);

      if (!txid.has_value())
      {
        reportSubmitFailure(submit_err);
        return;
      }

      session.last_txid_hex = *txid;
      std::cout << "Submitted: " << *txid << "\n";

      if (!wait)
        return;

      std::cout << "Waiting for confirmation...\n";
      std::string wait_err;
      auto outcome = Wallet::waitForReceipt(
          *session.rpc, *txid, std::chrono::seconds(60), &wait_err);

      if (!outcome.has_value())
      {
        std::cerr << "error: " << wait_err << "\n";
        return;
      }

      switch (outcome->kind)
      {
      case Wallet::ReceiptOutcome::Kind::Confirmed:
        std::cout << "Confirmed.\n";
        break;

      case Wallet::ReceiptOutcome::Kind::Failed:
      {
        std::cerr << "error: transaction committed but failed.\n";
        if (outcome->receipt.is_object() &&
            outcome->receipt.contains("fee_paid"))
        {
          std::cerr << "  fee charged: "
                    << outcome->receipt["fee_paid"].dump() << "\n";
        }
        break;
      }

      case Wallet::ReceiptOutcome::Kind::Pending:
        std::cout << "Still pending after 60s. Use 'status' to check later.\n";
        break;
      }
    }

    //  ---- Validator-record formatting ----

    //  Print a validator record from the RPC in a human-readable
    //  form. Tolerant of missing fields — prints what's there and
    //  skips what isn't.
    void printValidatorRecord(const Common::Json &v)
    {
      auto s = [&](const char *key) -> std::string
      {
        if (!v.contains(key))
          return "(missing)";
        const auto &field = v[key];
        if (field.is_string())
          return field.get<std::string>();
        if (field.is_number())
          return std::to_string(field.get<int64_t>());
        if (field.is_boolean())
          return field.get<bool>() ? "true" : "false";
        return field.dump();
      };

      std::cout << "Registered as validator " << s("id") << "\n";
      std::cout << "  reward address:  " << s("reward_address") << "\n";
      std::cout << "  consensus key:   " << s("consensus_key") << "\n";
      std::cout << "  node key:        " << s("node_key") << "\n";
      std::cout << "  owner:           " << s("owner") << "\n";
      std::cout << "  stake:           " << s("stake") << "\n";
      std::cout << "  registered at:   " << s("registered_at_height") << "\n";

      const bool is_seed = v.value("is_seed", false);
      const bool is_active = v.value("is_active", false);
      const bool can_be_active = v.value("can_be_active", false);
      const bool is_offline = v.value("is_offline", false);

      std::cout << "  status:          ";
      if (is_seed)
        std::cout << "seed";
      else if (is_active)
        std::cout << "active";
      else
        std::cout << "registered (not in active set)";
      std::cout << "\n";

      std::cout << "  can be active:   "
                << (can_be_active ? "yes" : "no") << "\n";
      std::cout << "  is offline:      "
                << (is_offline ? "yes" : "no") << "\n";
      std::cout << "  uptime:          " << s("uptime_score") << " bps\n";
      std::cout << "  multiplier:      " << s("reward_multiplier") << " bps\n";
      std::cout << "  infractions:     " << s("infraction_count") << "\n";
    }

  } // anonymous namespace

  // ===========================================================================
  //  balance [address]
  // ===========================================================================

  void cmd_balance(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireRpc(session))
      return;

    std::string address;
    if (args.size() >= 2)
    {
      address = args[1];
    }
    else if (session.hasKeystore())
    {
      address = session.address_bech32m;
    }
    else
    {
      std::cerr << "error: no keystore open. Pass an address, or use 'open'.\n";
      return;
    }

    std::string err;
    auto balance = Wallet::getBalance(*session.rpc, address, &err);
    if (!balance.has_value())
    {
      std::cerr << "error: " << err << "\n";
      return;
    }

    std::cout << Wallet::formatAmount(*balance) << " CLRTY\n";
  }

  // ===========================================================================
  //  nonce [address]
  // ===========================================================================

  void cmd_nonce(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireRpc(session))
      return;

    std::string address;
    if (args.size() >= 2)
    {
      address = args[1];
    }
    else if (session.hasKeystore())
    {
      address = session.address_bech32m;
    }
    else
    {
      std::cerr << "error: no keystore open. Pass an address, or use 'open'.\n";
      return;
    }

    std::string err;
    auto nonce = Wallet::getNonce(*session.rpc, address, &err);
    if (!nonce.has_value())
    {
      std::cerr << "error: " << err << "\n";
      return;
    }

    std::cout << *nonce << "\n";
  }

  // ===========================================================================
  //  info
  // ===========================================================================

  void cmd_info(WalletSession &session, const std::vector<std::string> &args)
  {
    (void)args;

    if (!session.hasKeystore())
    {
      std::cerr << "error: no keystore open. Use 'open <path>' first.\n";
      return;
    }

    std::cout << "Path:        " << session.keystore_path << "\n";
    std::cout << "Address:     " << session.address_bech32m << "\n";
    std::cout << "Network:     "
              << Wallet::networkName(session.currentNetwork()) << "\n";
    std::cout << "Chain ID:    0x" << std::hex << session.chainId()
              << std::dec << "\n";
  }

  // ===========================================================================
  //  status [txid]
  // ===========================================================================

  void cmd_status(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireRpc(session))
      return;

    std::string txid_hex;
    if (args.size() >= 2)
    {
      txid_hex = args[1];
    }
    else if (session.last_txid_hex.has_value())
    {
      txid_hex = *session.last_txid_hex;
      std::cout << "(using last txid: " << txid_hex << ")\n";
    }
    else
    {
      std::cerr << "error: no txid given and no previous submission "
                   "in this session\n";
      return;
    }

    bool not_found = false;
    std::string err;
    auto receipt = Wallet::getTransactionReceipt(*session.rpc, txid_hex,
                                                 &not_found, &err);

    if (receipt.has_value())
    {
      //  Distinguish success from failure.
      try
      {
        const bool success = Wallet::receiptSucceeded(*receipt);
        std::cout << (success ? "Confirmed: success\n"
                              : "Confirmed: FAILED\n");
      }
      catch (const std::exception &e)
      {
        std::cout << "Confirmed (malformed receipt: "
                  << e.what() << ")\n";
      }

      std::cout << receipt->dump(2) << "\n";
      return;
    }

    if (not_found)
    {
      std::cout << "Pending (not yet in a block).\n";
      return;
    }

    std::cerr << "error: " << err << "\n";
  }

  // ===========================================================================
  //  send <to> <amount> <fee> [--token <id>] [--wait] [--dry-run]
  // ===========================================================================

  void cmd_send(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireKeystore(session))
      return;

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 1, flags, positional))
      return;

    if (positional.size() < 3)
    {
      std::cerr << "usage: send <to> <amount> <fee> "
                   "[--token <id>] [--wait] [--dry-run]\n";
      return;
    }

    auto to = parseAddress(session, positional[0], "<to>");
    if (!to.has_value())
      return;

    auto amount = Wallet::parseAmount(positional[1]);
    if (!amount.has_value())
    {
      std::cerr << "error: invalid amount: " << positional[1] << "\n";
      return;
    }

    auto fee = Wallet::parseAmount(positional[2]);
    if (!fee.has_value())
    {
      std::cerr << "error: invalid fee: " << positional[2] << "\n";
      return;
    }

    if (*amount == 0)
    {
      std::cerr << "error: amount must be non-zero\n";
      return;
    }
    if (*fee == 0)
    {
      std::cerr << "error: fee must be non-zero\n";
      return;
    }

    auto nonce = fetchNonce(session);
    if (!nonce.has_value())
      return;

    Wallet::TransferParams p;
    p.common.chain_id = session.chainId();
    p.common.nonce = *nonce;
    p.common.fee = *fee;
    p.to = *to;
    p.token_id = flags.token_id;
    p.amount = *amount;

    WalletStatus st;
    auto tx = Wallet::buildTransfer(*session.address, p, &st);
    if (!tx.has_value())
    {
      reportWalletError("cannot build transaction", st);
      return;
    }

    if (flags.dry_run)
    {
      std::cout << "Unsigned transaction (dry run):\n";
      std::cout << "  type:   transfer\n";
      std::cout << "  to:     " << positional[0] << "\n";
      std::cout << "  amount: " << Wallet::formatAmount(*amount)
                << " CLRTY\n";
      std::cout << "  fee:    " << Wallet::formatAmount(*fee) << " CLRTY\n";
      std::cout << "  nonce:  " << *nonce << "\n";
      std::cout << "Not signed. Not submitted.\n";
      return;
    }

    if (!signBuiltTransaction(session, *tx))
      return;

    submitAndReport(session, *tx, flags.wait);
  }

  // ===========================================================================
  //  claim <fee> [--wait]
  // ===========================================================================

  void cmd_claim(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireKeystore(session))
      return;

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 1, flags, positional))
      return;

    if (positional.size() < 1)
    {
      std::cerr << "usage: claim <fee> [--wait]\n";
      return;
    }

    auto fee = Wallet::parseAmount(positional[0]);
    if (!fee.has_value() || *fee == 0)
    {
      std::cerr << "error: invalid fee: " << positional[0] << "\n";
      return;
    }

    auto nonce = fetchNonce(session);
    if (!nonce.has_value())
      return;

    Wallet::StakingParams p;
    p.common.chain_id = session.chainId();
    p.common.nonce = *nonce;
    p.common.fee = *fee;

    WalletStatus st;
    auto tx = Wallet::buildClaimRewards(*session.address, p, &st);
    if (!tx.has_value())
    {
      reportWalletError("cannot build transaction", st);
      return;
    }

    if (flags.dry_run)
    {
      std::cout << "Unsigned claim-rewards (dry run). Not submitted.\n";
      return;
    }

    if (!signBuiltTransaction(session, *tx))
      return;

    submitAndReport(session, *tx, flags.wait);
  }

  // ===========================================================================
  //  stake <opt-in|opt-out> <fee> [--wait]
  // ===========================================================================

  void cmd_stake(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireKeystore(session))
      return;

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 1, flags, positional))
      return;

    if (positional.size() < 2)
    {
      std::cerr << "usage: stake <opt-in|opt-out> <fee> [--wait]\n";
      return;
    }

    const std::string &sub = positional[0];
    if (sub != "opt-in" && sub != "opt-out")
    {
      std::cerr << "error: subcommand must be 'opt-in' or 'opt-out'\n";
      return;
    }

    auto fee = Wallet::parseAmount(positional[1]);
    if (!fee.has_value() || *fee == 0)
    {
      std::cerr << "error: invalid fee: " << positional[1] << "\n";
      return;
    }

    auto nonce = fetchNonce(session);
    if (!nonce.has_value())
      return;

    Wallet::StakingParams p;
    p.common.chain_id = session.chainId();
    p.common.nonce = *nonce;
    p.common.fee = *fee;

    WalletStatus st;
    std::optional<Core::Transaction> tx;
    if (sub == "opt-in")
      tx = Wallet::buildOptInStaking(*session.address, p, &st);
    else
      tx = Wallet::buildOptOutStaking(*session.address, p, &st);

    if (!tx.has_value())
    {
      reportWalletError("cannot build transaction", st);
      return;
    }

    if (!signBuiltTransaction(session, *tx))
      return;

    submitAndReport(session, *tx, flags.wait);
  }

  // ===========================================================================
  //  validator <info|register|update-reward|unregister> ...
  // ===========================================================================

  void cmd_validator(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireKeystore(session))
      return;

    if (args.size() < 2)
    {
      std::cerr << "usage:\n"
                << "  validator info\n"
                << "  validator register <node-key-hex> <stake> <fee>\n"
                << "  validator update-reward <new-address> <fee>\n"
                << "  validator unregister <fee>\n";
      return;
    }

    const std::string &sub = args[1];

    //  ---- validator info: read-only, no transaction ----
    if (sub == "info")
    {
      bool not_found = false;
      std::string err;
      auto v = Wallet::getValidatorByAddress(
          *session.rpc, session.address_bech32m, &not_found, &err);

      if (v.has_value())
      {
        printValidatorRecord(*v);
        return;
      }

      if (not_found)
      {
        std::cout << "This account is not registered as a validator.\n";
        return;
      }

      std::cerr << "error: " << err << "\n";
      return;
    }

    //  ---- Parse flags and positional args ----
    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 2, flags, positional))
      return;

    //  ---- Pre-flight: look up the current validator state once,
    //       and use it to give a clear error before submitting a
    //       doomed transaction ----
    bool currently_registered = false;
    bool currently_seed = false;
    {
      bool not_found = false;
      std::string err;
      auto v = Wallet::getValidatorByAddress(
          *session.rpc, session.address_bech32m, &not_found, &err);

      if (v.has_value())
      {
        currently_registered = true;
        currently_seed = v->value("is_seed", false);
      }
      else if (!not_found)
      {
        //  Real RPC error. Fail fast rather than submit blind.
        std::cerr << "error: cannot query validator state: "
                  << err << "\n";
        return;
      }
    }

    //  ---- Build the transaction ----

    WalletStatus st;
    std::optional<Core::Transaction> tx;

    if (sub == "register")
    {
      if (currently_registered)
      {
        std::cerr << "error: this account is already registered as a "
                     "validator.\n";
        std::cerr << "  Use 'validator info' to see the current state.\n";
        return;
      }

      if (positional.size() < 3)
      {
        std::cerr << "usage: validator register <node-key-hex> <stake> <fee>\n";
        return;
      }

      auto node_key = parsePublicKeyHex(positional[0], "<node-key>");
      if (!node_key.has_value())
        return;

      auto stake = Wallet::parseAmount(positional[1]);
      if (!stake.has_value() || *stake == 0)
      {
        std::cerr << "error: invalid stake: " << positional[1] << "\n";
        return;
      }

      auto fee = Wallet::parseAmount(positional[2]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[2] << "\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::RegisterValidatorParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.node_key = *node_key;
      p.stake = *stake;

      tx = Wallet::buildRegisterValidator(*session.address, p, &st);
    }
    else if (sub == "update-reward")
    {
      if (!currently_registered)
      {
        std::cerr << "error: this account is not a registered validator.\n";
        return;
      }

      if (positional.size() < 2)
      {
        std::cerr << "usage: validator update-reward <new-address> <fee>\n";
        return;
      }

      auto new_addr = parseAddress(session, positional[0], "<new-address>");
      if (!new_addr.has_value())
        return;

      auto fee = Wallet::parseAmount(positional[1]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[1] << "\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::UpdateRewardParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.new_reward_address = *new_addr;

      tx = Wallet::buildUpdateRewardAddress(*session.address, p, &st);
    }
    else if (sub == "unregister")
    {
      if (!currently_registered)
      {
        std::cerr << "error: this account is not a registered validator.\n";
        return;
      }
      if (currently_seed)
      {
        std::cerr << "error: seed validators cannot be unregistered.\n";
        return;
      }

      if (positional.size() < 1)
      {
        std::cerr << "usage: validator unregister <fee>\n";
        return;
      }

      auto fee = Wallet::parseAmount(positional[0]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[0] << "\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::StakingParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;

      tx = Wallet::buildUnregisterValidator(*session.address, p, &st);
    }
    else
    {
      std::cerr << "error: unknown validator subcommand '" << sub << "'\n";
      return;
    }

    if (!tx.has_value())
    {
      reportWalletError("cannot build transaction", st);
      return;
    }

    if (!signBuiltTransaction(session, *tx))
      return;

    submitAndReport(session, *tx, flags.wait);
  }

  // ===========================================================================
  //  open <path> [--password-file <path>]
  // ===========================================================================

  void cmd_open(WalletSession &session, const std::vector<std::string> &args)
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

    Wallet::openKeystore(session, path, password_file);
  }

  // ===========================================================================
  //  close
  // ===========================================================================

  void cmd_close(WalletSession &session, const std::vector<std::string> &args)
  {
    (void)args;
    Wallet::closeKeystore(session);
  }

  // ===========================================================================
  //  connect <host:port>
  // ===========================================================================

  void cmd_connect(WalletSession &session, const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: connect <host:port>\n";
      return;
    }

    const std::string &spec = args[1];
    const size_t colon = spec.find(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size())
    {
      std::cerr << "error: expected host:port\n";
      return;
    }

    std::string host = spec.substr(0, colon);
    std::string port_str = spec.substr(colon + 1);

    char *end = nullptr;
    const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
    if (end == port_str.c_str() || *end != '\0' || port == 0 || port > 65535)
    {
      std::cerr << "error: invalid port: " << port_str << "\n";
      return;
    }

    session.rpc_endpoint.host = host;
    session.rpc_endpoint.port = static_cast<uint16_t>(port);
    session.rpc = std::make_unique<Wallet::RpcClient>(session.rpc_endpoint);

    std::cout << "Connected to " << host << ":" << port << "\n";
  }

  // ===========================================================================
  //  help [command]
  // ===========================================================================

  void cmd_help(WalletSession &session, const std::vector<std::string> &args)
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
      //  Skip the `quit` alias to avoid listing it twice.
      if (std::string(c->name) == "quit")
        continue;
      std::cout << "  " << c->usage << "\n";
    }
    std::cout << "\nType 'help <command>' for details.\n";
  }

  // ===========================================================================
  //  exit / quit
  // ===========================================================================

  void cmd_exit(WalletSession &session, const std::vector<std::string> &args)
  {
    (void)args;
    session.running = false;
  }

} // namespace Wallet