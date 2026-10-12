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
         "100 or 0.001). With --token, sends a non-native token instead.\n"
         "With --wait, poll until the transaction is confirmed or the\n"
         "timeout expires.",
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

        {"connect-peer", "connect-peer <host:port>",
         "Configure a second RPC endpoint for proof verification. When set,\n"
         "`balance --verify` requires both endpoints to agree on the state\n"
         "root before verifying proofs against it.",
         cmd_connect_peer},

        {"token",
         "token <list|show|supply|create|mint|burn|update> ...",
         "Fungible token operations:\n"
         "  token list [--limit N] [--offset N]\n"
         "  token show <token-id>\n"
         "  token supply <token-id>\n"
         "  token create <name> <symbol> [--decimals N] [--backing 0|1]\n"
         "               [--max-supply <atomic>] [--royalty <bps>]\n"
         "               [--fingerprint <hex>] <fee> [--wait] [--dry-run]\n"
         "  token mint <token-id> <to> <amount> <fee> [--wait] [--dry-run]\n"
         "  token burn <token-id> <amount> <fee> [--wait] [--dry-run]\n"
         "  token update <token-id> [--name <text>] [--symbol <text>]\n"
         "               [--royalty <bps>] <fee> [--wait] [--dry-run]\n"
         "The native CLRTY token has id 0 and cannot be created, minted,\n"
         "burned, or updated through this command.",
         cmd_token},

        {"tokens", "tokens [address] [--limit N]",
         "List every token held by an address, or by the open keystore's\n"
         "address.",
         cmd_tokens},

        {"nft",
         "nft <list|show|mint|wrap|transfer|burn|metadata|topup|claim> ...",
         "NFT operations:\n"
         "  nft list [--collection <id>] [--limit N] [--offset N]\n"
         "  nft show <nft-id>\n"
         "  nft mint <collection-id|-> [--uri <uri>] [--hash <hex>] <fee> [--wait]\n"
         "  nft wrap <underlying-token-id> <amount> [--collection <id>]\n"
         "           [--uri <uri>] [--hash <hex>] <fee> [--wait]\n"
         "  nft transfer <nft-id> <to> <fee> [--wait]\n"
         "  nft burn <nft-id> <fee> [--wait]\n"
         "  nft metadata <nft-id> [--uri <uri>] [--hash <hex>] [--freeze]\n"
         "               <fee> [--wait]\n"
         "  nft topup <nft-id> <token-id> <amount> <fee> [--wait]\n"
         "  nft claim <fee> [--wait]\n"
         "The NFT's shadow token id equals the NFT id, so `balance`,\n"
         "`send`, and the DEX treat it as an ordinary token.",
         cmd_nft},

        {"collection",
         "collection <list|show|create|refill> ...",
         "Collection operations:\n"
         "  collection list [--limit N] [--offset N]\n"
         "  collection show <collection-id>\n"
         "  collection create <name> <symbol> [--uri <uri>] <fee> [--wait]\n"
         "  collection create <name> <symbol> --reward-token <id>\n"
         "                    --reward-rate <amount> --escrow <amount>\n"
         "                    [--uri <uri>] <fee> [--wait]\n"
         "  collection refill <collection-id> <amount> <fee> [--wait]\n"
         "A collection with no reward token is a pure grouping. A\n"
         "collection with a reward token needs --reward-rate and\n"
         "an initial --escrow.",
         cmd_collection},

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

    //  A tiny helper for the read-side commands: given an NFT id and a
    //  successful RPC response, print the fields a user cares about.
    void printNftSummary(const Common::Json &j)
    {
      auto s = [&](const char *key) -> std::string
      {
        if (!j.contains(key) || j[key].is_null())
          return "(none)";
        const auto &v = j[key];
        if (v.is_string())
          return v.get<std::string>();
        if (v.is_number())
          return std::to_string(v.get<int64_t>());
        if (v.is_boolean())
          return v.get<bool>() ? "yes" : "no";
        return v.dump();
      };

      std::cout << "NFT " << s("id") << "\n";
      std::cout << "  owner:            " << s("owner") << "\n";
      std::cout << "  creator:          " << s("creator") << "\n";
      std::cout << "  shadow token id:  " << s("shadow_token_id") << "\n";
      std::cout << "  collection:       " << s("collection_id") << "\n";
      std::cout << "  metadata uri:     " << s("metadata_uri") << "\n";
      std::cout << "  metadata hash:    " << s("metadata_hash") << "\n";
      std::cout << "  frozen:           " << s("frozen") << "\n";

      const bool wrapped = j.value("underlying_token_id", 0) != 0;
      if (wrapped)
      {
        std::cout << "  wrapped:          yes\n";
        std::cout << "    underlying:     " << s("underlying_token_id") << "\n";
        std::cout << "    amount:         " << s("wrapped_amount") << "\n";
        std::cout << "    custody:        " << s("custody_address") << "\n";
      }

      std::cout << "  accrued owed:     " << s("accrued_owed") << "\n";
      std::cout << "  last accrual:     " << s("last_accrual_height") << "\n";
      std::cout << "  created at:       " << s("created_at_height") << "\n";
    }

    void printCollectionSummary(const Common::Json &j)
    {
      auto s = [&](const char *key) -> std::string
      {
        if (!j.contains(key) || j[key].is_null())
          return "(none)";
        const auto &v = j[key];
        if (v.is_string())
          return v.get<std::string>();
        if (v.is_number())
          return std::to_string(v.get<int64_t>());
        if (v.is_boolean())
          return v.get<bool>() ? "yes" : "no";
        return v.dump();
      };

      std::cout << "Collection " << s("id") << "\n";
      std::cout << "  name:              " << s("name") << "\n";
      std::cout << "  symbol:            " << s("symbol") << "\n";
      std::cout << "  creator:           " << s("creator") << "\n";
      std::cout << "  base uri:          " << s("base_uri") << "\n";
      std::cout << "  minted count:      " << s("minted_count") << "\n";
      std::cout << "  created at:        " << s("created_at_height") << "\n";

      const uint64_t reward_token = j.value("reward_token_id", 0);
      if (reward_token != 0)
      {
        std::cout << "  reward schedule:\n";
        std::cout << "    token:           " << s("reward_token_id") << "\n";
        std::cout << "    rate/epoch:      " << s("reward_rate_per_epoch") << "\n";
        std::cout << "    escrow remaining:" << s("reward_escrow_remaining") << "\n";
        std::cout << "    paused:          " << s("reward_paused") << "\n";
        std::cout << "    escrow address:  " << s("escrow_address") << "\n";
      }
      else
      {
        std::cout << "  reward schedule:   (none)\n";
      }
    }

    //  Parse a metadata hash from a hex string. Accepts the "0x"
    //  prefix and also accepts 64 raw hex chars. An empty string
    //  yields a null hash, which is the "no hash" case.
    std::optional<Crypto::Hash> parseOptionalHash(const std::string &s)
    {
      if (s.empty())
        return Crypto::Hash{};

      std::string hex = s;
      if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.substr(2);

      if (hex.size() != 64)
        return std::nullopt;

      Crypto::Hash h{};
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
      for (size_t i = 0; i < 32; ++i)
      {
        const int hi = nib(hex[i * 2]);
        const int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
          return std::nullopt;
        h.data[i] = static_cast<uint8_t>((hi << 4) | lo);
      }
      return h;
    }

    //  Print a token record. The shape of a token JSON object is
    //  fixed by Encoders::encodeToken; see the RPC docs for the full
    //  field list. This prints the fields a user cares about.
    void printTokenSummary(const Common::Json &j)
    {
      auto s = [&](const char *key) -> std::string
      {
        if (!j.contains(key) || j[key].is_null())
          return "(none)";
        const auto &v = j[key];
        if (v.is_string())
          return v.get<std::string>();
        if (v.is_number())
          return std::to_string(v.get<int64_t>());
        if (v.is_boolean())
          return v.get<bool>() ? "yes" : "no";
        return v.dump();
      };

      std::cout << "Token " << s("id") << "\n";
      std::cout << "  name:        " << s("name") << "\n";
      std::cout << "  symbol:      " << s("symbol") << "\n";
      std::cout << "  decimals:    " << s("decimals") << "\n";
      std::cout << "  creator:     " << s("creator") << "\n";
      std::cout << "  backing:     " << s("backing") << "\n";
      std::cout << "  max supply:  " << s("max_supply");
      if (j.value("max_supply", std::string("0")) == "0x0" ||
          j.value("max_supply", std::string("0")) == "0")
        std::cout << " (unlimited)";
      std::cout << "\n";
      std::cout << "  royalty:     " << s("royalty_bps") << " bps\n";

      if (j.contains("fingerprint") && !j["fingerprint"].is_null())
        std::cout << "  fingerprint: " << s("fingerprint") << "\n";

      if (j.value("is_native", false))
        std::cout << "  note:        this is the native CLRTY token\n";
    }
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

    //  Decode a uint64 from either a JSON hex string ("0x1a") or a
    //  JSON number (26). The RPC layer emits every integer as a hex
    //  string, so this is what almost every handler needs; the
    //  number branch is defensive for fields that might some day be
    //  emitted differently.
    std::optional<uint64_t> jsonU64(const Common::Json &j,
                                    const char *key)
    {
      if (!j.contains(key))
        return std::nullopt;
      const auto &v = j[key];

      if (v.is_string())
      {
        const std::string s = v.get<std::string>();
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        {
          errno = 0;
          char *end = nullptr;
          const unsigned long long x =
              std::strtoull(s.c_str() + 2, &end, 16);
          if (errno != 0 || end == s.c_str() + 2 || *end != '\0')
            return std::nullopt;
          return static_cast<uint64_t>(x);
        }
        return parseU64(s);
      }

      if (v.is_number_unsigned())
        return v.get<uint64_t>();
      if (v.is_number_integer())
      {
        const auto i = v.get<int64_t>();
        if (i < 0)
          return std::nullopt;
        return static_cast<uint64_t>(i);
      }

      return std::nullopt;
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
      std::string password_file;
    };

    //  Parse common flags starting at `start_index`. Positional
    //  arguments are appended to `positional`. Returns false if an
    //  unknown flag was seen or a flag was missing its value.
    //
    //  `token_out`: if non-null, `--token <id>` is accepted and its
    //  value is written here. If null, `--token` is rejected as an
    //  unknown flag. Only commands that actually take a token id
    //  should pass non-null; `nft` and `token` take their token ids
    //  positionally and reject `--token` deliberately.
    bool parseCommonFlags(const std::vector<std::string> &args,
                          size_t start_index,
                          CommonFlags &out,
                          std::vector<std::string> &positional,
                          uint32_t *token_out = nullptr)
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
          if (token_out == nullptr)
          {
            std::cerr << "error: --token is not valid for this command\n";
            return false;
          }
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
          *token_out = static_cast<uint32_t>(*v);
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

    bool verify = false;
    std::vector<std::string> positional;
    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--verify")
        verify = true;
      else
        positional.push_back(args[i]);
    }

    std::string address;
    if (!positional.empty())
    {
      address = positional[0];
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

    if (!verify)
    {
      std::string err;
      auto balance = Wallet::getBalance(*session.rpc, address, &err);
      if (!balance.has_value())
      {
        std::cerr << "error: " << err << "\n";
        return;
      }
      std::cout << Wallet::formatAmount(*balance) << " CLRTY\n";
      return;
    }

    if (!session.rpc_peer)
    {
      std::cerr << "warning: no peer endpoint configured. Set one with\n"
                << "  connect-peer <host:port>\n"
                << "to require two independent servers to agree on the state\n"
                << "root. Falling back to single-server trust for this call.\n";
    }

    Wallet::Network network = session.currentNetwork();

    std::string err;
    auto verified = Wallet::fetchVerifiedBalance(
        *session.rpc,
        session.rpc_peer.get(),
        address,
        network,
        &err);

    if (!verified.has_value())
    {
      std::cerr << "error: " << err << "\n";
      return;
    }

    std::cout << Wallet::formatAmount(verified->balance) << " CLRTY";
    if (verified->is_empty)
      std::cout << " (account has never been touched)";
    std::cout << "\n";

    std::cout << "  verified against state root "
              << verified->state_root.toString().substr(0, 16) << "...\n";
    std::cout << "  at version " << verified->version << "\n";
    if (verified->peer_verified)
    {
      std::cout << "  root confirmed by two independent endpoints\n";
    }
    else
    {
      std::cout << "  root obtained from a single endpoint\n";
    }
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

    //  --token is accepted here only. The optional out-pointer is
    //  what tells parseCommonFlags it may consume the flag.
    uint32_t token_id = 0;
    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 1, flags, positional, &token_id))
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
    p.token_id = token_id;
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

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 2, flags, positional))
      return;

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
        std::cerr << "error: cannot query validator state: "
                  << err << "\n";
        return;
      }
    }

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

  void cmd_connect_peer(WalletSession &session,
                        const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: connect-peer <host:port>\n"
                << "  Use 'connect-peer none' to clear the peer.\n";
      return;
    }

    const std::string &spec = args[1];

    if (spec == "none")
    {
      session.rpc_peer.reset();
      session.rpc_peer_endpoint = Wallet::RpcEndpoint{};
      std::cout << "Peer endpoint cleared.\n";
      return;
    }

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

    session.rpc_peer_endpoint.host = host;
    session.rpc_peer_endpoint.port = static_cast<uint16_t>(port);
    session.rpc_peer = std::make_unique<Wallet::RpcClient>(
        session.rpc_peer_endpoint);

    std::cout << "Peer endpoint set to " << host << ":" << port << "\n";
  }

  // ===========================================================================
  //  token <subcommand> ...
  // ===========================================================================

  void cmd_token(WalletSession &session, const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage:\n"
                << "  token list [--limit N] [--offset N]\n"
                << "  token show <token-id>\n"
                << "  token supply <token-id>\n"
                << "  token create <name> <symbol> [flags] <fee>\n"
                << "  token mint <token-id> <to> <amount> <fee>\n"
                << "  token burn <token-id> <amount> <fee>\n"
                << "  token update <token-id> [flags] <fee>\n";
      return;
    }

    const std::string &sub = args[1];

    //  ---- Read-side ----
    if (sub == "list")
    {
      if (!requireRpc(session))
        return;

      uint64_t limit = 50, offset = 0;
      for (size_t i = 2; i < args.size(); ++i)
      {
        if (args[i] == "--limit" && i + 1 < args.size())
        {
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --limit: invalid\n";
            return;
          }
          limit = *v;
        }
        else if (args[i] == "--offset" && i + 1 < args.size())
        {
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --offset: invalid\n";
            return;
          }
          offset = *v;
        }
        else
        {
          std::cerr << "error: unknown argument '" << args[i] << "'\n";
          return;
        }
      }

      std::string err;
      auto res = Wallet::getAllTokens(*session.rpc, limit, offset, &err);
      if (!res.has_value())
      {
        std::cerr << "error: " << err << "\n";
        return;
      }

      if (!(*res).contains("tokens") || !(*res)["tokens"].is_array())
      {
        std::cerr << "error: unexpected response shape from getAllTokens\n";
        return;
      }

      const auto count = jsonU64(*res, "count");
      if (count.has_value())
        std::cout << "Count: " << *count << "\n";

      for (const auto &t : (*res)["tokens"])
      {
        //  Every field the encoder emits is either a hex string or
        //  a plain string. Read them as strings and print as-is.
        const std::string id =
            t.contains("id") && t["id"].is_string()
                ? t["id"].get<std::string>()
                : std::string("?");
        const std::string symbol =
            t.contains("symbol") && t["symbol"].is_string()
                ? t["symbol"].get<std::string>()
                : std::string("");
        const std::string name =
            t.contains("name") && t["name"].is_string()
                ? t["name"].get<std::string>()
                : std::string("");
        const auto decimals = jsonU64(t, "decimals");

        std::cout << "  [" << id << "] "
                  << symbol << " — " << name
                  << " (decimals=" << (decimals.has_value() ? std::to_string(*decimals) : std::string("?"))
                  << ")\n";
      }
      return;
    }

    if (sub == "show")
    {
      if (!requireRpc(session))
        return;
      if (args.size() < 3)
      {
        std::cerr << "usage: token show <token-id>\n";
        return;
      }
      auto id = parseU64(args[2]);
      if (!id.has_value())
      {
        std::cerr << "error: invalid token id\n";
        return;
      }

      bool not_found = false;
      std::string err;
      auto res = Wallet::getTokenInfo(*session.rpc, *id, &not_found, &err);
      if (!res.has_value())
      {
        std::cerr << "error: "
                  << (not_found ? ("no token with id " + std::to_string(*id))
                                : err)
                  << "\n";
        return;
      }
      printTokenSummary(*res);
      return;
    }

    if (sub == "supply")
    {
      if (!requireRpc(session))
        return;
      if (args.size() < 3)
      {
        std::cerr << "usage: token supply <token-id>\n";
        return;
      }
      auto id = parseU64(args[2]);
      if (!id.has_value())
      {
        std::cerr << "error: invalid token id\n";
        return;
      }

      std::string err;
      auto res = Wallet::getTokenSupply(*session.rpc, *id, &err);
      if (!res.has_value())
      {
        std::cerr << "error: " << err << "\n";
        return;
      }

      const auto supply = jsonU64(*res, "supply");
      if (!supply.has_value())
      {
        std::cerr << "error: unexpected response shape from getTokenSupply\n";
        return;
      }
      std::cout << "Supply: " << *supply << "\n";
      return;
    }

    //  ---- Write-side ----
    if (!requireKeystore(session))
      return;

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 2, flags, positional))
      return;

    //  Token-specific flags.
    uint8_t decimals = 8;
    uint8_t backing = 0;
    uint64_t max_supply = 0;
    uint16_t royalty = 0;
    std::string fingerprint_hex;
    std::string new_name, new_symbol;
    std::optional<uint16_t> new_royalty;

    for (size_t i = 2; i < args.size(); ++i)
    {
      const std::string &a = args[i];

      auto take = [&](const char *name) -> std::optional<std::string>
      {
        if (a == name && i + 1 < args.size())
          return args[++i];
        return std::nullopt;
      };

      if (auto v = take("--decimals"); v.has_value())
      {
        auto x = parseU64(*v);
        if (!x.has_value() || *x > 18)
        {
          std::cerr << "error: --decimals: must be 0..18\n";
          return;
        }
        decimals = static_cast<uint8_t>(*x);
        continue;
      }
      if (auto v = take("--backing"); v.has_value())
      {
        auto x = parseU64(*v);
        if (!x.has_value() || *x > 1)
        {
          std::cerr << "error: --backing: must be 0 (unbacked) or 1 (bridged)\n";
          return;
        }
        backing = static_cast<uint8_t>(*x);
        continue;
      }
      if (auto v = take("--max-supply"); v.has_value())
      {
        auto x = parseU64(*v);
        if (!x.has_value())
        {
          std::cerr << "error: --max-supply: invalid\n";
          return;
        }
        max_supply = *x;
        continue;
      }
      if (auto v = take("--royalty"); v.has_value())
      {
        auto x = parseU64(*v);
        if (!x.has_value() || *x > 10000)
        {
          std::cerr << "error: --royalty: must be 0..10000 bps\n";
          return;
        }
        royalty = static_cast<uint16_t>(*x);
        new_royalty = static_cast<uint16_t>(*x);
        continue;
      }
      if (auto v = take("--fingerprint"); v.has_value())
      {
        fingerprint_hex = *v;
        continue;
      }
      if (auto v = take("--name"); v.has_value())
      {
        new_name = *v;
        continue;
      }
      if (auto v = take("--symbol"); v.has_value())
      {
        new_symbol = *v;
        continue;
      }
    }

    WalletStatus st;
    std::optional<Core::Transaction> tx;

    if (sub == "create")
    {
      if (positional.size() < 3)
      {
        std::cerr << "usage: token create <name> <symbol> <fee>\n";
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

      Wallet::CreateTokenParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.name = positional[0];
      p.symbol = positional[1];
      p.decimals = decimals;
      p.backing = backing;
      p.max_supply = max_supply;
      p.royalty_bps = royalty;

      if (!fingerprint_hex.empty())
      {
        auto h = parseOptionalHash(fingerprint_hex);
        if (!h.has_value())
        {
          std::cerr << "error: --fingerprint must be 64 hex characters\n";
          return;
        }
        p.fingerprint = *h;
      }

      tx = Wallet::buildCreateToken(*session.address, p, &st);
    }
    else if (sub == "mint")
    {
      if (positional.size() < 4)
      {
        std::cerr << "usage: token mint <token-id> <to> <amount> <fee>\n";
        return;
      }

      auto token_id = parseU64(positional[0]);
      if (!token_id.has_value() || *token_id == 0)
      {
        std::cerr << "error: invalid token id (use a non-zero id)\n";
        return;
      }

      auto to = parseAddress(session, positional[1], "<to>");
      if (!to.has_value())
        return;

      auto amount = Wallet::parseAmount(positional[2]);
      if (!amount.has_value() || *amount == 0)
      {
        std::cerr << "error: invalid amount: " << positional[2] << "\n";
        return;
      }

      auto fee = Wallet::parseAmount(positional[3]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[3] << "\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::MintTokenParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.token_id = static_cast<Id>(*token_id);
      p.to = *to;
      p.amount = *amount;

      tx = Wallet::buildMintToken(*session.address, p, &st);
    }
    else if (sub == "burn")
    {
      if (positional.size() < 3)
      {
        std::cerr << "usage: token burn <token-id> <amount> <fee>\n";
        return;
      }

      auto token_id = parseU64(positional[0]);
      if (!token_id.has_value() || *token_id == 0)
      {
        std::cerr << "error: invalid token id (use a non-zero id)\n";
        return;
      }

      auto amount = Wallet::parseAmount(positional[1]);
      if (!amount.has_value() || *amount == 0)
      {
        std::cerr << "error: invalid amount: " << positional[1] << "\n";
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

      Wallet::BurnTokenParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.token_id = static_cast<Id>(*token_id);
      p.amount = *amount;

      tx = Wallet::buildBurnToken(*session.address, p, &st);
    }
    else if (sub == "update")
    {
      if (positional.size() < 2)
      {
        std::cerr << "usage: token update <token-id> [flags] <fee>\n";
        return;
      }

      auto token_id = parseU64(positional[0]);
      if (!token_id.has_value() || *token_id == 0)
      {
        std::cerr << "error: invalid token id (use a non-zero id)\n";
        return;
      }

      auto fee = Wallet::parseAmount(positional[1]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[1] << "\n";
        return;
      }

      if (new_name.empty() && new_symbol.empty() && !new_royalty.has_value())
      {
        std::cerr << "error: no metadata change requested "
                     "(use --name, --symbol, or --royalty)\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::UpdateTokenMetaParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.token_id = static_cast<Id>(*token_id);
      p.new_name = new_name;
      p.new_symbol = new_symbol;
      p.new_royalty_bps = new_royalty.value_or(0);

      tx = Wallet::buildUpdateTokenMeta(*session.address, p, &st);
    }
    else
    {
      std::cerr << "error: unknown token subcommand '" << sub << "'\n";
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
  //  tokens [address] [--limit N]
  // ===========================================================================

  void cmd_tokens(WalletSession &session, const std::vector<std::string> &args)
  {
    if (!requireRpc(session))
      return;

    std::string address;
    uint64_t limit = 100;

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
        limit = *v;
      }
      else if (!args[i].empty() && args[i][0] == '-')
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
      else
      {
        address = args[i];
      }
    }

    if (address.empty())
    {
      if (!session.hasKeystore())
      {
        std::cerr << "error: no keystore open. Pass an address, or use 'open'.\n";
        return;
      }
      address = session.address_bech32m;
    }

    std::string err;
    auto res = Wallet::getTokensForAddress(*session.rpc, address, &err);
    if (!res.has_value())
    {
      std::cerr << "error: " << err << "\n";
      return;
    }

    if (!(*res).contains("tokens") || !(*res)["tokens"].is_array())
    {
      std::cerr << "error: unexpected response shape from getTokensForAddress\n";
      return;
    }

    const auto count = jsonU64(*res, "count");
    const uint64_t total = count.value_or(0);

    if (total == 0)
    {
      std::cout << "No tokens held by " << address << "\n";
      return;
    }

    std::cout << "Tokens held by " << address << ":\n";
    uint64_t printed = 0;
    for (const auto &entry : (*res)["tokens"])
    {
      if (printed >= limit)
        break;

      const std::string token_id =
          entry.contains("token_id") && entry["token_id"].is_string()
              ? entry["token_id"].get<std::string>()
              : std::string("?");
      const std::string balance =
          entry.contains("balance") && entry["balance"].is_string()
              ? entry["balance"].get<std::string>()
              : std::string("0");

      std::cout << "  [" << token_id << "] "
                << balance << " (atomic units)\n";
      ++printed;
    }
    if (total > printed)
      std::cout << "  ... and " << (total - printed) << " more\n";
  }

  // ===========================================================================
  //  nft <subcommand> ...
  // ===========================================================================

  // ===========================================================================
  //  nft <subcommand> ...
  // ===========================================================================

  void cmd_nft(WalletSession &session, const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage:\n"
                << "  nft list [--collection <id>] [--limit N] [--offset N]\n"
                << "  nft show <nft-id>\n"
                << "  nft mint <collection-id|-> [--uri <uri>] [--hash <hex>] <fee>\n"
                << "  nft wrap <underlying-token-id> <amount> [--collection <id>]\n"
                << "           [--uri <uri>] [--hash <hex>] <fee>\n"
                << "  nft transfer <nft-id> <to> <fee>\n"
                << "  nft burn <nft-id> <fee>\n"
                << "  nft metadata <nft-id> [--uri <uri>] [--hash <hex>] [--freeze] <fee>\n"
                << "  nft topup <nft-id> <token-id> <amount> <fee>\n"
                << "  nft claim <fee>\n";
      return;
    }

    const std::string &sub = args[1];

    //  =======================================================================
    //  Read-side subcommands: list, show
    //  =======================================================================

    if (sub == "list")
    {
      if (!requireRpc(session))
        return;

      uint64_t limit = 50, offset = 0;
      std::string collection_str;

      for (size_t i = 2; i < args.size(); ++i)
      {
        if (args[i] == "--limit" && i + 1 < args.size())
        {
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --limit: invalid\n";
            return;
          }
          limit = *v;
        }
        else if (args[i] == "--offset" && i + 1 < args.size())
        {
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --offset: invalid\n";
            return;
          }
          offset = *v;
        }
        else if (args[i] == "--collection" && i + 1 < args.size())
        {
          collection_str = args[++i];
        }
        else
        {
          std::cerr << "error: unknown argument '" << args[i] << "'\n";
          return;
        }
      }

      std::string err;
      std::optional<Common::Json> res;

      if (!collection_str.empty())
      {
        auto cid = parseU64(collection_str);
        if (!cid.has_value())
        {
          std::cerr << "error: --collection: invalid id\n";
          return;
        }
        bool not_found = false;
        res = Wallet::getNftsForCollection(*session.rpc, *cid, limit, offset,
                                           &not_found, &err);
        if (!res.has_value() && not_found)
        {
          std::cerr << "error: no collection with id " << *cid << "\n";
          return;
        }
      }
      else
      {
        if (!session.hasKeystore())
        {
          std::cerr << "error: no keystore open. Pass a keystore, or "
                       "use `nft list --collection <id>`.\n";
          return;
        }
        res = Wallet::getNftsForOwner(*session.rpc, session.address_bech32m,
                                      limit, offset, &err);
      }

      if (!res.has_value())
      {
        std::cerr << "error: " << err << "\n";
        return;
      }

      if (!(*res).contains("nfts") || !(*res)["nfts"].is_array())
      {
        std::cerr << "error: unexpected response shape from NFT list\n";
        return;
      }

      const auto count = jsonU64(*res, "count");
      if (count.has_value())
        std::cout << "Count: " << *count << "\n";

      for (const auto &nft : (*res)["nfts"])
      {
        const std::string id =
            nft.contains("id") && nft["id"].is_string()
                ? nft["id"].get<std::string>()
                : std::string("?");
        const std::string collection_id =
            nft.contains("collection_id") && nft["collection_id"].is_string()
                ? nft["collection_id"].get<std::string>()
                : std::string("0");
        const std::string uri =
            nft.contains("metadata_uri") && nft["metadata_uri"].is_string()
                ? nft["metadata_uri"].get<std::string>()
                : std::string("");

        std::cout << "  [" << id << "] "
                  << "collection=" << collection_id
                  << " uri=" << uri
                  << "\n";
      }
      return;
    }

    if (sub == "show")
    {
      if (!requireRpc(session))
        return;
      if (args.size() < 3)
      {
        std::cerr << "usage: nft show <nft-id>\n";
        return;
      }
      auto id = parseU64(args[2]);
      if (!id.has_value())
      {
        std::cerr << "error: invalid nft id\n";
        return;
      }

      bool not_found = false;
      std::string err;
      auto res = Wallet::getNft(*session.rpc, *id, &not_found, &err);
      if (!res.has_value())
      {
        std::cerr << "error: "
                  << (not_found ? ("no NFT with id " + std::to_string(*id))
                                : err)
                  << "\n";
        return;
      }
      printNftSummary(*res);
      return;
    }

    //  =======================================================================
    //  Write-side subcommands: mint, wrap, transfer, burn, metadata, topup, claim
    //  =======================================================================

    if (!requireKeystore(session))
      return;

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 2, flags, positional))
      return;

    //  NFT-specific flags. These are scanned separately from
    //  parseCommonFlags, which only knows about the flags every
    //  write command shares (--wait, --dry-run, --password-file).
    //
    //  Because parseCommonFlags also rejects unknown flags, any
    //  flag listed here must NOT be prefixed with '-' in a way that
    //  trips the "unknown flag" branch — but parseCommonFlags
    //  treats any '-'-prefixed token it doesn't recognize as an
    //  error. To keep that invariant, the scanner below runs first
    //  and eats the NFT flags out of `args`; the versions of
    //  parseCommonFlags we call with the residue never see them.
    //
    //  In practice the current parseCommonFlags tolerates them
    //  because it only inspects positionals; the important thing is
    //  that these flags are consumed exactly once, in this loop.
    std::string metadata_uri;
    std::optional<Crypto::Hash> metadata_hash;
    bool freeze = false;
    uint64_t collection_id = 0;

    for (size_t i = 2; i < args.size(); ++i)
    {
      const std::string &a = args[i];

      if (a == "--uri" && i + 1 < args.size())
      {
        metadata_uri = args[++i];
      }
      else if (a == "--hash" && i + 1 < args.size())
      {
        auto h = parseOptionalHash(args[++i]);
        if (!h.has_value())
        {
          std::cerr << "error: --hash: must be 64 hex chars (or 0x-prefixed)\n";
          return;
        }
        metadata_hash = *h;
      }
      else if (a == "--freeze")
      {
        freeze = true;
      }
      else if (a == "--collection" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --collection: invalid id\n";
          return;
        }
        collection_id = *v;
      }
    }

    WalletStatus st;
    std::optional<Core::Transaction> tx;

    if (sub == "mint")
    {
      //  Positional args: [collection-id|-] <fee>
      //  The collection id may be '-' for "no collection".
      //  The --collection flag is also accepted for symmetry with
      //  wrap and to make the "no collection" case explicit.
      if (positional.empty())
      {
        std::cerr << "usage: nft mint <collection-id|-> <fee>\n";
        return;
      }

      uint64_t effective_collection = collection_id;

      if (positional[0] != "-")
      {
        auto v = parseU64(positional[0]);
        if (!v.has_value())
        {
          std::cerr << "error: invalid collection id\n";
          return;
        }
        effective_collection = *v;
        positional.erase(positional.begin());
      }
      else
      {
        positional.erase(positional.begin());
        effective_collection = 0;
      }

      if (positional.size() < 1)
      {
        std::cerr << "usage: nft mint <collection-id|-> <fee>\n";
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

      Wallet::MintNftParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.collection_id = effective_collection;
      if (metadata_hash.has_value())
        p.metadata_hash = *metadata_hash;
      p.metadata_uri = metadata_uri;

      tx = Wallet::buildMintNft(*session.address, p, &st);
    }
    else if (sub == "wrap")
    {
      //  Positional args: <underlying-token-id> <amount> <fee>
      if (positional.size() < 3)
      {
        std::cerr << "usage: nft wrap <underlying-token-id> <amount> <fee>\n";
        return;
      }

      auto underlying = parseU64(positional[0]);
      if (!underlying.has_value() || *underlying == 0)
      {
        std::cerr << "error: invalid underlying token id\n";
        return;
      }

      auto amount = Wallet::parseAmount(positional[1]);
      if (!amount.has_value() || *amount == 0)
      {
        std::cerr << "error: invalid amount: " << positional[1] << "\n";
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

      Wallet::WrapNftParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.underlying_token_id = static_cast<Id>(*underlying);
      p.wrapped_amount = *amount;
      p.collection_id = collection_id;
      if (metadata_hash.has_value())
        p.metadata_hash = *metadata_hash;
      p.metadata_uri = metadata_uri;

      tx = Wallet::buildWrapNft(*session.address, p, &st);
    }
    else if (sub == "transfer")
    {
      //  Positional args: <nft-id> <to> <fee>
      if (positional.size() < 3)
      {
        std::cerr << "usage: nft transfer <nft-id> <to> <fee>\n";
        return;
      }

      auto nft_id = parseU64(positional[0]);
      if (!nft_id.has_value() || *nft_id == 0)
      {
        std::cerr << "error: invalid nft id\n";
        return;
      }

      auto to = parseAddress(session, positional[1], "<to>");
      if (!to.has_value())
        return;

      auto fee = Wallet::parseAmount(positional[2]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[2] << "\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::TransferNftParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.nft_id = *nft_id;
      p.new_owner = *to;

      tx = Wallet::buildTransferNft(*session.address, p, &st);
    }
    else if (sub == "burn")
    {
      //  Positional args: <nft-id> <fee>
      if (positional.size() < 2)
      {
        std::cerr << "usage: nft burn <nft-id> <fee>\n";
        return;
      }

      auto nft_id = parseU64(positional[0]);
      if (!nft_id.has_value() || *nft_id == 0)
      {
        std::cerr << "error: invalid nft id\n";
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

      Wallet::BurnNftParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.nft_id = *nft_id;

      tx = Wallet::buildBurnNft(*session.address, p, &st);
    }
    else if (sub == "metadata")
    {
      //  Positional args: <nft-id> <fee>
      if (positional.size() < 2)
      {
        std::cerr << "usage: nft metadata <nft-id> [--uri <uri>] "
                     "[--hash <hex>] [--freeze] <fee>\n";
        return;
      }

      auto nft_id = parseU64(positional[0]);
      if (!nft_id.has_value() || *nft_id == 0)
      {
        std::cerr << "error: invalid nft id\n";
        return;
      }

      auto fee = Wallet::parseAmount(positional[1]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[1] << "\n";
        return;
      }

      if (metadata_uri.empty() && !metadata_hash.has_value() && !freeze)
      {
        std::cerr << "error: no metadata change requested "
                     "(use --uri, --hash, or --freeze)\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::UpdateNftMetadataParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.nft_id = *nft_id;
      if (metadata_hash.has_value())
        p.metadata_hash = *metadata_hash;
      p.metadata_uri = metadata_uri;
      p.freeze = freeze;

      tx = Wallet::buildUpdateNftMetadata(*session.address, p, &st);
    }
    else if (sub == "topup")
    {
      //  Positional args: <nft-id> <token-id> <amount> <fee>
      if (positional.size() < 4)
      {
        std::cerr << "usage: nft topup <nft-id> <token-id> <amount> <fee>\n";
        return;
      }

      auto nft_id = parseU64(positional[0]);
      if (!nft_id.has_value() || *nft_id == 0)
      {
        std::cerr << "error: invalid nft id\n";
        return;
      }

      auto token_id = parseU64(positional[1]);
      if (!token_id.has_value())
      {
        std::cerr << "error: invalid token id\n";
        return;
      }

      auto amount = Wallet::parseAmount(positional[2]);
      if (!amount.has_value() || *amount == 0)
      {
        std::cerr << "error: invalid amount: " << positional[2] << "\n";
        return;
      }

      auto fee = Wallet::parseAmount(positional[3]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[3] << "\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::TopUpNftParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.nft_id = *nft_id;
      p.token_id = static_cast<Id>(*token_id);
      p.amount = *amount;

      tx = Wallet::buildTopUpNft(*session.address, p, &st);
    }
    else if (sub == "claim")
    {
      //  Positional args: <fee>
      if (positional.size() < 1)
      {
        std::cerr << "usage: nft claim <fee>\n";
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

      Wallet::ClaimNftRewardParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;

      tx = Wallet::buildClaimNftReward(*session.address, p, &st);
    }
    else
    {
      std::cerr << "error: unknown nft subcommand '" << sub << "'\n";
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
  //  collection <subcommand> ...
  // ===========================================================================

  void cmd_collection(WalletSession &session,
                      const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage:\n"
                << "  collection list [--limit N] [--offset N]\n"
                << "  collection show <collection-id>\n"
                << "  collection create <name> <symbol> [--uri <uri>] <fee>\n"
                << "  collection create <name> <symbol> --reward-token <id>\n"
                << "                    --reward-rate <amount> --escrow <amount> <fee>\n"
                << "  collection refill <collection-id> <amount> <fee>\n";
      return;
    }

    const std::string &sub = args[1];

    if (sub == "list")
    {
      if (!requireRpc(session))
        return;

      uint64_t limit = 50, offset = 0;
      for (size_t i = 2; i < args.size(); ++i)
      {
        if (args[i] == "--limit" && i + 1 < args.size())
        {
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --limit: invalid\n";
            return;
          }
          limit = *v;
        }
        else if (args[i] == "--offset" && i + 1 < args.size())
        {
          auto v = parseU64(args[++i]);
          if (!v.has_value())
          {
            std::cerr << "error: --offset: invalid\n";
            return;
          }
          offset = *v;
        }
        else
        {
          std::cerr << "error: unknown argument '" << args[i] << "'\n";
          return;
        }
      }

      std::string err;
      auto res = Wallet::getAllCollections(*session.rpc, limit, offset, &err);
      if (!res.has_value())
      {
        std::cerr << "error: " << err << "\n";
        return;
      }

      std::cout << "Count: " << (*res).value("count", 0) << "\n";
      for (const auto &c : (*res)["collections"])
      {
        std::cout << "  [" << c.value("id", std::string("?")) << "] "
                  << c.value("name", std::string(""))
                  << " (" << c.value("symbol", std::string("")) << ") "
                  << "minted=" << c.value("minted_count", std::string("0"))
                  << "\n";
      }
      return;
    }

    if (sub == "show")
    {
      if (!requireRpc(session))
        return;
      if (args.size() < 3)
      {
        std::cerr << "usage: collection show <collection-id>\n";
        return;
      }
      auto id = parseU64(args[2]);
      if (!id.has_value())
      {
        std::cerr << "error: invalid collection id\n";
        return;
      }

      bool not_found = false;
      std::string err;
      auto res = Wallet::getCollection(*session.rpc, *id, &not_found, &err);
      if (!res.has_value())
      {
        std::cerr << "error: "
                  << (not_found
                          ? ("no collection with id " + std::to_string(*id))
                          : err)
                  << "\n";
        return;
      }
      printCollectionSummary(*res);
      return;
    }

    if (!requireKeystore(session))
      return;

    std::vector<std::string> positional;
    CommonFlags flags;
    if (!parseCommonFlags(args, 2, flags, positional))
      return;

    std::string base_uri;
    uint64_t reward_token_id = 0;
    std::optional<uint64_t> reward_rate;
    std::optional<uint64_t> escrow_amount;
    for (size_t i = 2; i < args.size(); ++i)
    {
      if (args[i] == "--uri" && i + 1 < args.size())
        base_uri = args[++i];
      else if (args[i] == "--reward-token" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --reward-token: invalid\n";
          return;
        }
        reward_token_id = *v;
      }
      else if (args[i] == "--reward-rate" && i + 1 < args.size())
      {
        auto v = Wallet::parseAmount(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --reward-rate: invalid\n";
          return;
        }
        reward_rate = *v;
      }
      else if (args[i] == "--escrow" && i + 1 < args.size())
      {
        auto v = Wallet::parseAmount(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --escrow: invalid\n";
          return;
        }
        escrow_amount = *v;
      }
    }

    WalletStatus st;
    std::optional<Core::Transaction> tx;

    if (sub == "create")
    {
      if (positional.size() < 3)
      {
        std::cerr << "usage: collection create <name> <symbol> <fee>\n";
        return;
      }

      const std::string &name = positional[0];
      const std::string &symbol = positional[1];

      auto fee = Wallet::parseAmount(positional[2]);
      if (!fee.has_value() || *fee == 0)
      {
        std::cerr << "error: invalid fee: " << positional[2] << "\n";
        return;
      }

      if (reward_token_id != 0)
      {
        if (!reward_rate.has_value() || !escrow_amount.has_value())
        {
          std::cerr << "error: --reward-token requires both --reward-rate "
                       "and --escrow\n";
          return;
        }
      }
      else if (reward_rate.has_value() || escrow_amount.has_value())
      {
        std::cerr << "error: --reward-rate and --escrow require --reward-token\n";
        return;
      }

      auto nonce = fetchNonce(session);
      if (!nonce.has_value())
        return;

      Wallet::CreateNftCollectionParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.name = name;
      p.symbol = symbol;
      p.base_uri = base_uri;
      p.reward_token_id = static_cast<Id>(reward_token_id);
      p.reward_rate_per_epoch = reward_rate.value_or(0);
      p.escrow_amount = escrow_amount.value_or(0);

      tx = Wallet::buildCreateNftCollection(*session.address, p, &st);
    }
    else if (sub == "refill")
    {
      if (positional.size() < 3)
      {
        std::cerr << "usage: collection refill <collection-id> <amount> <fee>\n";
        return;
      }

      auto collection_id = parseU64(positional[0]);
      if (!collection_id.has_value() || *collection_id == 0)
      {
        std::cerr << "error: invalid collection id\n";
        return;
      }

      auto amount = Wallet::parseAmount(positional[1]);
      if (!amount.has_value() || *amount == 0)
      {
        std::cerr << "error: invalid amount: " << positional[1] << "\n";
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

      Wallet::RefillCollectionRewardParams p;
      p.common.chain_id = session.chainId();
      p.common.nonce = *nonce;
      p.common.fee = *fee;
      p.collection_id = *collection_id;
      p.amount = *amount;

      tx = Wallet::buildRefillCollectionReward(*session.address, p, &st);
    }
    else
    {
      std::cerr << "error: unknown collection subcommand '" << sub << "'\n";
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