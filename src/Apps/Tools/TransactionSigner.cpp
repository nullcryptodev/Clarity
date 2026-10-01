// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//  transaction_signer
//
//  Signs a single transaction from an encrypted keystore and prints
//  the serialized hex to stdout. Does not submit — the caller sends
//  the hex to a node's clrty_sendRawTransaction method (via curl, or
//  a future send command).
//
//  Usage:
//    transaction_signer sign transfer --keystore <path> --to <addr> --amount <clrty> --fee <clrty> --nonce <n> [--token <id>] [--raw] [--dry-run] [--password-file <path>]
//
//    transaction_signer sign register-validator --keystore <path> --stake <clrty> --node-key <hex> --fee <clrty> --nonce <n> [--raw] [--dry-run] [--password-file <path>]
//
//    transaction_signer sign update-reward-address --keystore <path> --new-address <addr> --fee <clrty> --nonce <n> [--raw] [--dry-run] [--password-file <path>]
//
//    transaction_signer sign unregister-validator --keystore <path> --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign claim-rewards --keystore <path> --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign opt-in-staking --keystore <path> --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign opt-out-staking --keystore <path> --fee <clrty> --nonce <n> [...]
//
//  Output discipline:
//    stdout  — the raw hex (with --raw), or a summary (default).
//    stderr  — prompts, warnings, errors, and the password input.
//
//  The tool refuses to accept the password as a command-line flag.
//  Use --password-file, or let it prompt interactively.

#include "Common/PasswordPrompt.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/HdPath.h"
#include "Wallet/LocalSigner.h"
#include "Wallet/TransactionBuilder.h"
#include "Wallet/WalletError.h"
#include "Wallet/WalletTypes.h"

#include "Crypto/Types.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

namespace
{
  // ===========================================================================
  //  Argument types
  // ===========================================================================

  enum class SignType
  {
    Transfer,
    RegisterValidator,
    UnregisterValidator,
    UpdateRewardAddress,
    ClaimRewards,
    OptInStaking,
    OptOutStaking,
  };

  struct SignArgs
  {
    SignType type{SignType::Transfer};

    // Common
    std::string keystore;
    std::string password_file; // empty = prompt
    uint64_t nonce{0};
    uint64_t fee{0};
    bool raw{false};
    bool dry_run{false};

    // Transfer
    std::string to;
    uint64_t amount{0};
    uint32_t token_id{0};

    // RegisterValidator
    std::string node_key_hex;
    uint64_t stake{0};

    // UpdateRewardAddress
    std::string new_address;
  };

  // ===========================================================================
  //  Argument parsing helpers
  // ===========================================================================

  SignType parseSignType(const std::string &s)
  {
    if (s == "transfer")
      return SignType::Transfer;
    if (s == "register-validator")
      return SignType::RegisterValidator;
    if (s == "unregister-validator")
      return SignType::UnregisterValidator;
    if (s == "update-reward-address")
      return SignType::UpdateRewardAddress;
    if (s == "claim-rewards")
      return SignType::ClaimRewards;
    if (s == "opt-in-staking")
      return SignType::OptInStaking;
    if (s == "opt-out-staking")
      return SignType::OptOutStaking;

    throw std::runtime_error("unknown transaction type: " + s);
  }

  //  Parse a CLRTY decimal amount into atomic units. Uses the
  //  wallet's parser so we get consistent behavior with the rest of
  //  the codebase.
  uint64_t parseAmountOrDie(const std::string &s, const char *flag)
  {
    auto v = Wallet::parseAmount(s);
    if (!v.has_value())
    {
      throw std::runtime_error(
          std::string(flag) + ": invalid amount '" + s +
          "' (expected a decimal like 100 or 0.001)");
    }
    return *v;
  }

  //  Parse a plain uint64 (nonce, token_id).
  uint64_t parseU64OrDie(const std::string &s, const char *flag)
  {
    if (s.empty())
      throw std::runtime_error(std::string(flag) + ": empty value");
    errno = 0;
    char *end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0')
    {
      throw std::runtime_error(
          std::string(flag) + ": invalid integer '" + s + "'");
    }
    return static_cast<uint64_t>(v);
  }

  // ===========================================================================
  //  Argument parsing
  // ===========================================================================

  SignArgs parseSignArgs(int argc, char **argv)
  {
    SignArgs args;

    if (argc < 1)
      throw std::runtime_error("missing transaction type");

    args.type = parseSignType(argv[0]);

    for (int i = 1; i < argc; ++i)
    {
      const std::string arg = argv[i];

      auto next = [&]() -> std::string
      {
        if (i + 1 >= argc)
          throw std::runtime_error("missing value for " + arg);
        return argv[++i];
      };

      //  ---- Common ----
      if (arg == "--keystore")
      {
        args.keystore = next();
        continue;
      }
      if (arg == "--password-file")
      {
        args.password_file = next();
        continue;
      }
      if (arg == "--password")
      {
        // Explicitly rejected. See file header.
        throw std::runtime_error(
            "--password is not accepted; use --password-file or "
            "let the tool prompt");
      }
      if (arg == "--nonce")
      {
        args.nonce = parseU64OrDie(next(), "--nonce");
        continue;
      }
      if (arg == "--fee")
      {
        args.fee = parseAmountOrDie(next(), "--fee");
        continue;
      }
      if (arg == "--raw")
      {
        args.raw = true;
        continue;
      }
      if (arg == "--dry-run")
      {
        args.dry_run = true;
        continue;
      }

      //  ---- Transfer ----
      if (arg == "--to")
      {
        args.to = next();
        continue;
      }
      if (arg == "--amount")
      {
        args.amount = parseAmountOrDie(next(), "--amount");
        continue;
      }
      if (arg == "--token")
      {
        args.token_id = static_cast<uint32_t>(
            parseU64OrDie(next(), "--token"));
        continue;
      }

      //  ---- RegisterValidator ----
      if (arg == "--node-key")
      {
        args.node_key_hex = next();
        continue;
      }
      if (arg == "--stake")
      {
        args.stake = parseAmountOrDie(next(), "--stake");
        continue;
      }

      //  ---- UpdateRewardAddress ----
      if (arg == "--new-address")
      {
        args.new_address = next();
        continue;
      }

      throw std::runtime_error("unknown argument: " + arg);
    }

    //  ---- Post-parse validation ----

    if (args.keystore.empty())
      throw std::runtime_error("--keystore is required");

    if (args.fee == 0)
      throw std::runtime_error("--fee is required and must be non-zero");

    //  Per-type required args. This is where we catch "you forgot
    //  --to" before opening the keystore.
    switch (args.type)
    {
    case SignType::Transfer:
      if (args.to.empty())
        throw std::runtime_error("transfer requires --to");
      if (args.amount == 0)
        throw std::runtime_error("transfer requires --amount (non-zero)");
      break;

    case SignType::RegisterValidator:
      if (args.node_key_hex.empty())
        throw std::runtime_error("register-validator requires --node-key");
      if (args.stake == 0)
        throw std::runtime_error("register-validator requires --stake (non-zero)");
      break;

    case SignType::UpdateRewardAddress:
      if (args.new_address.empty())
        throw std::runtime_error("update-reward-address requires --new-address");
      break;

    case SignType::UnregisterValidator:
    case SignType::ClaimRewards:
    case SignType::OptInStaking:
    case SignType::OptOutStaking:
      // No type-specific required args.
      break;
    }

    return args;
  }

  // ===========================================================================
  //  Hex output
  // ===========================================================================

  std::string bytesToHex(const uint8_t *data, size_t len)
  {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
      out.push_back(hex[data[i] >> 4]);
      out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
  }

  // ===========================================================================
  //  Address parsing
  // ===========================================================================

  //  Parse a bech32m address for the network the keystore is bound to.
  Crypto::Address parseAddressOrDie(const std::string &s,
                                    Wallet::Network network,
                                    const char *flag_name)
  {
    auto addr = Wallet::decodeAddress(s, network);
    if (!addr.has_value())
    {
      throw std::runtime_error(
          std::string(flag_name) +
          ": not a valid address for this network: " + s);
    }
    return *addr;
  }

  //  Parse a 64-character hex string into a Crypto::PublicKey.
  //  Used for --node-key. Unlike addresses, this is raw hex, not
  //  bech32m.
  Crypto::PublicKey parsePublicKeyHexOrDie(const std::string &s,
                                           const char *flag_name)
  {
    if (s.size() != 64)
    {
      throw std::runtime_error(
          std::string(flag_name) + ": must be 64 hex characters (32 bytes)");
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
        throw std::runtime_error(
            std::string(flag_name) + ": contains non-hex characters");
      }
      pk.data[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return pk;
  }

  // ===========================================================================
  //  Password
  // ===========================================================================

  std::string resolvePassword(const SignArgs &args)
  {
    if (!args.password_file.empty())
    {
      auto pw = Apps::readPasswordFile(args.password_file);
      if (!pw.has_value())
      {
        std::cerr << "error: could not read password file: "
                  << args.password_file << "\n";
        std::exit(1);
      }
      return *pw;
    }

    auto pw = Apps::promptForPassword("Keystore password: ");
    if (!pw.has_value())
    {
      std::cerr << "error: could not read password\n";
      std::exit(1);
    }
    return *pw;
  }

  // ===========================================================================
  //  Error reporting
  // ===========================================================================

  void reportWalletError(const char *prefix, const Wallet::WalletStatus &st)
  {
    std::cerr << "error: " << prefix << ": ";
    if (!st.detail.empty())
      std::cerr << st.detail;
    else
      std::cerr << Wallet::walletErrorMessage(st.code);
    std::cerr << "\n";
  }

  // ===========================================================================
  //  Output formatting
  // ===========================================================================

  void printSummary(const Core::Transaction &tx,
                    const Crypto::Hash &signing_hash,
                    Wallet::Network network)
  {
    const std::string from = Wallet::encodeAddress(tx.from, network);
    const std::string to = tx.to.isNull()
                               ? std::string("(none)")
                               : Wallet::encodeAddress(tx.to, network);

    std::cout << "Signed transaction:\n";
    std::cout << "  type:      " << Core::txTypeName(tx.tx_type) << "\n";
    std::cout << "  from:      " << from << "\n";
    std::cout << "  to:        " << to << "\n";
    if (tx.amount > 0)
      std::cout << "  amount:    " << Wallet::formatAmount(tx.amount)
                << " CLRTY\n";
    std::cout << "  fee:       " << Wallet::formatAmount(tx.fee)
              << " CLRTY\n";
    std::cout << "  nonce:     " << tx.nonce << "\n";
    std::cout << "  chain_id:  0x" << std::hex << tx.chain_id << std::dec << "\n";
    std::cout << "  size:      " << tx.serializedSize() << " bytes\n";
    std::cout << "  txid:      0x" << signing_hash.toString() << "\n";
    std::cout << "\n";

    auto bytes = tx.serialize();
    std::cout << "Raw hex (for clrty_sendRawTransaction):\n";
    std::cout << "0x" << bytesToHex(bytes.data(), bytes.size()) << "\n";
  }

  void printDryRun(const Core::Transaction &tx,
                   Wallet::Network network)
  {
    const std::string from = Wallet::encodeAddress(tx.from, network);
    const std::string to = tx.to.isNull()
                               ? std::string("(none)")
                               : Wallet::encodeAddress(tx.to, network);

    std::cout << "Unsigned transaction (dry run):\n";
    std::cout << "  type:      " << Core::txTypeName(tx.tx_type) << "\n";
    std::cout << "  from:      " << from << "\n";
    std::cout << "  to:        " << to << "\n";
    if (tx.amount > 0)
      std::cout << "  amount:    " << Wallet::formatAmount(tx.amount)
                << " CLRTY\n";
    std::cout << "  fee:       " << Wallet::formatAmount(tx.fee)
              << " CLRTY\n";
    std::cout << "  nonce:     " << tx.nonce << "\n";
    std::cout << "  chain_id:  0x" << std::hex << tx.chain_id << std::dec << "\n";
    std::cout << "  size:      " << tx.serializedSize() << " bytes\n";
    std::cout << "  signing hash:  0x" << tx.signingHash().toString() << "\n";
    std::cout << "\n";
    std::cout << "Not signed. Not submitted.\n";
  }

  void printRaw(const Core::Transaction &tx)
  {
    auto bytes = tx.serialize();
    std::cout << "0x" << bytesToHex(bytes.data(), bytes.size()) << "\n";
  }

  // ===========================================================================
  //  Sign flow
  // ===========================================================================

  int runSign(const SignArgs &args)
  {
    // ---- Open the keystore ----
    Wallet::WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::open(args.keystore, &st);
    if (!ks.has_value())
    {
      reportWalletError("cannot open keystore", st);
      return 1;
    }

    // ---- Unlock ----
    const std::string password = resolvePassword(args);
    const Wallet::WalletError err = (*ks)->unlock(password);
    if (err != Wallet::WalletError::Ok)
    {
      Wallet::WalletStatus unlock_err = Wallet::WalletStatus::fail(err, "");
      reportWalletError("cannot unlock keystore", unlock_err);
      return 1;
    }

    // ---- Resolve the signer's account address ----
    auto from_addr = Wallet::decodeAddress((*ks)->address(), (*ks)->network());
    if (!from_addr.has_value())
    {
      std::cerr << "error: keystore address is not decodable: "
                << (*ks)->address() << "\n";
      return 1;
    }

    // ---- Build the transaction ----
    const uint64_t chain_id = (*ks)->chainId();
    const Wallet::Network network = (*ks)->network();
    std::optional<Core::Transaction> tx;

    switch (args.type)
    {
    case SignType::Transfer:
    {
      Wallet::TransferParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.to = parseAddressOrDie(args.to, network, "--to");
      p.token_id = args.token_id;
      p.amount = args.amount;
      tx = Wallet::buildTransfer(*from_addr, p, &st);
      break;
    }
    case SignType::RegisterValidator:
    {
      Wallet::RegisterValidatorParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.node_key = parsePublicKeyHexOrDie(args.node_key_hex, "--node-key");
      p.stake = args.stake;
      tx = Wallet::buildRegisterValidator(*from_addr, p, &st);
      break;
    }
    case SignType::UnregisterValidator:
    {
      Wallet::StakingParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      tx = Wallet::buildUnregisterValidator(*from_addr, p, &st);
      break;
    }
    case SignType::UpdateRewardAddress:
    {
      Wallet::UpdateRewardParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.new_reward_address =
          parseAddressOrDie(args.new_address, network, "--new-address");
      tx = Wallet::buildUpdateRewardAddress(*from_addr, p, &st);
      break;
    }
    case SignType::ClaimRewards:
    {
      Wallet::StakingParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      tx = Wallet::buildClaimRewards(*from_addr, p, &st);
      break;
    }
    case SignType::OptInStaking:
    {
      Wallet::StakingParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      tx = Wallet::buildOptInStaking(*from_addr, p, &st);
      break;
    }
    case SignType::OptOutStaking:
    {
      Wallet::StakingParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      tx = Wallet::buildOptOutStaking(*from_addr, p, &st);
      break;
    }
    }

    if (!tx.has_value())
    {
      reportWalletError("cannot build transaction", st);
      return 1;
    }

    // ---- Dry run: print and exit before signing ----
    if (args.dry_run)
    {
      printDryRun(*tx, network);
      return 0;
    }

    // ---- Sign ----
    Wallet::LocalSigner signer(**ks);
    auto signing_hash = Wallet::signTransaction(*tx, signer,
                                                Wallet::clrtyPath(0, 0, 0),
                                                &st);
    if (!signing_hash.has_value())
    {
      reportWalletError("cannot sign transaction", st);
      return 1;
    }

    // ---- Output ----
    if (args.raw)
      printRaw(*tx);
    else
      printSummary(*tx, *signing_hash, network);

    return 0;
  }

  // ===========================================================================
  //  Usage
  // ===========================================================================

  void printUsage()
  {
    std::cout
        << "Usage: transaction_signer sign <type> [options]\n"
        << "\n"
        << "Types:\n"
        << "  transfer                 send CLRTY or a custom token\n"
        << "  register-validator       register this account as a validator\n"
        << "  unregister-validator     remove this account's validator\n"
        << "  update-reward-address    redirect validator rewards\n"
        << "  claim-rewards            move pending rewards into balance\n"
        << "  opt-in-staking           enable auto-staking\n"
        << "  opt-out-staking          disable auto-staking\n"
        << "\n"
        << "Common options:\n"
        << "  --keystore <path>        encrypted keystore to sign with (required)\n"
        << "  --password-file <path>   read password from file (default: prompt)\n"
        << "  --nonce <n>              transaction nonce (required)\n"
        << "  --fee <clrty>            fee in CLRTY, e.g. 0.001 (required)\n"
        << "  --raw                    print only the hex on stdout\n"
        << "  --dry-run                show the transaction without signing\n"
        << "\n"
        << "Type-specific options:\n"
        << "  transfer:              --to <addr> --amount <clrty> [--token <id>]\n"
        << "  register-validator:    --stake <clrty> --node-key <hex>\n"
        << "  update-reward-address: --new-address <addr>\n"
        << "\n"
        << "The signed hex is printed on stdout. Submit it with:\n"
        << "  curl -s http://127.0.0.1:9633 -H 'Content-Type: application/json' \\\n"
        << "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\n"
        << "         \"method\":\"clrty_sendRawTransaction\",\n"
        << "         \"params\":[\"0x...\"]}'\n";
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    printUsage();
    return 1;
  }

  const std::string top = argv[1];
  if (top == "-h" || top == "--help")
  {
    printUsage();
    return 0;
  }

  if (top != "sign")
  {
    std::cerr << "error: unknown command '" << top << "'\n\n";
    printUsage();
    return 1;
  }

  if (argc < 3)
  {
    std::cerr << "error: 'sign' requires a transaction type\n\n";
    printUsage();
    return 1;
  }

  try
  {
    SignArgs args = parseSignArgs(argc - 2, argv + 2);
    return runSign(args);
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}