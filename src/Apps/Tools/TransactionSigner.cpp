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
//  Bridge:
//
//    transaction_signer sign bridge-mint --keystore <path> \
//        --source-chain-id <n> --source-tx-hash <hex32> --output-index <n> \
//        --destination <addr> --amount <clrty> --signature-block <hex> \
//        --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign bridge-burn --keystore <path> \
//        --source-chain-id <n> --wrapped-token-id <n> \
//        --destination-blob <hex> --amount <clrty> \
//        --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign bridge-ack --keystore <path> \
//        --withdrawal-id <n> --signature-block <hex> \
//        --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign bridge-pause --keystore <path> \
//        --bound-height <n> --signature-block <hex> \
//        --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign bridge-unpause --keystore <path> \
//        --bound-height <n> --signature-block <hex> \
//        --fee <clrty> --nonce <n> [...]
//
//    transaction_signer sign bridge-register-chain --keystore <path> \
//        --registration-blob <hex> --signature-block <hex> \
//        --fee <clrty> --nonce <n> [...]
//
//  Governance-blob helper:
//
//    transaction_signer sign sign-governance-blob --keystore <path> \
//        --blob <hex55>
//
//  Hashes the blob under the `brgr` domain and signs the hash with
//  the keystore's key, then prints a single line "index:0x<sig>"
//  suitable for pasting into the webwallet's "Other seeds'
//  signatures" field. The index is the signer's position in the
//  active validator set at the current height, resolved via the
//  node's RPC (default 127.0.0.1:9633).
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
#include "Wallet/RpcClient.h"
#include "Wallet/TransactionBuilder.h"
#include "Wallet/WalletError.h"
#include "Wallet/WalletTypes.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Types.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

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

    // Bridge
    BridgeMint,
    BridgeBurn,
    BridgeAck,
    BridgePause,
    BridgeUnpause,
    BridgeRegisterChain,

    //  Sign a governance blob hash and print the signature.
    //  Used to collect a quorum of validator signatures for
    //  BridgeRegisterChain. Outputs a single "index:0xhex" line
    //  suitable for pasting into the webwallet's dialog.
    GovernanceBlob,
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

    // RPC endpoint (used only by sign-governance-blob to resolve
    // the signer's index in the active set). Default is the
    // operator's local node, matching clarity_wallet's default.
    std::string rpc_host{"127.0.0.1"};
    uint16_t rpc_port{9633};

    // Transfer
    std::string to;
    uint64_t amount{0};
    uint32_t token_id{0};

    // RegisterValidator
    std::string node_key_hex;
    uint64_t stake{0};

    // UpdateRewardAddress
    std::string new_address;

    // ---- Bridge ----

    // BridgeMint / BridgeBurn share source_chain_id.
    uint64_t source_chain_id{0};

    // BridgeMint
    std::string source_tx_hash_hex;
    uint32_t source_output_index{0};
    std::string destination;          // bech32m address
    std::string mint_signature_block; // hex

    // BridgeBurn
    uint64_t wrapped_token_id{0};
    std::string destination_blob_hex;
    std::string destination_address;

    // BridgeAck
    uint64_t withdrawal_id{0};

    // BridgePause / BridgeUnpause
    uint64_t bound_height{0};

    // BridgeRegisterChain
    std::string registration_blob_hex;

    // GovernanceBlob
    std::string governance_blob_hex;

    // Signature block shared by all governance / attestation
    // transactions. Stored once; used by whichever subcommand is
    // active.
    std::string signature_block_hex;
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

    if (s == "bridge-mint")
      return SignType::BridgeMint;
    if (s == "bridge-burn")
      return SignType::BridgeBurn;
    if (s == "bridge-ack")
      return SignType::BridgeAck;
    if (s == "bridge-pause")
      return SignType::BridgePause;
    if (s == "bridge-unpause")
      return SignType::BridgeUnpause;
    if (s == "bridge-register-chain")
      return SignType::BridgeRegisterChain;

    if (s == "sign-governance-blob")
      return SignType::GovernanceBlob;

    throw std::runtime_error("unknown transaction type: " + s);
  }

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

  uint32_t parseU32OrDie(const std::string &s, const char *flag)
  {
    const uint64_t v = parseU64OrDie(s, flag);
    if (v > 0xFFFFFFFFull)
      throw std::runtime_error(std::string(flag) + ": value exceeds uint32");
    return static_cast<uint32_t>(v);
  }

  //  Parse a hex string (with or without 0x prefix) into bytes.
  std::vector<uint8_t> parseHexBytesOrDie(const std::string &s,
                                          const char *flag)
  {
    size_t start = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
      start = 2;

    const size_t n = s.size() - start;
    if (n == 0 || (n & 1) != 0)
      throw std::runtime_error(
          std::string(flag) + ": hex string must have an even number of "
                              "digits after any 0x prefix");

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

    std::vector<uint8_t> out;
    out.reserve(n / 2);
    for (size_t i = start; i < s.size(); i += 2)
    {
      const int hi = nib(s[i]);
      const int lo = nib(s[i + 1]);
      if (hi < 0 || lo < 0)
        throw std::runtime_error(
            std::string(flag) + ": contains non-hex characters");
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
  }

  //  Parse a 32-byte hash. Accepts 64 hex chars, with or without 0x.
  Crypto::Hash parseHashOrDie(const std::string &s, const char *flag)
  {
    auto bytes = parseHexBytesOrDie(s, flag);
    if (bytes.size() != 32)
    {
      throw std::runtime_error(
          std::string(flag) + ": expected 32 bytes (64 hex chars), got " +
          std::to_string(bytes.size()) + " bytes");
    }
    Crypto::Hash h;
    std::memcpy(h.data.data(), bytes.data(), 32);
    return h;
  }

  //  Parse a hex id (up to 8 bytes) into a uint64.
  uint64_t parseHexU64OrDie(const std::string &s, const char *flag)
  {
    size_t i = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
      i = 2;
    if (i >= s.size() || s.size() - i > 16)
    {
      throw std::runtime_error(
          std::string(flag) + ": not a hex id: " + s);
    }
    uint64_t v = 0;
    for (; i < s.size(); ++i)
    {
      const char c = s[i];
      int nib = -1;
      if (c >= '0' && c <= '9')
        nib = c - '0';
      else if (c >= 'a' && c <= 'f')
        nib = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        nib = c - 'A' + 10;
      if (nib < 0)
      {
        throw std::runtime_error(
            std::string(flag) + ": non-hex character in: " + s);
      }
      v = (v << 4) | static_cast<uint64_t>(nib);
    }
    return v;
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
      if (arg == "--rpc")
      {
        const std::string spec = next();
        const size_t colon = spec.find(':');
        if (colon == std::string::npos || colon == 0 ||
            colon + 1 >= spec.size())
        {
          throw std::runtime_error(
              "--rpc: expected host:port, got '" + spec + "'");
        }
        args.rpc_host = spec.substr(0, colon);
        char *end = nullptr;
        const unsigned long port =
            std::strtoul(spec.c_str() + colon + 1, &end, 10);
        if (end == spec.c_str() + colon + 1 || *end != '\0' ||
            port == 0 || port > 65535)
        {
          throw std::runtime_error(
              "--rpc: invalid port in '" + spec + "'");
        }
        args.rpc_port = static_cast<uint16_t>(port);
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

      //  ---- Bridge (shared) ----
      if (arg == "--source-chain-id")
      {
        args.source_chain_id = parseU64OrDie(next(), "--source-chain-id");
        continue;
      }
      if (arg == "--signature-block")
      {
        args.signature_block_hex = next();
        continue;
      }

      //  ---- BridgeMint ----
      if (arg == "--source-tx-hash")
      {
        args.source_tx_hash_hex = next();
        continue;
      }
      if (arg == "--output-index")
      {
        args.source_output_index = parseU32OrDie(next(), "--output-index");
        continue;
      }
      if (arg == "--destination")
      {
        args.destination = next();
        continue;
      }

      //  ---- BridgeBurn ----
      if (arg == "--wrapped-token-id")
      {
        args.wrapped_token_id = parseU64OrDie(next(), "--wrapped-token-id");
        continue;
      }
      if (arg == "--destination-blob")
      {
        args.destination_blob_hex = next();
        continue;
      }
      if (arg == "--destination-address")
      {
        args.destination_address = next();
        continue;
      }

      //  ---- BridgeAck ----
      if (arg == "--withdrawal-id")
      {
        args.withdrawal_id = parseU64OrDie(next(), "--withdrawal-id");
        continue;
      }

      //  ---- BridgePause / BridgeUnpause ----
      if (arg == "--bound-height")
      {
        args.bound_height = parseU64OrDie(next(), "--bound-height");
        continue;
      }

      //  ---- BridgeRegisterChain ----
      if (arg == "--registration-blob")
      {
        args.registration_blob_hex = next();
        continue;
      }

      //  ---- GovernanceBlob ----
      if (arg == "--blob")
      {
        args.governance_blob_hex = next();
        continue;
      }

      throw std::runtime_error("unknown argument: " + arg);
    }

    //  ---- Post-parse validation ----

    if (args.keystore.empty())
      throw std::runtime_error("--keystore is required");

    //  GovernanceBlob doesn't submit a transaction, so it doesn't
    //  need a fee. Every other type does.
    if (args.fee == 0 && args.type != SignType::GovernanceBlob)
      throw std::runtime_error("--fee is required and must be non-zero");

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
      break;

    case SignType::BridgeMint:
      if (args.source_chain_id == 0)
        throw std::runtime_error("bridge-mint requires --source-chain-id");
      if (args.source_tx_hash_hex.empty())
        throw std::runtime_error("bridge-mint requires --source-tx-hash");
      if (args.destination.empty())
        throw std::runtime_error("bridge-mint requires --destination");
      if (args.amount == 0)
        throw std::runtime_error("bridge-mint requires --amount (non-zero)");
      if (args.signature_block_hex.empty())
        throw std::runtime_error("bridge-mint requires --signature-block");
      break;

    case SignType::BridgeBurn:
      if (args.source_chain_id == 0)
        throw std::runtime_error("bridge-burn requires --source-chain-id");
      if (args.wrapped_token_id == 0)
        throw std::runtime_error("bridge-burn requires --wrapped-token-id");
      if (args.destination_blob_hex.empty())
        throw std::runtime_error("bridge-burn requires --destination-blob");
      if (args.amount == 0)
        throw std::runtime_error("bridge-burn requires --amount (non-zero)");
      break;

    case SignType::BridgeAck:
      if (args.withdrawal_id == 0)
        throw std::runtime_error("bridge-ack requires --withdrawal-id");
      if (args.signature_block_hex.empty())
        throw std::runtime_error("bridge-ack requires --signature-block");
      break;

    case SignType::BridgePause:
    case SignType::BridgeUnpause:
      if (args.signature_block_hex.empty())
        throw std::runtime_error(
            "bridge-pause/bridge-unpause requires --signature-block");
      break;

    case SignType::BridgeRegisterChain:
      if (args.registration_blob_hex.empty())
        throw std::runtime_error(
            "bridge-register-chain requires --registration-blob");
      if (args.signature_block_hex.empty())
        throw std::runtime_error(
            "bridge-register-chain requires --signature-block");
      break;

    case SignType::GovernanceBlob:
      if (args.governance_blob_hex.empty())
        throw std::runtime_error(
            "sign-governance-blob requires --blob");
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

  Crypto::PublicKey parsePublicKeyHexOrDie(const std::string &s,
                                           const char *flag_name)
  {
    auto bytes = parseHexBytesOrDie(s, flag_name);
    if (bytes.size() != 32)
    {
      throw std::runtime_error(
          std::string(flag_name) + ": must be 32 bytes (64 hex chars)");
    }
    Crypto::PublicKey pk;
    std::memcpy(pk.data.data(), bytes.data(), 32);
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
    if (!tx.payload.empty())
      std::cout << "  payload:   " << tx.payload.size() << " bytes\n";
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
    if (!tx.payload.empty())
      std::cout << "  payload:   " << tx.payload.size() << " bytes\n";
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
  //  Governance blob: hash + sign, print "index:0x<sig>"
  // ===========================================================================

  //  Resolve the signer's index in the active validator set at the
  //  current height. Two RPC calls: the validator record for the
  //  keystore's address, then the active set; the index is the
  //  position of the caller's validator id in the sorted `ids`
  //  array.
  //
  //  Returns nullopt if either call fails, if the address is not
  //  a validator, or if the validator is not in the active set.
  //  The caller then prints the signature with a "?" index and a
  //  warning, so the operator can figure out the index by hand.
  std::optional<uint64_t> resolveActiveSetIndex(
      const std::string &rpc_host, uint16_t rpc_port,
      const std::string &bech32_address,
      std::string *error_out)
  {
    try
    {
      Wallet::RpcEndpoint ep;
      ep.host = rpc_host;
      ep.port = rpc_port;
      Wallet::RpcClient rpc(ep);

      std::string err;
      bool not_a_validator = false;
      auto validator = Wallet::getValidatorByAddress(
          rpc, bech32_address, &not_a_validator, &err);
      if (not_a_validator)
      {
        if (error_out)
          *error_out = "address is not a validator";
        return std::nullopt;
      }
      if (!validator.has_value() || !validator->is_object() ||
          !validator->contains("id") || !(*validator)["id"].is_string())
      {
        if (error_out)
          *error_out = err.empty() ? "getValidatorByAddress failed" : err;
        return std::nullopt;
      }
      const uint64_t my_id = parseHexU64OrDie(
          (*validator)["id"].get<std::string>(), "validator.id");

      auto active = Wallet::getActiveSet(rpc, &err);
      if (!active.has_value() || !active->is_object() ||
          !active->contains("ids") || !(*active)["ids"].is_array())
      {
        if (error_out)
          *error_out = err.empty() ? "getActiveSet failed" : err;
        return std::nullopt;
      }
      const auto &ids = (*active)["ids"];
      for (size_t i = 0; i < ids.size(); ++i)
      {
        if (!ids[i].is_string())
          continue;
        try
        {
          const std::string id_str = ids[i].get<std::string>();
          const uint64_t id_i = parseHexU64OrDie(id_str, "active_set.id");
          if (id_i == my_id)
            return static_cast<uint64_t>(i);
        }
        catch (...)
        {
          continue;
        }
      }
      if (error_out)
        *error_out = "validator is not in the active set";
      return std::nullopt;
    }
    catch (const std::exception &e)
    {
      if (error_out)
        *error_out = std::string("RPC: ") + e.what();
      return std::nullopt;
    }
  }

  int runGovernanceBlob(const SignArgs &args,
                        Wallet::KeyStore &ks)
  {
    const auto blob = parseHexBytesOrDie(args.governance_blob_hex, "--blob");
    if (blob.size() != 55)
    {
      std::cerr << "error: --blob must be 55 bytes, got "
                << blob.size() << "\n";
      return 1;
    }

    //  Hash: Blake2b("brgr" || blob), matching the executor's
    //  verifyGovernanceSignatures.
    std::vector<uint8_t> input = {'b', 'r', 'g', 'r'};
    input.insert(input.end(), blob.begin(), blob.end());

    Crypto::Hash hash;
    Crypto::blake2b(input.data(), input.size(),
                    hash.data.data(), hash.data.size());

    //  Sign the hash with the keystore's account key.
    Wallet::LocalSigner signer(ks);
    Wallet::WalletStatus st;
    auto sig = signer.signAtPath(Wallet::clrtyPath(0, 0, 0), hash, &st);
    if (!sig.has_value())
    {
      reportWalletError("cannot sign governance blob", st);
      return 1;
    }

    //  Resolve the signer's index in the active set, so the output
    //  can be pasted straight into the webwallet dialog. If the
    //  node is unreachable or the caller is not in the set, print
    //  the signature with a "?" index; the operator can resolve it
    //  from the active-set listing.
    std::string rpc_err;
    const auto index = resolveActiveSetIndex(
        args.rpc_host, args.rpc_port, ks.address(), &rpc_err);

    if (args.raw)
    {
      std::cout << "0x"
                << bytesToHex(sig->data.data(), sig->data.size())
                << "\n";
    }
    else if (index.has_value())
    {
      std::cout << *index << ":0x"
                << bytesToHex(sig->data.data(), sig->data.size())
                << "\n";
    }
    else
    {
      std::cerr << "warning: could not resolve signer index: "
                << rpc_err << "\n";
      std::cerr << "         paste this line into the webwallet dialog, "
                   "replacing '?' with the correct index\n";
      std::cout << "?:0x"
                << bytesToHex(sig->data.data(), sig->data.size())
                << "\n";
    }
    return 0;
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

    // ---- GovernanceBlob: hash and sign, no transaction ----
    if (args.type == SignType::GovernanceBlob)
      return runGovernanceBlob(args, **ks);

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

      // ---- Bridge ----

    case SignType::BridgeMint:
    {
      Wallet::BridgeMintParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.source_chain_id = args.source_chain_id;
      p.source_tx_hash = parseHashOrDie(args.source_tx_hash_hex,
                                        "--source-tx-hash");
      p.source_output_index = args.source_output_index;
      p.destination = parseAddressOrDie(args.destination, network,
                                        "--destination");
      p.amount = args.amount;
      p.signature_block = parseHexBytesOrDie(args.signature_block_hex,
                                             "--signature-block");
      tx = Wallet::buildBridgeMint(*from_addr, p, &st);
      break;
    }
    case SignType::BridgeBurn:
    {
      Wallet::BridgeBurnParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.source_chain_id = args.source_chain_id;
      p.wrapped_token_id = static_cast<Id>(args.wrapped_token_id);
      p.destination_blob = parseHexBytesOrDie(args.destination_blob_hex,
                                              "--destination-blob");
      p.destination_address = args.destination_address;
      p.amount = args.amount;
      tx = Wallet::buildBridgeBurn(*from_addr, p, &st);
      break;
    }
    case SignType::BridgeAck:
    {
      Wallet::BridgeAckWithdrawalParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.withdrawal_id = args.withdrawal_id;
      p.signature_block = parseHexBytesOrDie(args.signature_block_hex,
                                             "--signature-block");
      tx = Wallet::buildBridgeAckWithdrawal(*from_addr, p, &st);
      break;
    }
    case SignType::BridgePause:
    {
      Wallet::BridgePauseParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.bound_height = args.bound_height;
      p.signature_block = parseHexBytesOrDie(args.signature_block_hex,
                                             "--signature-block");
      tx = Wallet::buildBridgePause(*from_addr, p, &st);
      break;
    }
    case SignType::BridgeUnpause:
    {
      Wallet::BridgePauseParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.bound_height = args.bound_height;
      p.signature_block = parseHexBytesOrDie(args.signature_block_hex,
                                             "--signature-block");
      tx = Wallet::buildBridgeUnpause(*from_addr, p, &st);
      break;
    }
    case SignType::BridgeRegisterChain:
    {
      Wallet::BridgeRegisterChainParams p;
      p.common.chain_id = chain_id;
      p.common.nonce = args.nonce;
      p.common.fee = args.fee;
      p.registration_blob = parseHexBytesOrDie(args.registration_blob_hex,
                                               "--registration-blob");
      p.signature_block = parseHexBytesOrDie(args.signature_block_hex,
                                             "--signature-block");
      tx = Wallet::buildBridgeRegisterChain(*from_addr, p, &st);
      break;
    }

    case SignType::GovernanceBlob:
      //  Handled above; unreachable here.
      return 1;
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
        << "Wallet types:\n"
        << "  transfer                 send CLRTY or a custom token\n"
        << "  register-validator       register this account as a validator\n"
        << "  unregister-validator     remove this account's validator\n"
        << "  update-reward-address    redirect validator rewards\n"
        << "  claim-rewards            move pending rewards into balance\n"
        << "  opt-in-staking           enable auto-staking\n"
        << "  opt-out-staking          disable auto-staking\n"
        << "\n"
        << "Bridge types:\n"
        << "  bridge-mint              mint wrapped tokens from a deposit\n"
        << "  bridge-burn              burn wrapped tokens, enqueue withdrawal\n"
        << "  bridge-ack               ack a released withdrawal\n"
        << "  bridge-pause             pause the bridge (governance)\n"
        << "  bridge-unpause           unpause the bridge (governance)\n"
        << "  bridge-register-chain    register a new source chain\n"
        << "  sign-governance-blob     sign a governance blob hash; prints\n"
        << "                           'index:0x<sig>' for the webwallet\n"
        << "\n"
        << "Common options:\n"
        << "  --keystore <path>        encrypted keystore to sign with (required)\n"
        << "  --password-file <path>   read password from file (default: prompt)\n"
        << "  --nonce <n>              transaction nonce (required)\n"
        << "  --fee <clrty>            fee in CLRTY, e.g. 0.001\n"
        << "  --raw                    print only the hex on stdout\n"
        << "  --dry-run                show the transaction without signing\n"
        << "  --rpc <host:port>        RPC endpoint for the index lookup\n"
        << "                           (default 127.0.0.1:9633; only used\n"
        << "                           by sign-governance-blob)\n"
        << "\n"
        << "Wallet-specific options:\n"
        << "  transfer:              --to <addr> --amount <clrty> [--token <id>]\n"
        << "  register-validator:    --stake <clrty> --node-key <hex>\n"
        << "  update-reward-address: --new-address <addr>\n"
        << "\n"
        << "Bridge-specific options:\n"
        << "  bridge-mint:           --source-chain-id <n> --source-tx-hash <hex32>\n"
        << "                         --output-index <n> --destination <addr>\n"
        << "                         --amount <clrty> --signature-block <hex>\n"
        << "  bridge-burn:           --source-chain-id <n> --wrapped-token-id <n>\n"
        << "                         --destination-blob <hex>\n"
        << "                         --destination-address <base58>\n"
        << "                         --amount <clrty>\n"
        << "  bridge-ack:            --withdrawal-id <n> --signature-block <hex>\n"
        << "  bridge-pause:          --bound-height <n> --signature-block <hex>\n"
        << "  bridge-unpause:        --bound-height <n> --signature-block <hex>\n"
        << "  bridge-register-chain: --registration-blob <hex>\n"
        << "                         --signature-block <hex>\n"
        << "  sign-governance-blob:  --blob <hex55>\n"
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