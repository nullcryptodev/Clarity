// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//  Address — keystore utility
//
//  Creates, imports, and inspects CLRTY keystores. A keystore carries
//  a single BIP-39 mnemonic from which two keys are derived:
//
//    - the reward address (receive path, m/44'/9000'/0'/0'/0')
//    - the validator consensus key (validator path, m/44'/9000'/0'/2'/0')
//
//  Both keys are recoverable from the mnemonic.
//
//  Subcommands:
//    --new, -n           create a fresh keystore
//    --import, -i        import an existing mnemonic
//    --show, -s          display every key in an existing keystore
//    --from-mnemonic     derive and print keys from a mnemonic, no
//                        keystore written
//
//  Output discipline:
//    stdout  — the mnemonic, keys, and metadata. Redirectable.
//    stderr  — prompts and narration. Never contains secrets.
//
//  --new and --import always print the full key set for all three
//  networks. --show-secret adds raw hex secrets to the output; it is
//  accepted by all four subcommands.
//
//  --show-secret prints private key material in plaintext. It is
//  documented as dangerous. Use it when you need to hand a key to the
//  daemon (--consensus-key) or to back it up out of band.

#include "Wallet/AddressCodec.h"
#include "Wallet/Bip39.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/HdPath.h"
#include "Wallet/KeyStoreFormat.h"
#include "Wallet/WalletError.h"
#include "Wallet/WalletTypes.h"

#include "Crypto/Types.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#endif

namespace
{
  using Wallet::Network;

  //  ---- Argument helpers ----

  std::optional<Network> parseNetwork(const std::string &s)
  {
    if (s == "mainnet")
      return Network::Mainnet;
    if (s == "testnet")
      return Network::Testnet;
    if (s == "regtest")
      return Network::Regtest;
    return std::nullopt;
  }

  std::string withDefaultKeystoreExtension(const std::string &path)
  {
    std::filesystem::path p(path);
    if (p.extension().empty())
      p += ".ks";
    return p.string();
  }

  //  ---- Formatting helpers ----

  std::string fingerprintHex(const Wallet::SeedFingerprint &fp)
  {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(8);
    for (size_t i = 0; i < 4; ++i)
    {
      uint8_t b = fp.bytes[i];
      out.push_back(hex[b >> 4]);
      out.push_back(hex[b & 0x0F]);
    }
    return out;
  }

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

  std::string secretToHex(const Crypto::SecretKey &sk)
  {
    return bytesToHex(sk.data.data(), sk.data.size());
  }

  std::string pubkeyToHex(const Crypto::PublicKey &pk)
  {
    return bytesToHex(pk.data.data(), pk.data.size());
  }

  std::string pad(const std::string &s, size_t width)
  {
    if (s.size() >= width)
      return s;
    return s + std::string(width - s.size(), ' ');
  }

  //  ---- Password prompting ----

#if defined(__unix__) || defined(__APPLE__)
  std::string readLineNoEcho(const char *prompt)
  {
    std::fputs(prompt, stderr);
    std::fflush(stderr);

    std::string line;
    if (::isatty(::fileno(stdin)))
    {
      termios oldt{};
      ::tcgetattr(::fileno(stdin), &oldt);
      termios newt = oldt;
      newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
      ::tcsetattr(::fileno(stdin), TCSANOW, &newt);
      std::getline(std::cin, line);
      ::tcsetattr(::fileno(stdin), TCSANOW, &oldt);
      std::fputs("\n", stderr);
    }
    else
    {
      std::getline(std::cin, line);
    }
    return line;
  }
#else
  std::string readLineNoEcho(const char *prompt)
  {
    std::fputs(prompt, stderr);
    std::fflush(stderr);
    std::string line;
    std::getline(std::cin, line);
    return line;
  }
#endif

  std::optional<std::string> promptForNewPassword()
  {
    std::string pw1 = readLineNoEcho("Password: ");
    if (pw1.empty())
    {
      std::cerr << "error: password must not be empty\n";
      return std::nullopt;
    }
    std::string pw2 = readLineNoEcho("Confirm password: ");
    if (pw1 != pw2)
    {
      std::cerr << "error: passwords do not match\n";
      return std::nullopt;
    }
    return pw1;
  }

  //  ---- Error reporting ----

  void reportError(const char *prefix, Wallet::WalletStatus st)
  {
    std::cerr << "error: " << prefix << ": ";
    if (!st.detail.empty())
      std::cerr << st.detail;
    else
      std::cerr << Wallet::walletErrorMessage(st.code);
    std::cerr << "\n";
  }

  //  ---- Usage ----

  void printUsage()
  {
    std::cout
        << "Usage: Address <command> [options]\n"
        << "\n"
        << "Commands:\n"
        << "  --new, -n           -o <path> [options]  create a fresh keystore\n"
        << "  --import, -i        -o <path> [options]  import an existing mnemonic\n"
        << "  --show, -s          <path> [options]     display all keys in a keystore\n"
        << "  --from-mnemonic     <words> [options]    derive keys from a mnemonic\n"
        << "\n"
        << "Options:\n"
        << "  -o <path>            output path (required for --new and --import).\n"
        << "                       A \".ks\" extension is added if none is present.\n"
        << "  --network <name>     mainnet | testnet | regtest (default: mainnet)\n"
        << "  --strength <bits>    for --new: 128 | 160 | 192 | 224 | 256\n"
        << "                       (default: 256)\n"
        << "  --passphrase <text>  for --import/--from-mnemonic: BIP-39 passphrase\n"
        << "  --all-networks       for --show/--from-mnemonic: print mainnet, testnet,\n"
        << "                       and regtest reward addresses in one run\n"
        << "  --show-secret        also print raw hex secrets. Accepted by all\n"
        << "                       subcommands. DANGEROUS. See below.\n"
        << "\n"
        << "Both the reward address and the validator consensus key are derived\n"
        << "from the same mnemonic. Backing up the words backs up both keys.\n"
        << "\n"
        << "--new and --import always print the full key set for all three\n"
        << "networks. --show and --from-mnemonic print one network by default;\n"
        << "pass --all-networks to see all three.\n"
        << "\n"
        << "--show-secret prints private key material in plaintext to stdout.\n"
        << "Anyone who sees the output can sign on your behalf. Do not run it\n"
        << "in a logged terminal, do not redirect stdout to an unprotected file,\n"
        << "and do not paste the output anywhere it can be captured.\n";
  }

  //  ---- Mnemonic display ----

  void printMnemonic(std::ostream &os, const std::string &mnemonic)
  {
    std::size_t start = 0;
    int words_on_line = 0;

    while (start < mnemonic.size())
    {
      std::size_t end = mnemonic.find(' ', start);
      if (end == std::string::npos)
        end = mnemonic.size();

      os << mnemonic.substr(start, end - start);
      ++words_on_line;

      if (end >= mnemonic.size())
        break;

      start = end + 1;

      if (words_on_line == 6)
      {
        os << "\n";
        words_on_line = 0;
      }
      else
      {
        os << " ";
      }
    }
    os << "\n";
  }

  //  ---- Key display ----

  const char *networkLabel(Network n)
  {
    switch (n)
    {
    case Network::Mainnet:
      return "mainnet";
    case Network::Testnet:
      return "testnet";
    case Network::Regtest:
      return "regtest";
    }
    return "unknown";
  }

  struct DerivedKeys
  {
    std::string reward_address_mainnet;
    std::string reward_address_testnet;
    std::string reward_address_regtest;

    std::string reward_pubkey_hex;
    std::string consensus_pubkey_hex;

    std::string reward_secret_hex;
    std::string consensus_secret_hex;

    std::string reward_derivation;
    std::string consensus_derivation;
  };

  std::optional<DerivedKeys> deriveAllKeys(Wallet::KeyStore &ks)
  {
    DerivedKeys out;

    auto reward = ks.derive(Wallet::receivePath(0, 0));
    if (!reward.has_value())
      return std::nullopt;

    auto consensus = ks.derive(Wallet::validatorPath(0));
    if (!consensus.has_value())
      return std::nullopt;

    out.reward_address_mainnet =
        Wallet::encodeAddress(reward->pubkey, Network::Mainnet);
    out.reward_address_testnet =
        Wallet::encodeAddress(reward->pubkey, Network::Testnet);
    out.reward_address_regtest =
        Wallet::encodeAddress(reward->pubkey, Network::Regtest);

    out.reward_pubkey_hex = pubkeyToHex(reward->pubkey);
    out.consensus_pubkey_hex = pubkeyToHex(consensus->pubkey);

    out.reward_secret_hex = secretToHex(reward->secret);
    out.consensus_secret_hex = secretToHex(consensus->secret);

    out.reward_derivation = Wallet::receivePath(0, 0).toString();
    out.consensus_derivation = Wallet::validatorPath(0).toString();

    return out;
  }

  void printFullKeySet(Wallet::KeyStore &ks,
                       const DerivedKeys &keys,
                       bool show_secrets)
  {
    std::cout << "==================== KEYSTORE ====================\n";
    std::cout << "\n";
    std::cout << "  path          : " << ks.name() << "\n";
    std::cout << "  fingerprint   : " << fingerprintHex(ks.fingerprint()) << "\n";
    std::cout << "  unlocked      : " << (ks.isUnlocked() ? "yes" : "no") << "\n";

    std::cout << "\n";
    std::cout << "  ---- reward address ----\n";
    std::cout << "  (same key on every network; only the HRP differs)\n";
    std::cout << "\n";
    std::cout << "  mainnet       : " << keys.reward_address_mainnet << "\n";
    std::cout << "  testnet       : " << keys.reward_address_testnet << "\n";
    std::cout << "  regtest       : " << keys.reward_address_regtest << "\n";
    std::cout << "\n";
    std::cout << "  pubkey        : " << keys.reward_pubkey_hex << "\n";
    std::cout << "  derivation    : " << keys.reward_derivation << "\n";

    if (show_secrets)
    {
      std::cout << "  secret        : " << keys.reward_secret_hex << "\n"; // use --consensus-key with clarityd
    }

    std::cout << "\n";
    std::cout << "  ---- validator consensus key ----\n";
    std::cout << "\n";
    std::cout << "  pubkey        : " << keys.consensus_pubkey_hex << "\n"; // goes into global config if seed
    std::cout << "  derivation    : " << keys.consensus_derivation << "\n";

    if (show_secrets)
    {
      std::cout << "  secret        : " << keys.consensus_secret_hex << "\n";
    }

    std::cout << "\n";
    std::cout << "  The consensus key is identical across all three networks.\n";
    std::cout << "  It's the key the daemon signs consensus messages with.\n";
    std::cout << "  Feed its secret to clarityd via --consensus-key.\n";

    if (show_secrets)
    {
      std::cout << "\n";
      std::cerr << "!!\n";
      std::cerr << "!! The secrets above are private key material.\n";
      std::cerr << "!! Anyone who sees them can sign on your behalf.\n";
      std::cerr << "!! Store them with the same care as the mnemonic.\n";
      std::cerr << "!!\n";
    }

    std::cout << "\n";
  }

  void printKeySet(Wallet::KeyStore &ks,
                   const DerivedKeys &keys,
                   Network network,
                   bool all_networks,
                   bool show_secrets)
  {
    std::cout << "==================== KEYSTORE ====================\n";
    std::cout << "\n";
    std::cout << "  path          : " << ks.name() << "\n";
    std::cout << "  fingerprint   : " << fingerprintHex(ks.fingerprint()) << "\n";
    std::cout << "  unlocked      : " << (ks.isUnlocked() ? "yes" : "no") << "\n";

    std::cout << "\n";
    std::cout << "  ---- reward address ----\n";
    std::cout << "\n";
    if (all_networks)
    {
      std::cout << "  mainnet       : " << keys.reward_address_mainnet << "\n";
      std::cout << "  testnet       : " << keys.reward_address_testnet << "\n";
      std::cout << "  regtest       : " << keys.reward_address_regtest << "\n";
    }
    else
    {
      const std::string &addr =
          (network == Network::Mainnet)   ? keys.reward_address_mainnet
          : (network == Network::Testnet) ? keys.reward_address_testnet
                                          : keys.reward_address_regtest;
      std::cout << "  " << pad(networkLabel(network), 13) << " : " << addr << "\n";
    }
    std::cout << "\n";
    std::cout << "  pubkey        : " << keys.reward_pubkey_hex << "\n";
    std::cout << "  derivation    : " << keys.reward_derivation << "\n";

    if (show_secrets)
    {
      std::cout << "  secret        : " << keys.reward_secret_hex << "\n";
    }

    std::cout << "\n";
    std::cout << "  ---- validator consensus key ----\n";
    std::cout << "\n";
    std::cout << "  pubkey        : " << keys.consensus_pubkey_hex << "\n";
    std::cout << "  derivation    : " << keys.consensus_derivation << "\n";

    if (show_secrets)
    {
      std::cout << "  secret        : " << keys.consensus_secret_hex << "\n";
    }

    if (show_secrets)
    {
      std::cout << "\n";
      std::cerr << "!!\n";
      std::cerr << "!! The secrets above are private key material.\n";
      std::cerr << "!! Anyone who sees them can sign on your behalf.\n";
      std::cerr << "!! Store them with the same care as the mnemonic.\n";
      std::cerr << "!!\n";
    }

    std::cout << "\n";
  }

  //  ---- Subcommands ----

  int cmdNew(int argc, char **argv)
  {
    std::string out_path;
    Network network = Network::Mainnet;
    uint32_t strength = 256;
    bool show_secrets = false;

    for (int i = 0; i < argc; ++i)
    {
      std::string arg = argv[i];

      if ((arg == "-o" || arg == "--output") && i + 1 < argc)
      {
        out_path = argv[++i];
      }
      else if (arg == "--network" && i + 1 < argc)
      {
        auto n = parseNetwork(argv[++i]);
        if (!n)
        {
          std::cerr << "error: unknown network '" << argv[i] << "'\n";
          return 1;
        }
        network = *n;
      }
      else if (arg == "--strength" && i + 1 < argc)
      {
        strength = static_cast<uint32_t>(std::stoul(argv[++i]));
      }
      else if (arg == "--show-secret")
      {
        show_secrets = true;
      }
      else
      {
        std::cerr << "error: unknown argument '" << arg << "'\n";
        return 1;
      }
    }

    if (out_path.empty())
    {
      std::cerr << "error: -o <path> is required\n";
      return 1;
    }

    out_path = withDefaultKeystoreExtension(out_path);

    if (std::filesystem::exists(out_path))
    {
      std::cerr << "error: refusing to overwrite existing file: "
                << out_path << "\n";
      return 1;
    }

    auto password = promptForNewPassword();
    if (!password)
      return 1;

    std::cerr << "Generating mnemonic and writing keystore...\n";

    std::string mnemonic;
    Wallet::WalletStatus st;

    auto ks = Wallet::EncryptedKeyStore::create(
        out_path, *password, network, strength, mnemonic,
        Wallet::KDF_ARGON2ID, &st);

    if (!ks)
    {
      reportError("failed to create keystore", st);
      std::fill(password->begin(), password->end(), '\0');
      return 1;
    }

    auto keys = deriveAllKeys(**ks);
    if (!keys.has_value())
    {
      std::cerr << "error: could not derive keys from the new keystore\n";
      std::fill(mnemonic.begin(), mnemonic.end(), '\0');
      std::fill(password->begin(), password->end(), '\0');
      return 1;
    }

    std::cout << "\n";
    std::cout << "==================== MNEMONIC ====================\n";
    std::cout << "\n";
    printMnemonic(std::cout, mnemonic);
    std::cout << "\n";
    std::cout << "Anyone with this mnemonic can spend your funds.\n";
    std::cout << "Write it down. Store it offline. Never share it.\n";
    std::cout << "\n";

    printFullKeySet(**ks, *keys, show_secrets);

    std::fill(mnemonic.begin(), mnemonic.end(), '\0');
    std::fill(password->begin(), password->end(), '\0');

    return 0;
  }

  int cmdImport(int argc, char **argv)
  {
    std::string out_path;
    Network network = Network::Mainnet;
    std::string passphrase;
    bool show_secrets = false;

    for (int i = 0; i < argc; ++i)
    {
      std::string arg = argv[i];

      if ((arg == "-o" || arg == "--output") && i + 1 < argc)
      {
        out_path = argv[++i];
      }
      else if (arg == "--network" && i + 1 < argc)
      {
        auto n = parseNetwork(argv[++i]);
        if (!n)
        {
          std::cerr << "error: unknown network '" << argv[i] << "'\n";
          return 1;
        }
        network = *n;
      }
      else if (arg == "--passphrase" && i + 1 < argc)
      {
        passphrase = argv[++i];
      }
      else if (arg == "--show-secret")
      {
        show_secrets = true;
      }
      else
      {
        std::cerr << "error: unknown argument '" << arg << "'\n";
        return 1;
      }
    }

    if (out_path.empty())
    {
      std::cerr << "error: -o <path> is required\n";
      return 1;
    }

    out_path = withDefaultKeystoreExtension(out_path);

    if (std::filesystem::exists(out_path))
    {
      std::cerr << "error: refusing to overwrite existing file: "
                << out_path << "\n";
      return 1;
    }

    std::cerr << "Mnemonic (one line, space-separated): ";
    std::string mnemonic;
    if (!std::getline(std::cin, mnemonic) || mnemonic.empty())
    {
      std::cerr << "error: no mnemonic provided\n";
      return 1;
    }

    {
      Wallet::WalletError err = Wallet::validateMnemonic(mnemonic);
      if (err != Wallet::WalletError::Ok)
      {
        std::cerr << "error: invalid mnemonic: "
                  << Wallet::walletErrorMessage(err) << "\n";
        std::fill(mnemonic.begin(), mnemonic.end(), '\0');
        return 1;
      }
    }

    auto password = promptForNewPassword();
    if (!password)
    {
      std::fill(mnemonic.begin(), mnemonic.end(), '\0');
      return 1;
    }

    std::cerr << "Deriving seed and writing keystore...\n";

    Wallet::WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::createFromMnemonic(
        out_path, *password, network, mnemonic, passphrase,
        Wallet::KDF_ARGON2ID, &st);

    if (!ks)
    {
      reportError("failed to import keystore", st);
      std::fill(mnemonic.begin(), mnemonic.end(), '\0');
      std::fill(password->begin(), password->end(), '\0');
      return 1;
    }

    auto keys = deriveAllKeys(**ks);
    if (!keys.has_value())
    {
      std::cerr << "error: could not derive keys from the imported keystore\n";
      std::fill(mnemonic.begin(), mnemonic.end(), '\0');
      std::fill(password->begin(), password->end(), '\0');
      return 1;
    }

    std::cout << "\n";

    printFullKeySet(**ks, *keys, show_secrets);

    std::fill(mnemonic.begin(), mnemonic.end(), '\0');
    std::fill(password->begin(), password->end(), '\0');

    return 0;
  }

  int cmdShow(int argc, char **argv)
  {
    if (argc < 1)
    {
      std::cerr << "error: --show requires a keystore path\n";
      return 1;
    }

    std::string path = argv[0];
    bool show_secrets = false;
    bool all_networks = false;

    for (int i = 1; i < argc; ++i)
    {
      std::string arg = argv[i];
      if (arg == "--show-secret")
        show_secrets = true;
      else if (arg == "--all-networks")
        all_networks = true;
      else
      {
        std::cerr << "error: unknown argument '" << arg << "'\n";
        return 1;
      }
    }

    Wallet::WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::open(path, &st);
    if (!ks.has_value())
    {
      reportError("cannot open keystore", st);
      return 1;
    }

    auto password = readLineNoEcho("Keystore password: ");
    if (password.empty())
    {
      std::cerr << "error: password must not be empty\n";
      return 1;
    }

    const Wallet::WalletError err = (*ks)->unlock(password);
    std::fill(password.begin(), password.end(), '\0');

    if (err != Wallet::WalletError::Ok)
    {
      Wallet::WalletStatus unlock_err = Wallet::WalletStatus::fail(err, "");
      reportError("cannot unlock keystore", unlock_err);
      return 1;
    }

    auto keys = deriveAllKeys(**ks);
    if (!keys.has_value())
    {
      std::cerr << "error: could not derive keys from the keystore\n";
      return 1;
    }

    printKeySet(**ks, *keys, (*ks)->network(), all_networks, show_secrets);
    return 0;
  }

  int cmdFromMnemonic(int argc, char **argv)
  {
    if (argc < 1)
    {
      std::cerr << "error: --from-mnemonic requires a mnemonic argument\n";
      return 1;
    }

    std::string mnemonic = argv[0];
    Network network = Network::Mainnet;
    std::string passphrase;
    bool show_secrets = false;
    bool all_networks = false;

    for (int i = 1; i < argc; ++i)
    {
      std::string arg = argv[i];
      if (arg == "--network" && i + 1 < argc)
      {
        auto n = parseNetwork(argv[++i]);
        if (!n)
        {
          std::cerr << "error: unknown network '" << argv[i] << "'\n";
          return 1;
        }
        network = *n;
      }
      else if (arg == "--passphrase" && i + 1 < argc)
      {
        passphrase = argv[++i];
      }
      else if (arg == "--show-secret")
      {
        show_secrets = true;
      }
      else if (arg == "--all-networks")
      {
        all_networks = true;
      }
      else
      {
        std::cerr << "error: unknown argument '" << arg << "'\n";
        return 1;
      }
    }

    {
      Wallet::WalletError err = Wallet::validateMnemonic(mnemonic);
      if (err != Wallet::WalletError::Ok)
      {
        std::cerr << "error: invalid mnemonic: "
                  << Wallet::walletErrorMessage(err) << "\n";
        return 1;
      }
    }

    namespace fs = std::filesystem;
    const auto tmp_dir = fs::temp_directory_path();
    const auto tmp_path = tmp_dir / ("clrty_mnemonic_" +
                                     std::to_string(::getpid()) + ".ks");

    std::error_code ec;
    fs::remove(tmp_path, ec);

    Wallet::WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::createFromMnemonic(
        tmp_path.string(), /*password=*/"", network, mnemonic, passphrase,
        Wallet::KDF_ARGON2ID, &st);

    if (!ks)
    {
      reportError("failed to derive from mnemonic", st);
      fs::remove(tmp_path, ec);
      return 1;
    }

    auto keys = deriveAllKeys(**ks);
    if (!keys.has_value())
    {
      std::cerr << "error: could not derive keys from the mnemonic\n";
      (*ks)->lock();
      ks.reset();
      fs::remove(tmp_path, ec);
      return 1;
    }

    printKeySet(**ks, *keys, network, all_networks, show_secrets);

    (*ks)->lock();
    ks.reset();
    fs::remove(tmp_path, ec);

    return 0;
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    printUsage();
    return 1;
  }

  std::string cmd = argv[1];
  int remaining = argc - 2;
  char **rest = argv + 2;

  if (cmd == "--new" || cmd == "-n")
    return cmdNew(remaining, rest);
  if (cmd == "--import" || cmd == "-i")
    return cmdImport(remaining, rest);
  if (cmd == "--show" || cmd == "-s")
    return cmdShow(remaining, rest);
  if (cmd == "--from-mnemonic")
    return cmdFromMnemonic(remaining, rest);
  if (cmd == "--help" || cmd == "-h")
  {
    printUsage();
    return 0;
  }

  std::cerr << "error: unknown command '" << cmd << "'\n\n";
  printUsage();
  return 1;
}