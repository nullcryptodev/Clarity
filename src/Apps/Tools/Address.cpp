// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//  Address — keystore generator
//
//  A small CLI for producing a CLRTY keystore file from a mnemonic.
//  It does not sign, does not talk to a chain, and does not unlock for
//  any reason other than creation. Its job is to turn a mnemonic
//  (fresh or supplied) into a keystore on disk, and to print the
//  details a user needs to back it up.
//
//  Output discipline:
//    stdout  — the mnemonic (--new only), address, fingerprint, metadata.
//              This is the data the user must save.
//    stderr  — prompts and narration. Kept out of any file the user
//              pipes stdout to.

#include "Wallet/Bip39.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/KeyStoreFormat.h"
#include "Wallet/WalletError.h"
#include "Wallet/WalletTypes.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
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

  //  ---- Fingerprint formatting ----
  //
  //  SeedFingerprint is a 4-byte value with a toHex() method, but we
  //  compute the hex here so the tool works even if the type is
  //  changed to remove toHex().

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

  //  ---- Errors ----

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
        << "  --new, -n    -o <path> [options]    generate a fresh keystore\n"
        << "  --import, -i -o <path> [options]    import an existing mnemonic\n"
        << "\n"
        << "Options:\n"
        << "  -o <path>            output keystore path (required)\n"
        << "  --network <name>     mainnet | testnet | regtest\n"
        << "                       (default: mainnet)\n"
        << "\n"
        << "Options for New:\n"
        << "  --strength <bits>    128 | 160 | 192 | 224 | 256\n"
        << "                       (default: 256, i.e. 24 words)\n"
        << "\n"
        << "Options for Import:\n"
        << "  --passphrase <text>  BIP-39 passphrase, the optional\n"
        << "                       \"25th word\" (default: empty)\n"
        << "\n"
        << "The keystore is written to <path>; the mnemonic and address\n"
        << "are printed to stdout. Passwords are prompted on stderr.\n";
  }

  //  ---- Subcommands ----

  int cmdNew(int argc, char **argv)
  {
    std::string out_path;
    Network network = Network::Mainnet;
    uint32_t strength = 256;

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

    //  Use the concrete EncryptedKeyStore::create directly. This
    //  returns std::optional<std::unique_ptr<EncryptedKeyStore>>, so
    //  every method call below resolves against EncryptedKeyStore's
    //  fully-visible class definition.
    auto ks = Wallet::EncryptedKeyStore::create(
        out_path, *password, network, strength, mnemonic,
        Wallet::KDF_ARGON2ID, &st);

    if (!ks)
    {
      reportError("failed to create keystore", st);
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
    std::cout << "==================== KEYSTORE ====================\n";
    std::cout << "\n";
    std::cout << "  path         : " << (*ks)->name() << "\n";
    std::cout << "  network      : " << Wallet::networkName(network) << "\n";
    std::cout << "  chain_id     : " << (*ks)->chainId() << "\n";
    std::cout << "  address      : " << (*ks)->address() << "\n";
    std::cout << "  fingerprint  : " << fingerprintHex((*ks)->fingerprint()) << "\n";
    std::cout << "  unlocked     : " << ((*ks)->isUnlocked() ? "yes" : "no") << "\n";
    std::cout << "\n";

    std::fill(mnemonic.begin(), mnemonic.end(), '\0');
    std::fill(password->begin(), password->end(), '\0');

    return 0;
  }

  int cmdImport(int argc, char **argv)
  {
    std::string out_path;
    Network network = Network::Mainnet;
    std::string passphrase;

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

    std::cout << "\n";
    std::cout << "==================== KEYSTORE ====================\n";
    std::cout << "\n";
    std::cout << "  path         : " << (*ks)->name() << "\n";
    std::cout << "  network      : " << Wallet::networkName(network) << "\n";
    std::cout << "  chain_id     : " << (*ks)->chainId() << "\n";
    std::cout << "  address      : " << (*ks)->address() << "\n";
    std::cout << "  fingerprint  : " << fingerprintHex((*ks)->fingerprint()) << "\n";
    std::cout << "  unlocked     : " << ((*ks)->isUnlocked() ? "yes" : "no") << "\n";
    std::cout << "\n";

    std::fill(mnemonic.begin(), mnemonic.end(), '\0');
    std::fill(password->begin(), password->end(), '\0');

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

  std::cerr << "Generates a password-encrypted Clarity keystore from a fresh or supplied BIP-39 mnemonic." << std::endl
            << "It prints the mnemonic, bech32m address, and seed fingerprint for backup." << std::endl
            << std::endl;

  std::cerr << "Anyone with your mnemonic can spend your funds!" << std::endl
            << "Write it down. Store it offline. Never share it." << std::endl
            << std::endl;

  std::string cmd = argv[1];
  int remaining = argc - 2;
  char **rest = argv + 2;

  if (cmd == "--new" || cmd == "-n")
    return cmdNew(remaining, rest);
  if (cmd == "--import" || cmd == "-i")
    return cmdImport(remaining, rest);
  if (cmd == "--help" || cmd == "-h")
  {
    printUsage();
    return 0;
  }

  std::cerr << "error: unknown command '" << cmd << "'\n\n";
  printUsage();
  return 1;
}