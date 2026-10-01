// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Session.h"

#include "Common/PasswordPrompt.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"

#include <iostream>
#include <string>

namespace Wallet
{

  namespace
  {
    //  Report a WalletStatus failure on stderr.
    void reportWalletError(const char *prefix, const WalletStatus &st)
    {
      std::cerr << "error: " << prefix << ": ";
      if (!st.detail.empty())
        std::cerr << st.detail;
      else
        std::cerr << walletErrorMessage(st.code);
      std::cerr << "\n";
    }

    //  Parse a "0x..." hex string into a uint64_t. Returns nullopt
    //  on malformed input.
    std::optional<uint64_t> parseHexU64(const std::string &hex)
    {
      if (hex.size() < 3 || hex[0] != '0' ||
          (hex[1] != 'x' && hex[1] != 'X'))
        return std::nullopt;

      uint64_t value = 0;
      for (size_t i = 2; i < hex.size(); ++i)
      {
        const char c = hex[i];
        int nib;
        if (c >= '0' && c <= '9')
          nib = c - '0';
        else if (c >= 'a' && c <= 'f')
          nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
          nib = c - 'A' + 10;
        else
          return std::nullopt;

        if (value > (UINT64_MAX >> 4))
          return std::nullopt;
        value = (value << 4) | static_cast<uint64_t>(nib);
      }
      return value;
    }

    //  Fetch the node's chain ID via the RPC. Returns nullopt on
    //  transport error or malformed response.
    std::optional<uint64_t> fetchNodeChainId(RpcClient &rpc)
    {
      Common::Json params = Common::Json::object();
      auto result = rpc.call("chainId", params);

      if (!result.ok())
        return std::nullopt;

      if (!result.result.is_object() ||
          !result.result.contains("chain_id"))
        return std::nullopt;

      const auto &field = result.result["chain_id"];
      if (!field.is_string())
        return std::nullopt;

      return parseHexU64(field.get<std::string>());
    }
  } // anonymous namespace

  bool openKeystore(WalletSession &session,
                    const std::string &path,
                    const std::string &password_file)
  {
    if (session.hasKeystore())
    {
      std::cerr << "error: a keystore is already open ("
                << session.keystore_path << "). Use 'close' first.\n";
      return false;
    }

    WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::open(path, &st);
    if (!ks.has_value())
    {
      reportWalletError("cannot open keystore", st);
      return false;
    }

    // ---- Get the password ----
    std::string password;
    if (!password_file.empty())
    {
      auto pw = Apps::readPasswordFile(password_file);
      if (!pw.has_value())
      {
        std::cerr << "error: cannot read password file: "
                  << password_file << "\n";
        return false;
      }
      password = *pw;
    }
    else
    {
      auto pw = Apps::promptForPassword("Keystore password: ");
      if (!pw.has_value())
      {
        std::cerr << "error: could not read password\n";
        return false;
      }
      password = *pw;
    }

    // ---- Unlock ----
    const WalletError err = (*ks)->unlock(password);
    if (!password.empty())
    {
      for (auto &c : password)
        c = '\0';
    }

    if (err != WalletError::Ok)
    {
      WalletStatus unlock_err = WalletStatus::fail(err, "");
      reportWalletError("cannot unlock keystore", unlock_err);
      return false;
    }

    // ---- Decode the account address ----
    auto from_addr = Wallet::decodeAddress((*ks)->address(), (*ks)->network());
    if (!from_addr.has_value())
    {
      std::cerr << "error: keystore address is not decodable: "
                << (*ks)->address() << "\n";
      return false;
    }

    // ---- Populate the session ----
    session.keystore_path = path;
    session.keystore = std::move(*ks);
    session.signer = std::make_unique<Wallet::LocalSigner>(*session.keystore);
    session.address = *from_addr;
    session.address_bech32m = session.keystore->address();
    session.network = session.keystore->network();

    std::cout << "Unlocked " << path
              << " (" << session.address_bech32m
              << ") — " << networkName(session.currentNetwork()) << "\n";

    // ---- Cross-check the keystore's network against the node ----
    //
    // A mismatch means every transaction signed with this keystore
    // will be rejected at the RPC layer (chain_id mismatch). Better
    // to warn now than to let the user discover it on their first
    // send.
    if (session.rpc)
    {
      auto node_chain_id = fetchNodeChainId(*session.rpc);

      if (node_chain_id.has_value() && *node_chain_id != 0 &&
          *node_chain_id != session.keystore->chainId())
      {
        std::cerr << "\n";
        std::cerr << "warning: keystore was created for a different chain.\n";
        std::cerr << "  keystore network:  "
                  << networkName(session.keystore->network()) << "\n";
        std::cerr << "  keystore chain_id: 0x"
                  << std::hex << session.keystore->chainId()
                  << std::dec << "\n";
        std::cerr << "  node chain_id:     0x"
                  << std::hex << *node_chain_id
                  << std::dec << "\n";
        std::cerr << "  transactions from this keystore will be rejected.\n";
        std::cerr << "  create a keystore for this network with:\n";
        std::cerr << "    address --new --network "
                  << networkName(session.currentNetwork())
                  << " -o <name>\n";
        std::cerr << "\n";
      }
    }

    return true;
  }

  void closeKeystore(WalletSession &session)
  {
    if (!session.hasKeystore())
      return;

    //  Lock before releasing. The KeyStore destructor also locks, but
    //  being explicit makes the sequence obvious.
    session.keystore->lock();

    session.signer.reset();
    session.keystore.reset();
    session.keystore_path.clear();
    session.address.reset();
    session.address_bech32m.clear();
    session.network.reset();

    std::cout << "Keystore closed.\n";
  }

} // namespace Wallet