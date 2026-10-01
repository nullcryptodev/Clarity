// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "Crypto/Types.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/KeyStore.h"
#include "Wallet/LocalSigner.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletTypes.h"

namespace Wallet
{
  //  WalletSession
  //
  //  The state carried across commands in a single interactive
  //  session. Holds the RPC connection, the currently-open keystore
  //  (if any), and a small amount of session-scoped state.
  //
  //  Not persistent: each `clrty-wallet` invocation is a fresh
  //  session. The keystore is the only thing that survives across
  //  invocations, and it lives on disk separately.

  struct WalletSession
  {
    // ---- RPC connection ----
    Wallet::RpcEndpoint rpc_endpoint;
    std::unique_ptr<Wallet::RpcClient> rpc;

    //  True if the RPC endpoint responded to the initial probe.
    //  Set by the startup wizard; may go stale if the node stops
    //  later, but that's fine — commands re-check on each call.
    bool rpc_connected{false};

    // ---- Keystore ----
    //
    // All five are populated together when a keystore is open, and
    // all five are cleared together on `close`. `signer` wraps
    // `keystore`, so it must be destroyed before `keystore`.
    std::string keystore_path;
    std::unique_ptr<Wallet::KeyStore> keystore;
    std::unique_ptr<Wallet::LocalSigner> signer;
    std::optional<Crypto::Address> address;
    std::string address_bech32m; // cached for RPC calls
    std::optional<Wallet::Network> network;

    // ---- Session state ----
    //
    // The last submitted txid, for `status` with no argument. Not
    // persistent.
    std::optional<std::string> last_txid_hex;

    // Whether the REPL loop should continue. Set to false by the
    // `exit` and `quit` commands.
    bool running{true};

    // ---- Helpers ----

    // True if a keystore is open.
    bool hasKeystore() const noexcept { return keystore != nullptr; }

    // Convenience: the current chain ID, or 0 if no keystore is
    // open. Callers that need a chain ID should check hasKeystore
    // first.
    uint64_t chainId() const noexcept
    {
      return keystore ? keystore->chainId() : 0;
    }

    // Convenience: the current network, or Mainnet as a fallback.
    Wallet::Network currentNetwork() const noexcept
    {
      return network.value_or(Wallet::Network::Mainnet);
    }
  };

  //  Prompt for a password and open the keystore at `path`. On
  //  success, populates the keystore, signer, and address fields of
  //  `session`. On failure, prints an error and leaves the session
  //  unchanged.
  //
  //  If `password_file` is non-empty, the password is read from that
  //  file. Otherwise the user is prompted interactively.
  //
  //  Emits a warning if the keystore's chain ID does not match the
  //  connected node's chain ID — a mismatch means every transaction
  //  from this keystore will be rejected at the RPC layer.
  bool openKeystore(WalletSession &session,
                    const std::string &path,
                    const std::string &password_file);

  //  Lock and release the currently-open keystore. Idempotent — a
  //  no-op if no keystore is open.
  void closeKeystore(WalletSession &session);

} // namespace Wallet