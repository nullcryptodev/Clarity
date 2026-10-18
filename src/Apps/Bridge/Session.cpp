// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Session.h"

#include "ChainAdapter.h"
#include "WatcherConfig.h"

#include "Common/PasswordPrompt.h"
#include "Common/StringTools.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"

#include <chrono>
#include <iostream>
#include <string>

namespace Bridge
{

  namespace
  {
    // Report a WalletStatus failure on stderr. Same helper as
    // Wallet::Session.cpp; duplicated because the Wallet namespace
    // doesn't export it.
    void reportWalletError(const char *prefix, const Wallet::WalletStatus &st)
    {
      std::cerr << "error: " << prefix << ": ";
      if (!st.detail.empty())
        std::cerr << st.detail;
      else
        std::cerr << Wallet::walletErrorMessage(st.code);
      std::cerr << "\n";
    }

    // Parse a host:port string into the two fields. Used by
    // ChainRuntime::reconnect (which is in the header but
    // references this via free function), and by the wizard when
    // the operator enters a custom endpoint.
    bool parseEndpointSpec(const std::string &spec,
                           std::string &host_out,
                           uint16_t &port_out)
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

      host_out = host;
      port_out = static_cast<uint16_t>(port);
      return true;
    }
  } // anonymous namespace

  // ===========================================================================
  // WatcherSession — accessors
  // ===========================================================================

  ChainRuntime *WatcherSession::current() noexcept
  {
    if (current_chain.empty())
      return nullptr;
    auto it = chains.find(current_chain);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  const ChainRuntime *WatcherSession::current() const noexcept
  {
    if (current_chain.empty())
      return nullptr;
    auto it = chains.find(current_chain);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  ChainRuntime *WatcherSession::findChain(const std::string &short_name) noexcept
  {
    auto it = chains.find(short_name);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  const ChainRuntime *WatcherSession::findChain(
      const std::string &short_name) const noexcept
  {
    auto it = chains.find(short_name);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  bool WatcherSession::selectChain(const std::string &short_name)
  {
    auto it = chains.find(short_name);
    if (it == chains.end())
      return false;
    if (!it->second.enabled)
      return false;
    current_chain = short_name;
    return true;
  }

  ChainRuntime *WatcherSession::enableChain(
      std::shared_ptr<ChainAdapter> adapter,
      ChainWatcherConfig config)
  {
    if (!adapter)
      return nullptr;

    const std::string short_name = adapter->short_name();

    // Fill in any missing defaults. The wizard should have done
    // this already, but enableChain is also called from the CLI
    // path and from tests, so it's defensive.
    applyAdapterDefaults(*adapter, config);

    ChainRuntime rt;
    rt.adapter = std::move(adapter);
    rt.config = std::move(config);
    rt.enabled = true;
    rt.reconnect(); // creates rpc from config

    auto [it, inserted] = chains.insert_or_assign(short_name, std::move(rt));

    // If this is the first chain, select it as the current chain.
    if (current_chain.empty())
      current_chain = short_name;

    return &it->second;
  }

  ChainRuntime *WatcherSession::enableChainByShortName(
      const std::string &short_name, bool replace_existing)
  {
    // Reuse if already present and not replacing.
    if (!replace_existing)
    {
      auto existing = chains.find(short_name);
      if (existing != chains.end() && existing->second.enabled)
        return &existing->second;
    }

    auto adapter = ChainAdapterRegistry::find(short_name);
    if (!adapter)
      return nullptr;

    ChainWatcherConfig cfg;
    cfg.chain_short_name = short_name;
    cfg.enabled = true;
    // rpc_host / rpc_port / confirmation_depth are filled in by
    // applyAdapterDefaults inside enableChain.

    return enableChain(std::move(adapter), std::move(cfg));
  }

  std::optional<ChainWatcherConfig> WatcherSession::defaultConfigFor(
      const std::string &short_name) const
  {
    auto adapter = ChainAdapterRegistry::find(short_name);
    if (!adapter)
      return std::nullopt;

    ChainWatcherConfig cfg;
    cfg.chain_short_name = short_name;
    cfg.enabled = true;
    applyAdapterDefaults(*adapter, cfg);
    return cfg;
  }

  size_t WatcherSession::enabledChainCount() const noexcept
  {
    size_t n = 0;
    for (const auto &[name, rt] : chains)
    {
      (void)name;
      if (rt.enabled)
        ++n;
    }
    return n;
  }

  void WatcherSession::reset()
  {
    // Close keystore first (locks it, nulls signer, etc.), then
    // destroy the chain map (which drops the per-chain RPC
    // clients), then the Clarity RPC.
    closeKeystore(*this);

    chains.clear();
    current_chain.clear();

    clarity_rpc.reset();
    clarity_endpoint = Wallet::RpcEndpoint{};
    clarity_connected = false;

    running = true;
  }

  // ===========================================================================
  // Keystore open / close
  // ===========================================================================

  bool openKeystore(WatcherSession &session,
                    const std::string &path,
                    const std::string &password_file)
  {
    if (session.hasKeystore())
    {
      std::cerr << "error: a keystore is already open ("
                << session.keystore_path << "). Use 'close' first.\n";
      return false;
    }

    Wallet::WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::open(path, &st);
    if (!ks.has_value())
    {
      reportWalletError("cannot open keystore", st);
      return false;
    }

    // ---- Read the password ----
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
    const Wallet::WalletError err = (*ks)->unlock(password);
    if (!password.empty())
    {
      for (auto &c : password)
        c = '\0';
    }

    if (err != Wallet::WalletError::Ok)
    {
      Wallet::WalletStatus unlock_err =
          Wallet::WalletStatus::fail(err, "");
      reportWalletError("cannot unlock keystore", unlock_err);
      return false;
    }

    // ---- Decode the address ----
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
    session.signer =
        std::make_unique<Wallet::LocalSigner>(*session.keystore);
    session.address = *from_addr;
    session.address_bech32m = session.keystore->address();
    session.network = session.keystore->network();

    std::cout << "Unlocked " << path
              << " (" << session.address_bech32m
              << ") — " << Wallet::networkName(session.currentNetwork())
              << "\n";

    // ---- Resolve watcher id, if possible ----
    //
    // The Clarity RPC may or may not expose getBridgeWatcherIdByAddress
    // yet (see the Wallet::RpcClient header — it doesn't, as of
    // this writing). resolveWatcherId probes for it and returns 0
    // if it's absent. A zero result here is not an error: the
    // operator may have supplied --watcher-id, or may be about to
    // register the watcher, in which case the id is assigned at
    // RegisterBridgeWatcher time and needs to be re-read from
    // the node after that transaction is confirmed.
    if (session.watcher_id == 0 && session.clarity_rpc)
    {
      const uint64_t resolved =
          resolveWatcherId(*session.clarity_rpc, *session.address);
      if (resolved != 0)
      {
        session.watcher_id = resolved;
        std::cout << "Watcher id: " << resolved << "\n";
      }
    }

    return true;
  }

  void closeKeystore(WatcherSession &session)
  {
    if (!session.hasKeystore())
      return;

    // Lock explicitly before releasing.
    session.keystore->lock();

    session.signer.reset();
    session.keystore.reset();
    session.keystore_path.clear();
    session.address.reset();
    session.address_bech32m.clear();
    session.network.reset();
    session.watcher_id = 0;

    std::cout << "Keystore closed.\n";
  }

  // ===========================================================================
  // Watcher-id resolution
  //
  // The Clarity RPC method we want is getBridgeWatcherIdByAddress:
  //
  // send: { "address": <bech32m> }
  // expect: { "watcher_id": "0x..." } on success
  // error code 1055-ish (NotFound) on "not a watcher"
  //
  // Neither the method nor its error code exists in the current
  // RpcClient surface. Rather than adding a call site against a
  // method that would fail on every node, this function returns 0
  // unconditionally and lets the caller fall back to --watcher-id
  // or to the "operator runs RegisterBridgeWatcher and records
  // the assigned id" flow.
  //
  // When the RPC method is added, this is a one-function change:
  // add the method name, the parameter, the response parsing, and
  // drop the stub.
  // ===========================================================================
  uint64_t resolveWatcherId(Wallet::RpcClient &clarity_rpc,
                            const Crypto::Address &address) noexcept
  {
    (void)clarity_rpc;
    (void)address;

    // TODO: when getBridgeWatcherIdByAddress is exposed by the
    // Clarity node, replace this body with the RPC call.
    //
    // try {
    // Common::Json params = Common::Json::object();
    // params["address"] = address_bech32m;
    // auto res = clarity_rpc.call("getBridgeWatcherIdByAddress", params);
    // if (!res.ok()) return 0;
    // if (!res.result.is_object()) return 0;
    // if (!res.result.contains("watcher_id")) return 0;
    // // ... parse hex -> uint64
    // } catch (...) {
    // return 0;
    // }

    return 0;
  }

  // ===========================================================================
  // Chain runtime helpers
  // ===========================================================================

  bool probeChain(ChainRuntime &runtime)
  {
    if (!runtime.adapter || !runtime.rpc)
    {
      runtime.connected = false;
      return false;
    }

    std::string error;
    const bool ok = runtime.adapter->probe_rpc(*runtime.rpc, &error);
    runtime.connected = ok;
    if (!ok && !error.empty())
    {
      std::cerr << " probe failed: " << error << "\n";
    }
    return ok;
  }

  void applyAdapterDefaults(ChainAdapter &adapter,
                            ChainWatcherConfig &config)
  {
    // RPC host/port: parse the adapter's default endpoint.
    if (config.rpc_host.empty() || config.rpc_port == 0)
    {
      std::string host;
      uint16_t port = 0;
      if (parseEndpointSpec(adapter.default_rpc_endpoint(), host, port))
      {
        if (config.rpc_host.empty())
          config.rpc_host = host;
        if (config.rpc_port == 0)
          config.rpc_port = port;
      }
    }

    // Confirmation depth: use the adapter's default if zero.
    if (config.confirmation_depth == 0)
      config.confirmation_depth = adapter.default_confirmation_depth();

    // State subdir: <state_dir>/<chain_short_name>/. The caller is
    // responsible for creating it on disk (not here — this is a
    // pure config function, no filesystem side effects).
    if (config.state_subdir.empty())
      config.state_subdir = "state/" + adapter.short_name();
  }

} // namespace Bridge