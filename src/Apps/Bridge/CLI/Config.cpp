// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Config.h"
#include "Args.h"
#include "Adapters/ChainAdapter.h"

#include "Common/Json.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace Bridge
{
  namespace
  {
    std::string getString(const Common::Json &j,
                          const std::string &key,
                          const std::string &def = {})
    {
      if (!j.is_object() || !j.contains(key) || !j[key].is_string())
        return def;
      return j[key].get<std::string>();
    }

    uint64_t getUInt(const Common::Json &j,
                     const std::string &key,
                     uint64_t def = 0)
    {
      if (!j.is_object() || !j.contains(key))
        return def;
      const auto &v = j[key];
      if (v.is_number_unsigned())
        return v.get<uint64_t>();
      if (v.is_number_integer())
      {
        const auto i = v.get<int64_t>();
        return i < 0 ? def : static_cast<uint64_t>(i);
      }
      if (v.is_string())
      {
        try
        {
          return std::stoull(v.get<std::string>(), nullptr, 0);
        }
        catch (...)
        {
          return def;
        }
      }
      return def;
    }

    std::vector<uint8_t> getHexBytes(const Common::Json &j,
                                     const std::string &key)
    {
      if (!j.is_object() || !j.contains(key) || !j[key].is_string())
        return {};
      const std::string s = j[key].get<std::string>();
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if ((s.size() - i) % 2 != 0)
        return {};
      std::vector<uint8_t> out;
      out.reserve((s.size() - i) / 2);
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
      for (; i < s.size(); i += 2)
      {
        const int hi = nib(s[i]);
        const int lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0)
          return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
      }
      return out;
    }

    std::pair<std::string, uint16_t> parseHostPort(const std::string &spec)
    {
      const size_t colon = spec.find(':');
      if (colon == std::string::npos)
        return {spec, 0};
      const std::string host = spec.substr(0, colon);
      const std::string port_str = spec.substr(colon + 1);
      char *end = nullptr;
      const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
      if (end == port_str.c_str() || *end != '\0' ||
          port == 0 || port > 65535)
        return {host, 0};
      return {host, static_cast<uint16_t>(port)};
    }

    std::string readPasswordFile(const std::string &path, const char *flag)
    {
      std::FILE *f = std::fopen(path.c_str(), "rb");
      if (!f)
        throw std::runtime_error(std::string(flag) +
                                 ": cannot open '" + path + "'");
      std::string contents;
      char buf[256];
      size_t n;
      while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        contents.append(buf, n);
      std::fclose(f);
      while (!contents.empty() &&
             (contents.back() == '\n' || contents.back() == '\r'))
        contents.pop_back();
      return contents;
    }
  } // anonymous namespace

  namespace BridgeConfig
  {
    void load(const std::string &path, Args &args)
    {
      std::ifstream f(path);
      if (!f.good())
        throw std::runtime_error("cannot open config file: " + path);

      std::stringstream buffer;
      buffer << f.rdbuf();

      Common::Json j;
      try
      {
        j = Common::Json::parse(buffer.str());
      }
      catch (const std::exception &e)
      {
        throw std::runtime_error(
            std::string("config file is not valid JSON (") + path +
            "): " + e.what());
      }

      if (!j.is_object())
        throw std::runtime_error(
            "config file is not a JSON object: " + path);

      //  ---- Reject the legacy `mint_destination` field ----
      //
      //  A config that still carries `mint_destination` was written
      //  against the old model where every deposit minted to one
      //  operator-chosen address. That model cannot coexist with the
      //  per-deposit binding the bridge now requires: if we silently
      //  ignored the field, an operator who upgraded without reading
      //  the migration notes would see their deposits mint to their
      //  keystore address (the old fallback path), which is exactly
      //  the silent-wrong-mint failure the per-deposit binding is
      //  designed to eliminate. Fail loudly instead.
      if (j.contains("mint_destination") && !j["mint_destination"].is_null())
      {
        throw std::runtime_error(
            "config file contains the removed field 'mint_destination' "
            "(path: " +
            path + ").\n"
                   "  A single global mint destination is no longer supported.\n"
                   "  Deposits now mint to the destination carried by the deposit\n"
                   "  itself: on Bitcoin, a 32-byte OP_RETURN output; on CCX, the\n"
                   "  subaddress the user registered. Delete the field from the\n"
                   "  config file to continue.");
      }

      WatcherConfig &cfg = args.config;

      cfg.app_name = getString(j, "app_name", "clarity-bridge");

      const std::string clarity_rpc =
          getString(j, "clarity_rpc", "127.0.0.1:9633");
      auto [host, port] = parseHostPort(clarity_rpc);
      cfg.clarity_rpc_host = host;
      cfg.clarity_rpc_port = port;
      cfg.clarity_rpc_user = getString(j, "clarity_rpc_user");
      if (j.contains("clarity_rpc_password_file") &&
          j["clarity_rpc_password_file"].is_string())
      {
        cfg.clarity_rpc_password = readPasswordFile(
            j["clarity_rpc_password_file"].get<std::string>(),
            "clarity_rpc_password_file");
      }
      else
      {
        cfg.clarity_rpc_password = getString(j, "clarity_rpc_password");
      }

      cfg.keystore_path = getString(j, "keystore");
      cfg.password_file = getString(j, "password_file");
      cfg.consensus_key_file = getString(j, "consensus_key_file");
      cfg.view_key_file = getString(j, "view_key_file");
      cfg.state_dir = getString(j, "state_dir", "./bridge-state");
      cfg.log_level = getString(j, "log_level", "info");

      //  A previous version of the config file could carry a
      //  "watcher_id" key. Under the validator-is-watcher model
      //  there is no per-chain watcher id; the daemon's validator
      //  id is resolved from the keystore address at runtime. The
      //  key is silently ignored if present, so an old config file
      //  does not fail to load.

      if (j.contains("no_wizard") && j["no_wizard"].is_boolean())
        cfg.no_wizard = j["no_wizard"].get<bool>();

      cfg.chains.clear();
      if (j.contains("chains") && j["chains"].is_array())
      {
        for (const auto &entry : j["chains"])
        {
          if (!entry.is_object())
            continue;

          ChainWatcherConfig chain;
          chain.chain_short_name = getString(entry, "name");
          chain.enabled = true;
          chain.raw_json = entry;

          const std::string rpc = getString(entry, "rpc");
          if (!rpc.empty())
          {
            auto [rh, rp] = parseHostPort(rpc);
            chain.rpc_host = rh;
            chain.rpc_port = rp;
          }
          chain.rpc_user = getString(entry, "rpc_user");
          if (entry.contains("rpc_password_file") &&
              entry["rpc_password_file"].is_string())
          {
            chain.rpc_password = readPasswordFile(
                entry["rpc_password_file"].get<std::string>(),
                "rpc_password_file");
          }
          else
          {
            chain.rpc_password = getString(entry, "rpc_password");
          }

          chain.confirmation_depth = static_cast<uint16_t>(
              getUInt(entry, "confirmation_depth", 0));
          chain.burn_finality_depth = static_cast<uint16_t>(
              getUInt(entry, "burn_finality_depth", 3));

          chain.start_height = getUInt(entry, "start_height", 0);

          chain.bridge_address = getString(entry, "bridge_address");
          if (entry.contains("destination_blob") &&
              entry["destination_blob"].is_string())
          {
            chain.bridge_deposit_address =
                getHexBytes(entry, "destination_blob");
          }

          const std::string wallet_rpc = getString(entry, "wallet_rpc");
          if (!wallet_rpc.empty())
          {
            auto [wh, wp] = parseHostPort(wallet_rpc);
            chain.wallet_rpc_host = wh;
            chain.wallet_rpc_port = wp;
          }
          chain.wallet_rpc_user = getString(entry, "wallet_rpc_user");
          if (entry.contains("wallet_rpc_password_file") &&
              entry["wallet_rpc_password_file"].is_string())
          {
            chain.wallet_rpc_password = readPasswordFile(
                entry["wallet_rpc_password_file"].get<std::string>(),
                "wallet_rpc_password_file");
          }
          else
          {
            chain.wallet_rpc_password =
                getString(entry, "wallet_rpc_password");
          }

          if (entry.contains("ccx_network_prefix"))
          {
            chain.ccx_network_prefix =
                getUInt(entry, "ccx_network_prefix", 0x13);
          }

          cfg.chains.push_back(std::move(chain));

          //  Fill any unset fields from the adapter's defaults. Called here
          //  rather than later so --print-config and the runtime see the
          //  same values; the wizard path calls applyAdapterDefaults again,
          //  which is idempotent.
          if (auto adapter = ChainAdapterRegistry::find(
                  cfg.chains.back().chain_short_name))
          {
            applyAdapterDefaults(*adapter, cfg.chains.back());
          }
        }
      }
    }
  } // namespace BridgeConfig

  bool ensureStateRoot(const std::string &path)
  {
    std::error_code ec;
    if (std::filesystem::exists(path, ec))
    {
      if (!std::filesystem::is_directory(path, ec) || ec)
      {
        std::cerr << "error: state path exists but is not a directory: "
                  << path << "\n";
        return false;
      }
      return true;
    }
    std::filesystem::create_directories(path, ec);
    if (ec)
    {
      std::cerr << "error: cannot create state dir " << path
                << ": " << ec.message() << "\n";
      return false;
    }
    return true;
  }

  bool ensureChainStateDirs(const WatcherConfig &cfg)
  {
    for (const auto &c : cfg.chains)
    {
      const std::filesystem::path full =
          std::filesystem::path(cfg.state_dir) / c.state_subdir;
      std::error_code ec;
      std::filesystem::create_directories(full, ec);
      if (ec)
      {
        std::cerr << "error: cannot create chain state dir "
                  << full.string() << ": " << ec.message() << "\n";
        return false;
      }
    }
    return true;
  }

  std::string expandHome(const std::string &path)
  {
    if (path.empty() || path[0] != '~')
      return path;
    const char *home = std::getenv("HOME");
    if (!home)
      return path;
    return std::string(home) + path.substr(1);
  }

  void applyAdapterDefaults(const ChainAdapter &adapter,
                            ChainWatcherConfig &cfg)
  {
    if (cfg.rpc_host.empty() || cfg.rpc_port == 0)
    {
      auto [h, p] = parseHostPort(adapter.default_rpc_endpoint());
      cfg.rpc_host = h;
      cfg.rpc_port = p;
    }
    if (cfg.confirmation_depth == 0)
      cfg.confirmation_depth = adapter.default_confirmation_depth();
  }

} // namespace Bridge