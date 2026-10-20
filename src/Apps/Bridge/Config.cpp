// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Config.h"
#include "ChainAdapter.h"
#include "Commands.h"

#include "Common/Json.h"

#include "Core/Bridge/ConcealCCX.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace Bridge
{
  namespace BridgeConfig
  {
    namespace
    {
      //  The config file is JSON. These helpers all throw with a
      //  message that names the file and the field, so an operator
      //  can find the error without bisecting the file.

      [[noreturn]] void fail(const std::string &path,
                             const std::string &msg)
      {
        throw std::runtime_error(path + ": " + msg);
      }

      void parseEndpoint(const std::string &path,
                         const std::string &field,
                         const std::string &spec,
                         std::string &host_out,
                         uint16_t &port_out)
      {
        const size_t colon = spec.find(':');
        if (colon == std::string::npos || colon == 0 ||
            colon + 1 >= spec.size())
        {
          fail(path, "field '" + field +
                         "': expected 'host:port', got '" + spec + "'");
        }

        const std::string host = spec.substr(0, colon);
        const std::string port_str = spec.substr(colon + 1);

        char *end = nullptr;
        const unsigned long port =
            std::strtoul(port_str.c_str(), &end, 10);
        if (end == port_str.c_str() || *end != '\0' ||
            port == 0 || port > 65535)
        {
          fail(path, "field '" + field +
                         "': invalid port '" + port_str + "'");
        }

        host_out = host;
        port_out = static_cast<uint16_t>(port);
      }

      std::string requireString(const std::string &path,
                                const Common::Json &j,
                                const char *field)
      {
        if (!j.contains(field) || !j[field].is_string())
          fail(path, std::string("field '") + field +
                         "': expected a string");
        return j[field].get<std::string>();
      }

      std::string optionalString(const Common::Json &j,
                                 const char *field,
                                 const std::string &default_value)
      {
        if (!j.contains(field) || !j[field].is_string())
          return default_value;
        return j[field].get<std::string>();
      }

      uint64_t optionalU64(const std::string &path,
                           const Common::Json &j,
                           const char *field,
                           uint64_t default_value)
      {
        if (!j.contains(field))
          return default_value;
        if (j[field].is_number_unsigned())
          return j[field].get<uint64_t>();
        if (j[field].is_number_integer())
        {
          const auto v = j[field].get<int64_t>();
          if (v < 0)
            fail(path, std::string("field '") + field +
                           "': must be non-negative");
          return static_cast<uint64_t>(v);
        }
        if (j[field].is_string())
        {
          const std::string s = j[field].get<std::string>();
          if (s.empty())
            fail(path, std::string("field '") + field +
                           "': empty string");
          try
          {
            size_t idx = 0;
            const uint64_t v = std::stoull(s, &idx, 0);
            if (idx != s.size())
              fail(path, std::string("field '") + field +
                             "': invalid integer '" + s + "'");
            return v;
          }
          catch (const std::exception &)
          {
            fail(path, std::string("field '") + field +
                           "': invalid integer '" + s + "'");
          }
        }
        fail(path, std::string("field '") + field +
                       "': expected a number or hex string");
        return default_value;
      }

      uint16_t optionalU16(const std::string &path,
                           const Common::Json &j,
                           const char *field,
                           uint16_t default_value)
      {
        if (!j.contains(field))
          return default_value;
        if (j[field].is_number_unsigned())
        {
          const auto v = j[field].get<uint64_t>();
          if (v > 0xFFFF)
            fail(path, std::string("field '") + field +
                           "': value exceeds uint16");
          return static_cast<uint16_t>(v);
        }
        if (j[field].is_number_integer())
        {
          const auto v = j[field].get<int64_t>();
          if (v < 0 || v > 0xFFFF)
            fail(path, std::string("field '") + field +
                           "': value out of range");
          return static_cast<uint16_t>(v);
        }
        fail(path, std::string("field '") + field +
                       "': expected a number");
      }

      bool optionalBool(const std::string &path,
                        const Common::Json &j,
                        const char *field,
                        bool default_value)
      {
        if (!j.contains(field))
          return default_value;
        if (!j[field].is_boolean())
          fail(path, std::string("field '") + field +
                         "': expected a boolean");
        return j[field].get<bool>();
      }

      //  Parse one entry in the "chains" array into a
      //  ChainWatcherConfig. Missing fields fall back to
      //  defaults, then to the adapter's defaults (for
      //  confirmation_depth specifically, since that's
      //  per-adapter). The chain_short_name is required.
      ChainWatcherConfig parseChain(const std::string &path,
                                    const Common::Json &j)
      {
        if (!j.is_object())
          fail(path, "'chains' entries must be objects");

        ChainWatcherConfig cc;

        cc.chain_short_name = requireString(path, j, "name");

        //  Look up the adapter to seed defaults. If the chain
        //  name isn't a known adapter, that's an error — the
        //  config file must not enable chains that don't exist
        //  in this build.
        auto adapter = ChainAdapterRegistry::find(cc.chain_short_name);
        if (!adapter)
        {
          fail(path, "unknown chain '" + cc.chain_short_name +
                         "' in 'chains' array (not compiled into this "
                         "binary)");
        }

        cc.enabled = true;
        cc.confirmation_depth =
            adapter->default_confirmation_depth();

        //  Apply the adapter's default RPC endpoint, then let
        //  the config override it.
        {
          std::string host;
          uint16_t port = 0;
          parseEndpoint(path, "chains[].rpc",
                        adapter->default_rpc_endpoint(),
                        host, port);
          cc.rpc_host = host;
          cc.rpc_port = port;
        }

        if (j.contains("rpc") && j["rpc"].is_string())
        {
          parseEndpoint(path, "chains[].rpc",
                        j["rpc"].get<std::string>(),
                        cc.rpc_host, cc.rpc_port);
        }

        cc.rpc_user = optionalString(j, "rpc_user", cc.rpc_user);

        //  Password is loaded from a file, not a plain string,
        //  matching the CLI convention. The file is read here,
        //  at config load time, so the plaintext never enters
        //  the config file itself.
        if (j.contains("rpc_password_file") &&
            j["rpc_password_file"].is_string())
        {
          const std::string pw_path =
              j["rpc_password_file"].get<std::string>();
          std::FILE *f = std::fopen(pw_path.c_str(), "rb");
          if (!f)
            fail(path, "chains[].rpc_password_file: cannot open '" +
                           pw_path + "'");
          std::string pw;
          char buf[256];
          size_t n;
          while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
            pw.append(buf, n);
          std::fclose(f);
          while (!pw.empty() &&
                 (pw.back() == '\n' || pw.back() == '\r'))
            pw.pop_back();
          cc.rpc_password = std::move(pw);
        }

        cc.confirmation_depth = optionalU16(
            path, j, "confirmation_depth", cc.confirmation_depth);

        cc.state_subdir = optionalString(j, "state_subdir", cc.state_subdir);

        //  ---- Deposit address ----
        //
        //  Two forms are accepted, in order of preference:
        //    - "bridge_address": base58 CCX address string.
        //      Authoritative when present; the adapter's
        //      parse_deposit_address turns it into the 64-byte
        //      blob at start time.
        //    - "destination_blob": 128-char hex string
        //      (spend ‖ view). Used only when bridge_address is
        //      absent. Parsed here so a typo fails at config-load
        //      time rather than at start time.
        cc.bridge_address =
            optionalString(j, "bridge_address", cc.bridge_address);

        if (j.contains("destination_blob") &&
            j["destination_blob"].is_string())
        {
          const std::string blob_hex =
              j["destination_blob"].get<std::string>();
          std::string clean = blob_hex;
          if (clean.size() >= 2 && clean[0] == '0' &&
              (clean[1] == 'x' || clean[1] == 'X'))
            clean = clean.substr(2);

          if ((clean.size() & 1) != 0 ||
              clean.size() != Core::CcxBridge::CCX_DESTINATION_BYTES * 2)
          {
            fail(path, "chains[].destination_blob: expected 128 "
                       "hex chars (64-byte spend‖view pair)");
          }

          std::vector<uint8_t> blob;
          blob.reserve(clean.size() / 2);
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
          for (size_t i = 0; i < clean.size(); i += 2)
          {
            const int hi = nib(clean[i]);
            const int lo = nib(clean[i + 1]);
            if (hi < 0 || lo < 0)
              fail(path, "chains[].destination_blob: non-hex "
                         "character");
            blob.push_back(static_cast<uint8_t>((hi << 4) | lo));
          }

          cc.bridge_deposit_address = std::move(blob);
        }

        //  ---- Withdrawal release config ----

        if (j.contains("wallet_rpc") && j["wallet_rpc"].is_string())
        {
          parseEndpoint(path, "chains[].wallet_rpc",
                        j["wallet_rpc"].get<std::string>(),
                        cc.wallet_rpc_host, cc.wallet_rpc_port);
        }
        cc.wallet_rpc_user =
            optionalString(j, "wallet_rpc_user", cc.wallet_rpc_user);
        if (j.contains("wallet_rpc_password_file") &&
            j["wallet_rpc_password_file"].is_string())
        {
          const std::string pw_path =
              j["wallet_rpc_password_file"].get<std::string>();
          std::FILE *f = std::fopen(pw_path.c_str(), "rb");
          if (!f)
            fail(path, "chains[].wallet_rpc_password_file: cannot open '" +
                           pw_path + "'");
          std::string pw;
          char buf[256];
          size_t n;
          while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
            pw.append(buf, n);
          std::fclose(f);
          while (!pw.empty() &&
                 (pw.back() == '\n' || pw.back() == '\r'))
            pw.pop_back();
          cc.wallet_rpc_password = std::move(pw);
        }

        cc.ccx_network_prefix = optionalU64(
            path, j, "ccx_network_prefix", cc.ccx_network_prefix);

        cc.burn_finality_depth = optionalU16(
            path, j, "burn_finality_depth", cc.burn_finality_depth);

        //  ---- Config validation: don't accept a half-configured
        //  release path ----
        //
        //  wallet_rpc_* being set means the operator wants this
        //  watcher to release withdrawals. Without a deposit
        //  address (string or blob), the watcher cannot build a
        //  walletd sendTransaction (no sourceAddresses /
        //  changeAddress), so it would sit in the scan loop
        //  failing submit_release every poll with "no custody
        //  address string configured." Refuse to start instead.
        if (!cc.wallet_rpc_host.empty() && cc.wallet_rpc_port != 0)
        {
          if (cc.bridge_address.empty() &&
              cc.bridge_deposit_address.empty())
          {
            fail(path,
                 "chains[]: wallet_rpc is set but neither "
                 "'bridge_address' nor 'destination_blob' is "
                 "configured; the custody address is required to "
                 "release withdrawals");
          }
        }

        return cc;
      }

      //  The set of top-level keys we accept. Anything else is
      //  warned about but ignored, so an operator editing an old
      //  config sees a clear message if they typo a field name.
      bool isKnownTopLevelKey(const std::string &k)
      {
        static const char *known[] = {
            "app_name",
            "clarity_rpc",
            "clarity_rpc_user",
            "clarity_rpc_password_file",
            "keystore",
            "password_file",
            "consensus_key_file",
            "view_key_file",
            "state_dir",
            "watcher_id",
            "mint_destination",
            "chains",
            "log_level",
            "log_file",
            "no_wizard",
            "command",
            "command_args",
            nullptr,
        };
        for (const char **p = known; *p != nullptr; ++p)
        {
          if (k == *p)
            return true;
        }
        return false;
      }
    } // anonymous namespace

    bool load(const std::string &path, Args &args)
    {
      std::ifstream in(path);
      if (!in)
        fail(path, "cannot open file");

      Common::Json j;
      try
      {
        in >> j;
      }
      catch (const std::exception &e)
      {
        fail(path, std::string("malformed JSON: ") + e.what());
      }
      in.close();

      if (!j.is_object())
        fail(path, "top-level value must be a JSON object");

      for (auto it = j.begin(); it != j.end(); ++it)
      {
        if (!isKnownTopLevelKey(it.key()))
        {
          std::cerr << "warning: " << path
                    << ": unknown field '" << it.key()
                    << "' (ignored)\n";
        }
      }

      //  ---- Top-level scalars ----

      args.config.app_name =
          optionalString(j, "app_name", args.config.app_name);

      if (j.contains("clarity_rpc") && j["clarity_rpc"].is_string())
      {
        parseEndpoint(path, "clarity_rpc",
                      j["clarity_rpc"].get<std::string>(),
                      args.config.clarity_rpc_host,
                      args.config.clarity_rpc_port);
      }
      args.config.clarity_rpc_user =
          optionalString(j, "clarity_rpc_user",
                         args.config.clarity_rpc_user);

      if (j.contains("clarity_rpc_password_file") &&
          j["clarity_rpc_password_file"].is_string())
      {
        const std::string pw_path =
            j["clarity_rpc_password_file"].get<std::string>();
        std::FILE *f = std::fopen(pw_path.c_str(), "rb");
        if (!f)
          fail(path, "clarity_rpc_password_file: cannot open '" +
                         pw_path + "'");
        std::string pw;
        char buf[256];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
          pw.append(buf, n);
        std::fclose(f);
        while (!pw.empty() &&
               (pw.back() == '\n' || pw.back() == '\r'))
          pw.pop_back();
        args.config.clarity_rpc_password = std::move(pw);
      }

      args.config.keystore_path =
          optionalString(j, "keystore",
                         args.config.keystore_path);
      args.config.password_file =
          optionalString(j, "password_file",
                         args.config.password_file);

      args.config.consensus_key_file =
          optionalString(j, "consensus_key_file",
                         args.config.consensus_key_file);
      args.config.view_key_file =
          optionalString(j, "view_key_file",
                         args.config.view_key_file);

      args.config.state_dir =
          optionalString(j, "state_dir",
                         args.config.state_dir);

      args.config.watcher_id =
          optionalU64(path, j, "watcher_id", args.config.watcher_id);

      args.config.mint_destination =
          optionalString(j, "mint_destination",
                         args.config.mint_destination);

      args.log_level =
          optionalString(j, "log_level", args.log_level);
      args.log_file =
          optionalString(j, "log_file", args.log_file);

      args.no_wizard =
          optionalBool(path, j, "no_wizard", args.no_wizard);

      if (j.contains("command") && j["command"].is_string())
      {
        args.command = j["command"].get<std::string>();
        if (!findCommand(args.command))
          fail(path, "field 'command': unknown command '" +
                         args.command + "'");
      }

      if (j.contains("command_args") &&
          j["command_args"].is_array())
      {
        for (const auto &a : j["command_args"])
        {
          if (!a.is_string())
            fail(path, "field 'command_args': entries must be strings");
          args.command_args.push_back(a.get<std::string>());
        }
      }

      //  ---- Chains array ----

      if (j.contains("chains"))
      {
        if (!j["chains"].is_array())
          fail(path, "field 'chains': expected an array");

        for (const auto &entry : j["chains"])
          args.cli_chain_configs.push_back(parseChain(path, entry));
      }

      return true;
    }

  } // namespace BridgeConfig

} // namespace Bridge