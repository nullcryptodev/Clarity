// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
//  token
//
//  Guided, interactive tool for creating, minting, burning, and
//  updating fungible tokens, and for querying token / chain state.
//
//  Two modes:
//     token                          guided walkthrough (default)
//     token <command> [options]      one-shot, scriptable
//
//  The walkthrough opens with "unlock or create a keystore", then
//  presents a menu of operations. Each wizard explains every field
//  before asking for it, shows a review block before signing, and
//  explains any error in plain language.
//
//  Output discipline:
//     stdout  — results, hex, JSON-ish summaries.
//     stderr  — prompts, warnings, errors, password input.

#include "Common/PasswordPrompt.h"
#include "Common/Repl.h"

#include "Core/TokenTypes.h"
#include "Core/TransactionTypes.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/HdPath.h"
#include "Wallet/LocalSigner.h"
#include "Wallet/TransactionBuilder.h"
#include "Wallet/WalletError.h"
#include "Wallet/WalletTypes.h"

#include "Crypto/Types.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
  // ===========================================================================
  //  JSON helpers (subset sufficient for JSON-RPC)
  // ===========================================================================

  std::string jsonEscape(const std::string &s)
  {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s)
    {
      switch (c)
      {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20)
        {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x",
                        static_cast<unsigned>(c));
          out += buf;
        }
        else
        {
          out.push_back(c);
        }
      }
    }
    out.push_back('"');
    return out;
  }

  std::optional<std::string> jsonFindString(const std::string &body,
                                            const std::string &key)
  {
    const std::string needle = "\"" + key + "\"";
    size_t pos = 0;
    while ((pos = body.find(needle, pos)) != std::string::npos)
    {
      size_t i = pos + needle.size();
      while (i < body.size() && std::isspace((unsigned char)body[i]))
        ++i;
      if (i >= body.size() || body[i] != ':')
      {
        pos = i;
        continue;
      }
      ++i;
      while (i < body.size() && std::isspace((unsigned char)body[i]))
        ++i;
      if (i >= body.size() || body[i] != '"')
      {
        pos = i;
        continue;
      }
      ++i;
      std::string out;
      while (i < body.size() && body[i] != '"')
      {
        if (body[i] == '\\' && i + 1 < body.size())
        {
          const char e = body[i + 1];
          switch (e)
          {
          case 'n':
            out.push_back('\n');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case '"':
            out.push_back('"');
            break;
          case '\\':
            out.push_back('\\');
            break;
          case '/':
            out.push_back('/');
            break;
          default:
            out.push_back(e);
            break;
          }
          i += 2;
          continue;
        }
        out.push_back(body[i++]);
      }
      return out;
    }
    return std::nullopt;
  }

  std::optional<std::string> jsonFindNumber(const std::string &body,
                                            const std::string &key)
  {
    const std::string needle = "\"" + key + "\"";
    size_t pos = 0;
    while ((pos = body.find(needle, pos)) != std::string::npos)
    {
      size_t i = pos + needle.size();
      while (i < body.size() && std::isspace((unsigned char)body[i]))
        ++i;
      if (i >= body.size() || body[i] != ':')
      {
        pos = i;
        continue;
      }
      ++i;
      while (i < body.size() && std::isspace((unsigned char)body[i]))
        ++i;
      if (i >= body.size())
        return std::nullopt;
      if (body[i] == '"')
      {
        ++i;
        std::string out;
        while (i < body.size() && body[i] != '"')
          out.push_back(body[i++]);
        return out;
      }
      const size_t start = i;
      while (i < body.size() &&
             (std::isalnum((unsigned char)body[i]) || body[i] == '-'))
        ++i;
      if (i == start)
      {
        pos = i;
        continue;
      }
      return body.substr(start, i - start);
    }
    return std::nullopt;
  }

  std::optional<std::string> jsonRpcError(const std::string &body)
  {
    const auto err_pos = body.find("\"error\"");
    if (err_pos == std::string::npos)
      return std::nullopt;
    size_t i = err_pos + 7;
    while (i < body.size() && std::isspace((unsigned char)body[i]))
      ++i;
    if (i < body.size() && body[i] == ':')
    {
      ++i;
      while (i < body.size() && std::isspace((unsigned char)body[i]))
        ++i;
      if (i + 4 <= body.size() && body.compare(i, 4, "null") == 0)
        return std::nullopt;
    }
    if (auto code = jsonFindString(body, "code"); code.has_value())
      return code;
    auto msg = jsonFindString(body, "message");
    if (msg)
      return msg;
    return std::string("(unspecified RPC error)");
  }

  //  Map an RPC error code to a fuller English explanation. The code
  //  itself is always printed alongside; this is the "what does it
  //  mean for me" layer that the walkthrough shows to non-developers.
  std::string humanError(const std::string &code)
  {
    if (code == "TxPrecondition")
      return "the transaction can't apply at the current chain tip "
             "(the token may not exist, you may not be its creator, "
             "or a supply cap would be exceeded)";
    if (code == "TxNonceTooLow")
      return "the transaction's nonce is below the account's current "
             "nonce; a pending transaction for this address is likely "
             "blocking, wait for it to mine or override with 'nonce'";
    if (code == "TxNonceConflict")
      return "another transaction with this nonce is already in the "
             "mempool; wait for it to mine or replace it with a "
             "higher-fee transaction";
    if (code == "TxInsufficientFunds")
      return "the sender doesn't hold enough of the amount plus the fee";
    if (code == "TxBadSignature")
      return "the signature doesn't verify against the sender's key";
    if (code == "TxWrongChain")
      return "the transaction's chain_id doesn't match this node's";
    if (code == "TxExpired")
      return "the transaction's valid_until_height has already passed";
    if (code == "TxFeeTooLow")
      return "the fee rate is below the mempool's minimum";
    if (code == "TxFeeTooHigh")
      return "the fee rate is above the mempool's maximum";
    if (code == "TxMalformed")
      return "the transaction bytes could not be decoded or are "
             "structurally invalid";
    if (code == "TxTooLarge")
      return "the transaction exceeds the maximum serialized size";
    if (code == "TxPoolFull")
      return "the mempool is full and this transaction wasn't "
             "competitive enough to evict anything";
    return "";
  }

  // ===========================================================================
  //  POSIX-socket HTTP/1.1 JSON-RPC client
  // ===========================================================================

  struct RpcEndpoint
  {
    std::string host = "127.0.0.1";
    uint16_t port = 9633;
  };

  struct RpcResult
  {
    bool transport_ok{false};
    std::string body;
    std::string error;
  };

  bool parseEndpoint(const std::string &url, RpcEndpoint &out, std::string &err)
  {
    std::string s = url;
    const std::string http = "http://";
    if (s.rfind(http, 0) == 0)
      s = s.substr(http.size());
    if (auto slash = s.find('/'); slash != std::string::npos)
      s = s.substr(0, slash);
    auto colon = s.rfind(':');
    if (colon == std::string::npos)
    {
      out.host = s.empty() ? "127.0.0.1" : s;
      out.port = 9633;
      return true;
    }
    out.host = s.substr(0, colon);
    if (out.host.empty())
      out.host = "127.0.0.1";
    const std::string ps = s.substr(colon + 1);
    if (ps.empty())
    {
      err = "empty port in --rpc";
      return false;
    }
    errno = 0;
    char *end = nullptr;
    const unsigned long v = std::strtoul(ps.c_str(), &end, 10);
    if (errno != 0 || end == ps.c_str() || *end != '\0' ||
        v == 0 || v > 65535)
    {
      err = "invalid port in --rpc: " + ps;
      return false;
    }
    out.port = static_cast<uint16_t>(v);
    return true;
  }

  RpcResult rpcCall(const RpcEndpoint &ep,
                    const std::string &method,
                    const std::string &params_json,
                    int timeout_seconds = 30)
  {
    RpcResult r;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    const std::string port_str = std::to_string(ep.port);
    const int gai = ::getaddrinfo(ep.host.c_str(), port_str.c_str(),
                                  &hints, &res);
    if (gai != 0 || res == nullptr)
    {
      r.error = std::string("resolve failed: ") + gai_strerror(gai);
      return r;
    }

    int fd = -1;
    for (addrinfo *ai = res; ai != nullptr; ai = ai->ai_next)
    {
      fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (fd < 0)
        continue;
      timeval tv{};
      tv.tv_sec = timeout_seconds;
      ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
        break;
      ::close(fd);
      fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0)
    {
      r.error = std::string("connect failed: ") + std::strerror(errno);
      return r;
    }

    const std::string request_body =
        std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":") +
        jsonEscape(method) + ",\"params\":" + params_json + "}";

    std::ostringstream req;
    req << "POST / HTTP/1.1\r\n"
        << "Host: " << ep.host << ":" << ep.port << "\r\n"
        << "User-Agent: token-tool/1.0\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << request_body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << request_body;

    const std::string req_str = req.str();
    size_t sent = 0;
    while (sent < req_str.size())
    {
      const ssize_t n = ::send(fd, req_str.data() + sent,
                               req_str.size() - sent, 0);
      if (n <= 0)
      {
        r.error = std::string("send failed: ") + std::strerror(errno);
        ::close(fd);
        return r;
      }
      sent += static_cast<size_t>(n);
    }

    std::string raw;
    char buf[4096];
    for (;;)
    {
      const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
      if (n == 0)
        break;
      if (n < 0)
      {
        r.error = std::string("recv failed: ") + std::strerror(errno);
        ::close(fd);
        return r;
      }
      raw.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);

    const auto hdr_end = raw.find("\r\n\r\n");
    if (hdr_end == std::string::npos)
    {
      r.error = "malformed HTTP response";
      return r;
    }
    std::string headers = raw.substr(0, hdr_end);
    std::string body = raw.substr(hdr_end + 4);

    bool chunked = false;
    {
      for (auto &c : headers)
        c = (char)std::tolower((unsigned char)c);
      if (headers.find("transfer-encoding: chunked") != std::string::npos)
        chunked = true;
    }

    if (chunked)
    {
      std::string out;
      size_t i = 0;
      while (i < body.size())
      {
        const size_t line_end = body.find("\r\n", i);
        if (line_end == std::string::npos)
          break;
        std::string sz = body.substr(i, line_end - i);
        if (auto semi = sz.find(';'); semi != std::string::npos)
          sz = sz.substr(0, semi);
        errno = 0;
        char *end = nullptr;
        const unsigned long chunk = std::strtoul(sz.c_str(), &end, 16);
        if (errno != 0 || end == sz.c_str() || *end != '\0')
          break;
        i = line_end + 2;
        if (chunk == 0)
          break;
        if (i + chunk > body.size())
          break;
        out.append(body, i, chunk);
        i += chunk;
        if (i + 1 < body.size() && body[i] == '\r' && body[i + 1] == '\n')
          i += 2;
      }
      body = out;
    }

    r.transport_ok = true;
    r.body = body;
    return r;
  }

  bool rpcAndPrint(const RpcEndpoint &ep,
                   const std::string &method,
                   const std::string &params_json)
  {
    RpcResult r = rpcCall(ep, method, params_json);
    if (!r.transport_ok)
    {
      std::cerr << "  the node isn't responding: " << r.error << "\n";
      std::cerr << "  (is the node running at "
                << ep.host << ":" << ep.port << "?)\n";
      return false;
    }
    if (auto err = jsonRpcError(r.body))
    {
      std::cerr << "  the node refused: " << *err;
      const std::string human = humanError(*err);
      if (!human.empty())
        std::cerr << "  (" << human << ")";
      std::cerr << "\n";
      return false;
    }
    std::cout << r.body << "\n";
    return true;
  }

  // ===========================================================================
  //  Command type
  // ===========================================================================

  enum class Command
  {
    Create,
    Mint,
    Burn,
    UpdateMeta,
    Info,
    Supply,
    List,
    Send,
    Balance,
    Whoami,
    Mempool,
    Stats
  };

  struct Args
  {
    Command cmd{Command::Create};
    bool has_cmd{false};

    std::string keystore;
    std::string password_file;
    std::optional<uint64_t> nonce;
    uint64_t fee{0};
    bool raw{false};
    bool dry_run{false};
    bool send{false};
    bool yes{false};

    RpcEndpoint rpc;

    std::string name;
    std::string symbol;
    uint8_t decimals{8};
    uint8_t backing{0};
    uint64_t max_supply{0};
    uint16_t royalty_bps{0};
    std::string fingerprint_hex;

    uint32_t token_id{0};
    uint64_t amount{0};
    std::string to;

    std::string new_name;
    std::string new_symbol;
    uint16_t new_royalty_bps{0};

    std::string hex_to_send;
  };

  // ===========================================================================
  //  Parsing helpers
  // ===========================================================================

  uint64_t parseU64DecOrDie(const std::string &s, const char *flag)
  {
    if (s.empty())
      throw std::runtime_error(std::string(flag) + ": empty value");
    errno = 0;
    char *end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0')
      throw std::runtime_error(
          std::string(flag) + ": invalid integer '" + s + "'");
    return static_cast<uint64_t>(v);
  }

  uint64_t parseU64OrDie(const std::string &s, const char *flag)
  {
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
      errno = 0;
      char *end = nullptr;
      const unsigned long long v = std::strtoull(s.c_str() + 2, &end, 16);
      if (errno != 0 || end == s.c_str() + 2 || *end != '\0')
        throw std::runtime_error(
            std::string(flag) + ": invalid hex integer '" + s + "'");
      return static_cast<uint64_t>(v);
    }
    return parseU64DecOrDie(s, flag);
  }

  uint8_t parseU8OrDie(const std::string &s, const char *flag)
  {
    const uint64_t v = parseU64OrDie(s, flag);
    if (v > 255)
      throw std::runtime_error(std::string(flag) + ": out of range (0..255)");
    return static_cast<uint8_t>(v);
  }

  uint16_t parseU16OrDie(const std::string &s, const char *flag)
  {
    const uint64_t v = parseU64OrDie(s, flag);
    if (v > 65535)
      throw std::runtime_error(std::string(flag) + ": out of range (0..65535)");
    return static_cast<uint16_t>(v);
  }

  Crypto::Hash parseHashHexOrDie(const std::string &s, const char *flag)
  {
    if (s.size() != 64)
      throw std::runtime_error(
          std::string(flag) + ": must be 64 hex characters (32 bytes)");

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

    Crypto::Hash h;
    for (size_t i = 0; i < 32; ++i)
    {
      const int hi = nib(s[i * 2]);
      const int lo = nib(s[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        throw std::runtime_error(
            std::string(flag) + ": contains non-hex characters");
      h.data[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return h;
  }

  std::string expandTilde(const std::string &path)
  {
    if (path.empty() || path[0] != '~')
      return path;
    if (path.size() > 1 && path[1] != '/')
      return path;
    const char *home = std::getenv("HOME");
    if (!home || !*home)
    {
      if (const passwd *pw = ::getpwuid(::getuid()))
        home = pw->pw_dir;
    }
    if (!home || !*home)
      return path;
    return std::string(home) + path.substr(1);
  }

  // ===========================================================================
  //  One-shot argument parsing
  // ===========================================================================

  Command parseCommand(const std::string &s)
  {
    if (s == "create")
      return Command::Create;
    if (s == "mint")
      return Command::Mint;
    if (s == "burn")
      return Command::Burn;
    if (s == "update-meta")
      return Command::UpdateMeta;
    if (s == "info")
      return Command::Info;
    if (s == "supply")
      return Command::Supply;
    if (s == "list")
      return Command::List;
    if (s == "send")
      return Command::Send;
    if (s == "balance")
      return Command::Balance;
    if (s == "whoami")
      return Command::Whoami;
    if (s == "mempool")
      return Command::Mempool;
    if (s == "stats")
      return Command::Stats;
    throw std::runtime_error("unknown command: " + s);
  }

  Args parseArgs(int argc, char **argv)
  {
    Args args;
    if (argc < 1)
      throw std::runtime_error("missing command");

    args.cmd = parseCommand(argv[0]);
    args.has_cmd = true;

    for (int i = 1; i < argc; ++i)
    {
      const std::string arg = argv[i];
      auto next = [&]() -> std::string
      {
        if (i + 1 >= argc)
          throw std::runtime_error("missing value for " + arg);
        return argv[++i];
      };

      if (arg == "--keystore")
      {
        args.keystore = expandTilde(next());
        continue;
      }
      if (arg == "--password-file")
      {
        args.password_file = next();
        continue;
      }
      if (arg == "--password")
        throw std::runtime_error(
            "--password is not accepted; use --password-file or let "
            "the tool prompt");
      if (arg == "--nonce")
      {
        const std::string v = next();
        if (v == "auto")
          args.nonce = std::nullopt;
        else
          args.nonce = parseU64OrDie(v, "--nonce");
        continue;
      }
      if (arg == "--fee")
      {
        args.fee = parseU64OrDie(next(), "--fee");
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
      if (arg == "--send")
      {
        args.send = true;
        continue;
      }
      if (arg == "--yes")
      {
        args.yes = true;
        continue;
      }
      if (arg == "--rpc")
      {
        std::string err;
        if (!parseEndpoint(next(), args.rpc, err))
          throw std::runtime_error(err);
        continue;
      }

      if (arg == "--name")
      {
        args.name = next();
        continue;
      }
      if (arg == "--symbol")
      {
        args.symbol = next();
        continue;
      }
      if (arg == "--decimals")
      {
        args.decimals = parseU8OrDie(next(), "--decimals");
        continue;
      }
      if (arg == "--backing")
      {
        args.backing = parseU8OrDie(next(), "--backing");
        continue;
      }
      if (arg == "--max-supply")
      {
        args.max_supply = parseU64OrDie(next(), "--max-supply");
        continue;
      }
      if (arg == "--royalty")
      {
        args.royalty_bps = parseU16OrDie(next(), "--royalty");
        continue;
      }
      if (arg == "--fingerprint")
      {
        args.fingerprint_hex = next();
        continue;
      }

      if (arg == "--token")
      {
        args.token_id = static_cast<uint32_t>(parseU64OrDie(next(), "--token"));
        continue;
      }
      if (arg == "--amount")
      {
        args.amount = parseU64OrDie(next(), "--amount");
        continue;
      }
      if (arg == "--to")
      {
        args.to = next();
        continue;
      }

      if (arg == "--new-name")
      {
        args.new_name = next();
        continue;
      }
      if (arg == "--new-symbol")
      {
        args.new_symbol = next();
        continue;
      }
      if (arg == "--new-royalty")
      {
        args.new_royalty_bps = parseU16OrDie(next(), "--new-royalty");
        continue;
      }

      throw std::runtime_error("unknown argument: " + arg);
    }

    switch (args.cmd)
    {
    case Command::Create:
      if (args.name.empty())
        throw std::runtime_error("create requires --name");
      if (args.symbol.empty())
        throw std::runtime_error("create requires --symbol");
      break;
    case Command::Mint:
      if (args.token_id == 0)
        throw std::runtime_error("mint requires --token (non-zero)");
      if (args.amount == 0)
        throw std::runtime_error("mint requires --amount (non-zero)");
      if (args.to.empty())
        throw std::runtime_error("mint requires --to");
      break;
    case Command::Burn:
      if (args.token_id == 0)
        throw std::runtime_error("burn requires --token (non-zero)");
      if (args.amount == 0)
        throw std::runtime_error("burn requires --amount (non-zero)");
      break;
    case Command::UpdateMeta:
      if (args.token_id == 0)
        throw std::runtime_error("update-meta requires --token (non-zero)");
      if (args.new_name.empty() && args.new_symbol.empty() &&
          args.new_royalty_bps == 0)
        throw std::runtime_error(
            "update-meta requires at least one of --new-name, "
            "--new-symbol, --new-royalty");
      break;
    case Command::Info:
      if (args.token_id == 0)
        throw std::runtime_error("info requires --token (non-zero)");
      break;
    case Command::Supply:
      if (args.token_id == 0)
        throw std::runtime_error("supply requires --token (non-zero)");
      break;
    case Command::Send:
      if (args.hex_to_send.empty())
        throw std::runtime_error("send requires a hex string argument");
      break;
    default:
      break;
    }

    const bool signing =
        args.cmd == Command::Create || args.cmd == Command::Mint ||
        args.cmd == Command::Burn || args.cmd == Command::UpdateMeta;
    if (signing)
    {
      if (args.keystore.empty())
        throw std::runtime_error("--keystore is required for signing commands");
      if (args.fee == 0)
        throw std::runtime_error("--fee is required and must be non-zero");
    }

    return args;
  }

  // ===========================================================================
  //  Output helpers
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

  Crypto::Address parseAddressOrDie(const std::string &s,
                                    Wallet::Network network,
                                    const char *flag_name)
  {
    auto addr = Wallet::decodeAddress(s, network);
    if (!addr.has_value())
      throw std::runtime_error(
          std::string(flag_name) +
          ": not a valid address for this network: " + s);
    return *addr;
  }

  std::string resolvePassword(const Args &args)
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

  void reportWalletError(const char *prefix, const Wallet::WalletStatus &st)
  {
    std::cerr << "  " << prefix << ": ";
    if (!st.detail.empty())
      std::cerr << st.detail;
    else
      std::cerr << Wallet::walletErrorMessage(st.code);
    std::cerr << "\n";
  }

  void printTxSummary(const Core::Transaction &tx,
                      const Crypto::Hash *signing_hash,
                      Wallet::Network network,
                      const char *heading)
  {
    const std::string from = Wallet::encodeAddress(tx.from, network);
    const std::string to = tx.to.isNull()
                               ? std::string("(none)")
                               : Wallet::encodeAddress(tx.to, network);

    std::cout << heading << ":\n";
    std::cout << "  type:      " << Core::txTypeName(tx.tx_type) << "\n";
    std::cout << "  from:      " << from << "\n";
    std::cout << "  to:        " << to << "\n";
    if (tx.amount > 0)
      std::cout << "  amount:    " << tx.amount << " (atomic units)\n";
    if (tx.token_id != NATIVE_TOKEN_ID)
      std::cout << "  token_id:  " << tx.token_id << "\n";
    std::cout << "  fee:       " << tx.fee << " (atomic units)\n";
    std::cout << "  nonce:     " << tx.nonce << "\n";
    std::cout << "  chain_id:  0x" << std::hex << tx.chain_id << std::dec << "\n";
    std::cout << "  size:      " << tx.serializedSize() << " bytes\n";
    if (signing_hash)
      std::cout << "  txid:      0x" << signing_hash->toString() << "\n";
    else
      std::cout << "  signing hash: 0x" << tx.signingHash().toString() << "\n";
    std::cout << "\n";
  }

  void printRaw(const Core::Transaction &tx)
  {
    auto bytes = tx.serialize();
    std::cout << "0x" << bytesToHex(bytes.data(), bytes.size()) << "\n";
  }

  // ===========================================================================
  //  Session
  // ===========================================================================

  struct Session
  {
    Args args;
    Common::Repl repl;
    bool ks_loaded{false};
    std::unique_ptr<Wallet::EncryptedKeyStore> ks;
    std::optional<Crypto::Address> from_addr;
    uint64_t chain_id{0};
    Wallet::Network network{Wallet::Network::Mainnet};
    std::string address_str;
    std::string keystore_path;
  };

  // ===========================================================================
  //  Prompt helpers
  //
  //  All of these accept an optional validator. When the validator
  //  returns a non-empty string, that string is printed and the
  //  prompt re-asks. This is what turns "you typed 'ex', I'm sending
  //  you back to the menu" into "symbol must be 3..8 characters, try
  //  again".
  // ===========================================================================

  using Validator = std::function<std::string(const std::string &)>;

  void hr()
  {
    std::cout << "────────────────────────────────────────────────────────────\n";
  }

  void step(int n, int total, const std::string &title)
  {
    std::cout << "\nStep " << n << " of " << total << " — " << title << "\n";
  }

  void explain(const std::string &text)
  {
    std::istringstream in(text);
    std::string paragraph;
    while (std::getline(in, paragraph))
    {
      if (paragraph.empty())
      {
        std::cout << "\n";
        continue;
      }
      std::string line;
      std::istringstream words(paragraph);
      std::string word;
      while (words >> word)
      {
        if (!line.empty() && line.size() + 1 + word.size() > 72)
        {
          std::cout << line << "\n";
          line.clear();
        }
        if (!line.empty())
          line.push_back(' ');
        line += word;
      }
      if (!line.empty())
        std::cout << line << "\n";
    }
  }

  std::optional<std::string> askString(Session &s,
                                       const std::string &lead_in,
                                       const std::string &prompt,
                                       bool allow_empty = false,
                                       const Validator &validate = nullptr)
  {
    if (!lead_in.empty())
    {
      explain(lead_in);
      std::cout << "\n";
    }
    for (;;)
    {
      auto v = s.repl.readLine(prompt);
      if (!v)
        return std::nullopt;
      if (!allow_empty && v->empty())
      {
        std::cout << "  this field is required; try again\n";
        continue;
      }
      if (validate)
      {
        const std::string err = validate(*v);
        if (!err.empty())
        {
          std::cout << "  " << err << "\n";
          continue;
        }
      }
      return v;
    }
  }

  std::optional<uint64_t> askU64(Session &s,
                                 const std::string &lead_in,
                                 const std::string &prompt,
                                 bool allow_empty = false,
                                 uint64_t empty_default = 0,
                                 const Validator &validate = nullptr)
  {
    if (!lead_in.empty())
    {
      explain(lead_in);
      std::cout << "\n";
    }
    for (;;)
    {
      auto v = s.repl.readLine(prompt);
      if (!v)
        return std::nullopt;
      if (v->empty() && allow_empty)
      {
        if (validate)
        {
          // Validate the default value so a validator that rejects
          // the default gets a chance to say so.
          const std::string err = validate(std::to_string(empty_default));
          if (!err.empty())
          {
            std::cout << "  " << err << "\n";
            continue;
          }
        }
        return empty_default;
      }
      try
      {
        const uint64_t value = parseU64OrDie(*v, prompt.c_str());
        if (validate)
        {
          const std::string err = validate(std::to_string(value));
          if (!err.empty())
          {
            std::cout << "  " << err << "\n";
            continue;
          }
        }
        return value;
      }
      catch (const std::exception &e)
      {
        std::cout << "  " << e.what() << "\n";
      }
    }
  }

  std::optional<uint8_t> askU8(Session &s,
                               const std::string &lead_in,
                               const std::string &prompt,
                               bool allow_empty = false,
                               uint8_t empty_default = 0,
                               const Validator &validate = nullptr)
  {
    if (!lead_in.empty())
    {
      explain(lead_in);
      std::cout << "\n";
    }
    for (;;)
    {
      auto v = s.repl.readLine(prompt);
      if (!v)
        return std::nullopt;
      if (v->empty() && allow_empty)
      {
        if (validate)
        {
          const std::string err = validate(std::to_string(empty_default));
          if (!err.empty())
          {
            std::cout << "  " << err << "\n";
            continue;
          }
        }
        return empty_default;
      }
      try
      {
        const uint8_t value = parseU8OrDie(*v, prompt.c_str());
        if (validate)
        {
          const std::string err = validate(std::to_string(value));
          if (!err.empty())
          {
            std::cout << "  " << err << "\n";
            continue;
          }
        }
        return value;
      }
      catch (const std::exception &e)
      {
        std::cout << "  " << e.what() << "\n";
      }
    }
  }

  std::optional<uint16_t> askU16(Session &s,
                                 const std::string &lead_in,
                                 const std::string &prompt,
                                 bool allow_empty = false,
                                 uint16_t empty_default = 0,
                                 const Validator &validate = nullptr)
  {
    if (!lead_in.empty())
    {
      explain(lead_in);
      std::cout << "\n";
    }
    for (;;)
    {
      auto v = s.repl.readLine(prompt);
      if (!v)
        return std::nullopt;
      if (v->empty() && allow_empty)
      {
        if (validate)
        {
          const std::string err = validate(std::to_string(empty_default));
          if (!err.empty())
          {
            std::cout << "  " << err << "\n";
            continue;
          }
        }
        return empty_default;
      }
      try
      {
        const uint16_t value = parseU16OrDie(*v, prompt.c_str());
        if (validate)
        {
          const std::string err = validate(std::to_string(value));
          if (!err.empty())
          {
            std::cout << "  " << err << "\n";
            continue;
          }
        }
        return value;
      }
      catch (const std::exception &e)
      {
        std::cout << "  " << e.what() << "\n";
      }
    }
  }

  bool askYesNo(Session &s, const std::string &lead_in,
                const std::string &label, bool default_yes = false)
  {
    if (!lead_in.empty())
    {
      explain(lead_in);
      std::cout << "\n";
    }
    const std::string suffix = default_yes ? "? [Y/n] " : "? [y/N] ";
    auto v = s.repl.readLine(label + suffix);
    if (!v)
      return false;
    if (v->empty())
      return default_yes;
    return (*v)[0] == 'y' || (*v)[0] == 'Y';
  }

  // ===========================================================================
  //  Nonce helper (on-chain value; mempool is not consulted)
  // ===========================================================================

  std::optional<uint64_t> fetchNonce(const RpcEndpoint &ep,
                                     const std::string &address,
                                     std::string *err)
  {
    RpcResult r = rpcCall(ep, "getNonce",
                          "{\"address\":" + jsonEscape(address) + "}");
    if (!r.transport_ok)
    {
      if (err)
        *err = r.error;
      return std::nullopt;
    }
    if (auto e = jsonRpcError(r.body))
    {
      if (err)
        *err = *e;
      return std::nullopt;
    }
    auto n = jsonFindNumber(r.body, "nonce");
    if (!n)
    {
      if (err)
        *err = "node did not return a nonce";
      return std::nullopt;
    }
    return parseU64OrDie(*n, "nonce");
  }

  // ===========================================================================
  //  Token existence / creator preflight
  //
  //  Called by the signing wizards and by the read-only wizards
  //  before dispatch. Returns true if the preflight passes, false
  //  otherwise; on false it prints the reason to stderr.
  //
  //  `require_creator` is true for MintToken and UpdateTokenMeta.
  //  False for BurnToken, which any holder may do.
  // ===========================================================================

  bool preflightToken(Session &s, Id token_id, bool require_creator)
  {
    //  Native token (id 0) never participates in these ops. The
    //  server-side checks reject them anyway; catching them here
    //  saves a round trip.
    if (token_id == 0)
    {
      std::cerr << "  token id 0 is the native coin and cannot be used "
                   "with this command\n";
      return false;
    }

    RpcResult tr = rpcCall(s.args.rpc, "getTokenInfo",
                           "{\"token_id\":" + std::to_string(token_id) + "}");
    if (!tr.transport_ok)
    {
      std::cerr << "  couldn't reach the node to check the token: "
                << tr.error << "\n";
      return false;
    }

    if (auto e = jsonRpcError(tr.body); e.has_value())
    {
      //  The node has an error code for "token not found", but
      //  catching it here gives us a cleaner message than the raw
      //  code.
      std::cerr << "  token " << token_id
                << " does not exist on the node (" << *e << ")\n";
      if (s.args.cmd == Command::Mint ||
          s.args.cmd == Command::UpdateMeta ||
          s.args.cmd == Command::Burn)
      {
        std::cerr << "  create it first with the 'create' command.\n";
      }
      return false;
    }

    if (!require_creator)
      return true;

    //  The token exists. Check creator.
    auto creator = jsonFindString(tr.body, "creator");
    if (creator.has_value() && !creator->empty() &&
        *creator != s.address_str)
    {
      std::cerr
          << "  token " << token_id << " exists, but its creator is\n"
          << "    " << *creator << "\n"
          << "  and this keystore's address is\n"
          << "    " << s.address_str << "\n"
          << "  only the creator can do this.\n";
      return false;
    }

    return true;
  }

  // ===========================================================================
  //  Keystore management
  // ===========================================================================

  bool ensureKeystore(Session &s)
  {
    if (s.ks_loaded)
      return true;
    if (s.args.keystore.empty())
    {
      std::cout << "  no keystore is loaded\n";
      return false;
    }

    Wallet::WalletStatus st;
    auto ks_opt = Wallet::EncryptedKeyStore::open(s.args.keystore, &st);
    if (!ks_opt.has_value())
    {
      std::cout << "  couldn't open the keystore at '"
                << s.args.keystore << "'\n";
      reportWalletError("reason", st);
      std::cout << "  (check the path, file permissions, and that it is a\n"
                << "   keystore file, not a backup or a seed phrase)\n";
      return false;
    }

    std::unique_ptr<Wallet::EncryptedKeyStore> ks = std::move(*ks_opt);

    const std::string password = resolvePassword(s.args);
    const Wallet::WalletError err = ks->unlock(password);
    if (err != Wallet::WalletError::Ok)
    {
      Wallet::WalletStatus unlock_err = Wallet::WalletStatus::fail(err, "");
      std::cout << "  couldn't unlock the keystore\n";
      reportWalletError("reason", unlock_err);
      std::cout << "  (the password is wrong, or the file is damaged)\n";
      return false;
    }

    auto from_addr = Wallet::decodeAddress(ks->address(), ks->network());
    if (!from_addr.has_value())
    {
      std::cout << "  keystore address is not decodable: "
                << ks->address() << "\n";
      return false;
    }

    s.ks = std::move(ks);
    s.from_addr = *from_addr;
    s.chain_id = s.ks->chainId();
    s.network = s.ks->network();
    s.address_str = s.ks->address();
    s.ks_loaded = true;

    const char *net_name = "mainnet";
    if (s.network == Wallet::Network::Testnet)
      net_name = "testnet";
    else if (s.network == Wallet::Network::Regtest)
      net_name = "regtest";

    std::cout << "\n  unlocked on " << net_name << "\n";
    std::cout << "  address: " << s.address_str << "\n";
    return true;
  }

  bool promptForKeystore(Session &s)
  {
    std::cout << "\nWhich keystore would you like to use?\n\n";
    explain(
        "A keystore is a file holding your encrypted BIP-39 seed. If you "
        "already have one — from the wallet CLI, from a previous run of "
        "this tool, or from a backup — enter its path. If you don't have "
        "one yet, this tool can't create one yet; use the wallet CLI's "
        "'create' command first, then come back here.\n\n"
        "Paths may start with '~' for your home directory. Relative paths "
        "resolve against the current directory.");

    auto v = s.repl.readLine("\nkeystore path: ");
    if (!v || v->empty())
      return false;
    s.args.keystore = expandTilde(*v);
    s.keystore_path = s.args.keystore;
    return true;
  }

  // ===========================================================================
  //  Transaction pipeline
  // ===========================================================================

  std::optional<uint64_t> resolveNonce(Session &s)
  {
    if (s.args.nonce.has_value())
    {
      std::cout << "  using nonce " << *s.args.nonce << " (set manually)\n";
      return *s.args.nonce;
    }

    std::cout << "  asking the node for the next nonce…\n";
    std::string err;
    auto n = fetchNonce(s.args.rpc, s.address_str, &err);
    if (n)
    {
      std::cout << "  nonce: " << *n << "\n";
      return n;
    }

    std::cout << "  couldn't get the nonce automatically: " << err << "\n";
    auto line = s.repl.readLine("  enter nonce manually: ");
    if (!line)
      return std::nullopt;
    return parseU64OrDie(*line, "nonce");
  }

  // Sign, print review, then either submit (with retry) or simulate.
  int buildSignAndMaybeSend(Session &s, Core::Transaction &&tx)
  {
    if (s.args.dry_run)
    {
      std::cout << "\nSigning for a dry run (nothing will be submitted)\n";
      Wallet::WalletStatus st;
      Wallet::LocalSigner signer(*s.ks);
      auto signing_hash = Wallet::signTransaction(
          tx, signer, Wallet::clrtyPath(0, 0, 0), &st);
      if (!signing_hash.has_value())
      {
        reportWalletError("cannot sign transaction", st);
        return 1;
      }
      printTxSummary(tx, &*signing_hash, s.network, "Signed transaction");

      auto bytes = tx.serialize();
      const std::string hex = "0x" + bytesToHex(bytes.data(), bytes.size());
      std::cout << "Asking the node to simulate it…\n";
      RpcResult r = rpcCall(s.args.rpc, "simulateTransaction",
                            "{\"tx\":" + jsonEscape(hex) + "}");
      if (!r.transport_ok)
      {
        std::cerr << "  the node isn't responding: " << r.error << "\n";
        std::cerr << "  (is the node running at "
                  << s.args.rpc.host << ":" << s.args.rpc.port << "?)\n";
        return 1;
      }
      if (auto e = jsonRpcError(r.body))
      {
        std::cerr << "  the node rejected the simulation: " << *e;
        const std::string human = humanError(*e);
        if (!human.empty())
          std::cerr << "  (" << human << ")";
        std::cerr << "\n";
        return 1;
      }
      std::cout << "\nSimulation result:\n"
                << r.body << "\n";
      return 0;
    }

    std::cout << "\nSigning the transaction…\n";
    Wallet::WalletStatus st;
    Wallet::LocalSigner signer(*s.ks);
    auto signing_hash = Wallet::signTransaction(
        tx, signer, Wallet::clrtyPath(0, 0, 0), &st);
    if (!signing_hash.has_value())
    {
      reportWalletError("cannot sign transaction", st);
      return 1;
    }

    if (s.args.raw)
    {
      printRaw(tx);
    }
    else
    {
      printTxSummary(tx, &*signing_hash, s.network, "Signed transaction");
    }

    if (!s.args.send)
    {
      if (!s.args.raw)
      {
        auto bytes = tx.serialize();
        std::cout << "Raw hex (submit with sendRawTransaction):\n"
                  << "0x" << bytesToHex(bytes.data(), bytes.size()) << "\n";
      }
      return 0;
    }

    const std::string where =
        s.args.rpc.host + ":" + std::to_string(s.args.rpc.port);
    if (!s.args.yes && !askYesNo(s, "", "Submit to " + where,
                                 /*default_yes=*/false))
    {
      std::cout << "Aborted; nothing was submitted.\n";
      return 0;
    }

    // The node's getNonce reads committed state, so a freshly-submitted
    // tx that has not yet been mined will not be reflected. On
    // nonce-too-low, re-fetch the nonce from the node and retry. Do
    // NOT blindly increment: on a chain where a prior submission left
    // a queued tx, the correct next nonce may be higher than our local
    // value by more than one, and an incremented guess that is still
    // wrong would be admitted to the mempool and stall block
    // production. Re-fetching is always right.
    constexpr int MAX_ATTEMPTS = 5;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt)
    {
      auto bytes = tx.serialize();
      const std::string hex = "0x" + bytesToHex(bytes.data(), bytes.size());
      std::cout << "Submitting…\n";
      RpcResult r = rpcCall(s.args.rpc, "sendRawTransaction",
                            "{\"tx\":" + jsonEscape(hex) + "}");
      if (!r.transport_ok)
      {
        std::cerr << "  the node isn't responding: " << r.error << "\n";
        std::cerr << "  (is the node running at "
                  << s.args.rpc.host << ":" << s.args.rpc.port << "?)\n";
        return 1;
      }
      if (auto e = jsonRpcError(r.body))
      {
        if (*e == "nonce-too-low" && attempt + 1 < MAX_ATTEMPTS)
        {
          std::cout << "  node says the nonce is too low; re-fetching\n";

          std::string err;
          auto fresh = fetchNonce(s.args.rpc, s.address_str, &err);
          if (!fresh)
          {
            std::cerr << "  couldn't re-fetch nonce: " << err << "\n";
            return 1;
          }
          if (*fresh <= tx.nonce)
          {
            std::cerr
                << "  node still reports nonce " << *fresh
                << " but rejected nonce " << tx.nonce << ".\n"
                << "  a pending transaction for this address is likely\n"
                << "  blocking us. Check the mempool, or use 'nonce' to\n"
                << "  override.\n";
            return 1;
          }

          tx.nonce = *fresh;
          Wallet::WalletStatus rst;
          Wallet::LocalSigner resigner(*s.ks);
          auto h = Wallet::signTransaction(
              tx, resigner, Wallet::clrtyPath(0, 0, 0), &rst);
          if (!h.has_value())
          {
            reportWalletError("cannot re-sign transaction", rst);
            return 1;
          }
          std::cout << "  retrying with nonce " << tx.nonce << "\n";
          continue;
        }
        std::cerr << "  the node rejected the transaction: " << *e;
        const std::string human = humanError(*e);
        if (!human.empty())
          std::cerr << "  (" << human << ")";
        std::cerr << "\n";
        return 1;
      }
      std::cout << "Accepted. Node reply:\n"
                << r.body << "\n";
      return 0;
    }

    std::cerr << "  gave up after " << MAX_ATTEMPTS
              << " attempts at a nonce the node would accept\n";
    return 1;
  }

  int runListAll(const RpcEndpoint &ep)
  {
    constexpr uint64_t PAGE = 500;
    uint64_t offset = 0;
    for (;;)
    {
      RpcResult r = rpcCall(
          ep, "getAllTokens",
          "{\"limit\":" + std::to_string(PAGE) +
              ",\"offset\":" + std::to_string(offset) + "}");
      if (!r.transport_ok)
      {
        std::cerr << "  the node isn't responding: " << r.error << "\n";
        std::cerr << "  (is the node running at "
                  << ep.host << ":" << ep.port << "?)\n";
        return 1;
      }
      if (auto e = jsonRpcError(r.body))
      {
        std::cerr << "  the node refused: " << *e << "\n";
        return 1;
      }
      std::cout << r.body << "\n";

      auto count = jsonFindNumber(r.body, "count");
      if (!count)
        break;
      const uint64_t emitted = parseU64OrDie(*count, "count");
      if (emitted < PAGE)
        break;
      offset += emitted;
    }
    return 0;
  }

  // ===========================================================================
  //  Dispatch (shared by walkthrough and one-shot)
  // ===========================================================================

  int dispatch(Session &s)
  {
    const Args &args = s.args;
    switch (args.cmd)
    {
    case Command::Info:
      std::cout << "Fetching token " << args.token_id << " from the node…\n";
      return rpcAndPrint(args.rpc, "getTokenInfo",
                         "{\"token_id\":" + std::to_string(args.token_id) + "}")
                 ? 0
                 : 1;

    case Command::Supply:
      std::cout << "Fetching supply for token " << args.token_id << "…\n";
      return rpcAndPrint(args.rpc, "getTokenSupply",
                         "{\"token_id\":" + std::to_string(args.token_id) + "}")
                 ? 0
                 : 1;

    case Command::List:
      std::cout << "Fetching all tokens…\n";
      return runListAll(args.rpc);

    case Command::Send:
    {
      RpcResult r = rpcCall(args.rpc, "sendRawTransaction",
                            "{\"tx\":" + jsonEscape(args.hex_to_send) + "}");
      if (!r.transport_ok)
      {
        std::cerr << "  the node isn't responding: " << r.error << "\n";
        return 1;
      }
      if (auto e = jsonRpcError(r.body))
      {
        std::cerr << "  the node rejected the transaction: " << *e;
        const std::string human = humanError(*e);
        if (!human.empty())
          std::cerr << "  (" << human << ")";
        std::cerr << "\n";
        return 1;
      }
      std::cout << r.body << "\n";
      return 0;
    }

    case Command::Balance:
    {
      if (!ensureKeystore(s))
        return 1;
      std::string params = "{\"address\":" + jsonEscape(s.address_str);
      if (args.token_id != 0)
        params += ",\"token_id\":" + std::to_string(args.token_id);
      params += "}";
      return rpcAndPrint(args.rpc, "getBalance", params) ? 0 : 1;
    }

    case Command::Whoami:
    {
      if (!ensureKeystore(s))
        return 1;
      return rpcAndPrint(args.rpc, "getAddressStats",
                         "{\"address\":" + jsonEscape(s.address_str) + "}")
                 ? 0
                 : 1;
    }

    case Command::Mempool:
      return rpcAndPrint(args.rpc, "getMempoolList",
                         "{\"limit\":50,\"order_by\":\"fee\"}")
                 ? 0
                 : 1;

    case Command::Stats:
      return rpcAndPrint(args.rpc, "getChainStats", "{}") ? 0 : 1;

    default:
      break;
    }

    // ---- signing commands ----
    if (!ensureKeystore(s))
      return 1;

    // Preflight for token operations: if the token doesn't exist, or
    // we aren't the creator, the executor will reject the tx. Catch
    // it here so we don't sign, submit, and burn a fee on a tx that
    // cannot apply. The node has the final say; this is a guardrail.
    if (args.cmd == Command::Mint || args.cmd == Command::Burn ||
        args.cmd == Command::UpdateMeta)
    {
      const bool creator_only =
          (args.cmd == Command::Mint || args.cmd == Command::UpdateMeta);
      if (!preflightToken(s, args.token_id, creator_only))
        return 1;
    }

    auto nonce = resolveNonce(s);
    if (!nonce)
      return 1;
    s.args.nonce = nonce;

    Wallet::WalletStatus st;
    std::optional<Core::Transaction> tx;

    switch (args.cmd)
    {
    case Command::Create:
    {
      Wallet::CreateTokenParams p;
      p.common.chain_id = s.chain_id;
      p.common.nonce = *nonce;
      p.common.fee = args.fee;
      p.name = args.name;
      p.symbol = args.symbol;
      p.decimals = args.decimals;
      p.backing = args.backing;
      p.max_supply = args.max_supply;
      p.royalty_bps = args.royalty_bps;
      if (!args.fingerprint_hex.empty())
        p.fingerprint = parseHashHexOrDie(args.fingerprint_hex, "--fingerprint");
      tx = Wallet::buildCreateToken(*s.from_addr, p, &st);
      break;
    }
    case Command::Mint:
    {
      Wallet::MintTokenParams p;
      p.common.chain_id = s.chain_id;
      p.common.nonce = *nonce;
      p.common.fee = args.fee;
      p.token_id = args.token_id;
      p.to = parseAddressOrDie(args.to, s.network, "to");
      p.amount = args.amount;
      tx = Wallet::buildMintToken(*s.from_addr, p, &st);
      break;
    }
    case Command::Burn:
    {
      Wallet::BurnTokenParams p;
      p.common.chain_id = s.chain_id;
      p.common.nonce = *nonce;
      p.common.fee = args.fee;
      p.token_id = args.token_id;
      p.amount = args.amount;
      tx = Wallet::buildBurnToken(*s.from_addr, p, &st);
      break;
    }
    case Command::UpdateMeta:
    {
      Wallet::UpdateTokenMetaParams p;
      p.common.chain_id = s.chain_id;
      p.common.nonce = *nonce;
      p.common.fee = args.fee;
      p.token_id = args.token_id;
      p.new_name = args.new_name;
      p.new_symbol = args.new_symbol;
      p.new_royalty_bps = args.new_royalty_bps;
      tx = Wallet::buildUpdateTokenMeta(*s.from_addr, p, &st);
      break;
    }
    default:
      return 1;
    }

    if (!tx.has_value())
    {
      reportWalletError("cannot build transaction", st);
      return 1;
    }

    return buildSignAndMaybeSend(s, std::move(*tx));
  }

  // ===========================================================================
  //  Walkthrough wizards
  // ===========================================================================

  //  Validators used by the wizards. Each returns "" on success and a
  //  human-readable error string otherwise.
  namespace Validators
  {
    Validator symbol()
    {
      return [](const std::string &v) -> std::string
      {
        if (v.size() < 3)
          return "a symbol must be at least 3 characters";
        if (v.size() > 8)
          return "a symbol must be at most 8 characters";
        return "";
      };
    }

    Validator nonemptyName()
    {
      return [](const std::string &v) -> std::string
      {
        if (v.size() > 64)
          return "the name is too long (max 64 characters)";
        return "";
      };
    }

    Validator decimals()
    {
      return [](const std::string &v) -> std::string
      {
        try
        {
          const uint64_t d = parseU64OrDie(v, "decimals");
          if (d > 18)
            return "decimals must be 0..18";
        }
        catch (...)
        {
          return "decimals must be a number 0..18";
        }
        return "";
      };
    }

    Validator backing()
    {
      return [](const std::string &v) -> std::string
      {
        if (v != "0" && v != "1")
          return "backing must be 0 (unbacked) or 1 (bridged)";
        return "";
      };
    }

    Validator fingerprintHex()
    {
      return [](const std::string &v) -> std::string
      {
        if (v.size() != 64)
          return "a fingerprint must be exactly 64 hex characters";
        for (char c : v)
        {
          if (!std::isxdigit((unsigned char)c))
            return "a fingerprint must contain only hex characters";
        }
        return "";
      };
    }

    Validator royaltyBps()
    {
      return [](const std::string &v) -> std::string
      {
        try
        {
          const uint64_t r = parseU64OrDie(v, "royalty");
          if (r > 10000)
            return "royalty must be 0..10000 basis points";
        }
        catch (...)
        {
          return "royalty must be a number 0..10000";
        }
        return "";
      };
    }

    Validator nonZeroU64(const char *what)
    {
      const std::string w = what;
      return [w](const std::string &v) -> std::string
      {
        try
        {
          const uint64_t x = parseU64OrDie(v, w.c_str());
          if (x == 0)
            return "the " + w + " must be non-zero";
        }
        catch (...)
        {
          return "the " + w + " must be a number";
        }
        return "";
      };
    }
  }

  int walkCreate(Session &s)
  {
    s.args.cmd = Command::Create;
    const int TOTAL = 7;

    std::cout << "\nCreating a new fungible token\n";
    hr();
    explain(
        "You are about to create a new fungible token on this chain. "
        "After this transaction confirms, you (the creator) will be the "
        "only one who can mint more of it, burn from your own balance, "
        "or change its name, symbol, or royalty. Everything else about "
        "the token is fixed forever.");

    step(1, TOTAL, "Name");
    auto name = askString(s,
                          "A human-readable label. This is what wallets and block explorers "
                          "will show. Pick something distinctive; names do not have to be "
                          "unique, but a collision will confuse your users.",
                          "name: ", /*allow_empty=*/false,
                          Validators::nonemptyName());
    if (!name)
      return 1;
    s.args.name = *name;

    step(2, TOTAL, "Symbol");
    auto symbol = askString(s,
                            "A short ticker symbol, typically three to eight characters. "
                            "Conventionally uppercase letters and digits. The chain enforces "
                            "only a length limit; it does not check for collisions.",
                            "symbol: ", /*allow_empty=*/false,
                            Validators::symbol());
    if (!symbol)
      return 1;
    s.args.symbol = *symbol;

    step(3, TOTAL, "Decimals");
    auto dec = askU8(s,
                     "How many decimal places the token has. 0 means whole units only; "
                     "8 is the common choice and matches most fungible tokens; 18 is "
                     "the Ethereum-style default. The maximum is 18. This number "
                     "cannot be changed after creation.",
                     "decimals [8]: ", /*allow_empty=*/true, 8,
                     Validators::decimals());
    if (!dec)
      return 1;
    s.args.decimals = *dec;

    step(4, TOTAL, "Backing");
    auto backing = askU8(s,
                         "Is this token a free-standing asset (0) or a claim on some "
                         "external asset (1, 'bridged')?\n\n"
                         "Most tokens are 0. Choose 1 only if you are wrapping an asset "
                         "that lives on another chain, and you have a 32-byte content "
                         "hash to identify it.",
                         "backing (0 or 1) [0]: ", /*allow_empty=*/true, 0,
                         Validators::backing());
    if (!backing)
      return 1;
    s.args.backing = *backing;

    if (s.args.backing == 1)
    {
      step(5, TOTAL, "Fingerprint");
      auto fp = askString(s,
                          "A 64-character hex string (32 bytes) that identifies the "
                          "external asset. This is stored verbatim on chain and returned "
                          "by the RPC.",
                          "fingerprint: ", /*allow_empty=*/false,
                          Validators::fingerprintHex());
      if (!fp)
        return 1;
      s.args.fingerprint_hex = *fp;
    }
    else
    {
      std::cout << "\nStep 5 of " << TOTAL
                << " — Fingerprint (skipped; backing is 0)\n";
    }

    step(6, TOTAL, "Max supply");
    auto supply = askU64(s,
                         "The maximum number of atomic units that can ever exist. This is "
                         "in atomic units, not whole tokens: for a token with N decimals, "
                         "1 token = 10^N atomic units. Zero means no cap, which means you "
                         "can mint without limit later. This number cannot be changed.",
                         "max-supply (atomic, 0 = unlimited) [0]: ",
                         /*allow_empty=*/true, 0);
    if (!supply)
      return 1;
    s.args.max_supply = *supply;

    step(7, TOTAL, "Royalty");
    auto royalty = askU16(s,
                          "An advisory royalty in basis points (1 bps = 0.01%). 500 means "
                          "5%. The chain stores this and the RPC returns it, but it is not "
                          "enforced by the protocol. Set 0 if you have no royalty policy.",
                          "royalty bps [0]: ", /*allow_empty=*/true, 0,
                          Validators::royaltyBps());
    if (!royalty)
      return 1;
    s.args.royalty_bps = *royalty;

    hr();
    std::cout << "Ready to build and sign.\n";
    return dispatch(s);
  }

  int walkMint(Session &s)
  {
    s.args.cmd = Command::Mint;
    const int TOTAL = 3;

    std::cout << "\nMinting units of an existing token\n";
    hr();
    explain(
        "Minting creates new units of a token you created. The amount "
        "is added to the recipient's balance and to the token's tracked "
        "supply. It fails if it would push supply past max-supply, or "
        "if you are not the token's creator.");

    step(1, TOTAL, "Token id");
    auto id = askU64(s,
                     "The numeric id the chain assigned to your token when it was "
                     "created. You can find it in the create transaction's receipt, "
                     "or by listing all tokens.",
                     "token id: ", /*allow_empty=*/false, 0,
                     Validators::nonZeroU64("token id"));
    if (!id)
      return 1;
    s.args.token_id = static_cast<uint32_t>(*id);

    step(2, TOTAL, "Recipient");
    auto to = askString(s,
                        "The address that will receive the minted units. Must be a valid "
                        "address for this network.",
                        "to (address): ");
    if (!to)
      return 1;
    s.args.to = *to;

    step(3, TOTAL, "Amount");
    auto amt = askU64(s,
                      "The number of atomic units to mint. For a token with N decimals, "
                      "1 whole token = 10^N atomic units.",
                      "amount (atomic): ", /*allow_empty=*/false, 0,
                      Validators::nonZeroU64("amount"));
    if (!amt)
      return 1;
    s.args.amount = *amt;

    hr();
    return dispatch(s);
  }

  int walkBurn(Session &s)
  {
    s.args.cmd = Command::Burn;
    const int TOTAL = 2;

    std::cout << "\nBurning units of a token you hold\n";
    hr();
    explain(
        "Burning destroys units from your own balance and reduces the "
        "token's tracked supply by the same amount. You can burn any "
        "token you hold; you cannot burn from someone else's balance. "
        "Burning is irreversible.");

    step(1, TOTAL, "Token id");
    auto id = askU64(s,
                     "The numeric id of the token you want to burn from.",
                     "token id: ", /*allow_empty=*/false, 0,
                     Validators::nonZeroU64("token id"));
    if (!id)
      return 1;
    s.args.token_id = static_cast<uint32_t>(*id);

    step(2, TOTAL, "Amount");
    auto amt = askU64(s,
                      "How many atomic units to burn. Must be no more than your "
                      "current balance of this token.",
                      "amount (atomic): ", /*allow_empty=*/false, 0,
                      Validators::nonZeroU64("amount"));
    if (!amt)
      return 1;
    s.args.amount = *amt;

    hr();
    return dispatch(s);
  }

  int walkUpdateMeta(Session &s)
  {
    s.args.cmd = Command::UpdateMeta;
    const int TOTAL = 4;

    std::cout << "\nUpdating a token's metadata\n";
    hr();
    explain(
        "You can change a token's name, its symbol, or its royalty "
        "hint. Each field is optional; leave a field blank to leave it "
        "unchanged. Only the token's creator can update it. The max "
        "supply and the decimals cannot be changed.");

    step(1, TOTAL, "Token id");
    auto id = askU64(s, "The numeric id of the token to update.",
                     "token id: ", /*allow_empty=*/false, 0,
                     Validators::nonZeroU64("token id"));
    if (!id)
      return 1;
    s.args.token_id = static_cast<uint32_t>(*id);

    step(2, TOTAL, "New name");
    auto name = askString(s,
                          "Leave blank to keep the current name.",
                          "new name (blank = no change): ", /*allow_empty=*/true,
                          Validators::nonemptyName());
    if (!name)
      return 1;
    s.args.new_name = *name;

    step(3, TOTAL, "New symbol");
    auto sym = askString(s,
                         "Leave blank to keep the current symbol.",
                         "new symbol (blank = no change): ", /*allow_empty=*/true,
                         Validators::symbol());
    if (!sym)
      return 1;
    s.args.new_symbol = *sym;

    step(4, TOTAL, "New royalty");
    auto roy = askU16(s,
                      "Leave blank or enter 0 to keep the current royalty.",
                      "new royalty bps (0 = no change): ",
                      /*allow_empty=*/true, 0,
                      Validators::royaltyBps());
    if (!roy)
      return 1;
    s.args.new_royalty_bps = *roy;

    if (s.args.new_name.empty() && s.args.new_symbol.empty() &&
        s.args.new_royalty_bps == 0)
    {
      std::cout << "\nYou didn't ask for any change; nothing to do.\n";
      return 0;
    }
    hr();
    return dispatch(s);
  }

  int walkInfo(Session &s)
  {
    s.args.cmd = Command::Info;
    std::cout << "\nLooking up a token\n";
    hr();
    explain(
        "Fetches the token's metadata: creator, name, symbol, decimals, "
        "backing, max supply, current supply, royalty, and fingerprint "
        "if any.");
    auto id = askU64(s, "", "token id: ", /*allow_empty=*/false, 0,
                     Validators::nonZeroU64("token id"));
    if (!id)
      return 1;
    s.args.token_id = static_cast<uint32_t>(*id);
    std::cout << "\n";
    return dispatch(s);
  }

  int walkSupply(Session &s)
  {
    s.args.cmd = Command::Supply;
    std::cout << "\nLooking up a token's supply\n";
    hr();
    auto id = askU64(s, "", "token id: ", /*allow_empty=*/false, 0,
                     Validators::nonZeroU64("token id"));
    if (!id)
      return 1;
    s.args.token_id = static_cast<uint32_t>(*id);
    std::cout << "\n";
    return dispatch(s);
  }

  int walkSend(Session &s)
  {
    s.args.cmd = Command::Send;
    std::cout << "\nSubmit a pre-signed transaction\n";
    hr();
    explain(
        "Paste the raw hex of a transaction that was already signed. "
        "This can come from another invocation of this tool with --raw, "
        "from a hardware wallet, or from any signer you trust. The "
        "node will validate the signature and the transaction body "
        "before accepting it.");
    auto hex = askString(s, "", "hex (0x...): ");
    if (!hex)
      return 1;
    s.args.hex_to_send = *hex;
    std::cout << "\n";
    return dispatch(s);
  }

  int walkBalance(Session &s)
  {
    s.args.cmd = Command::Balance;
    std::cout << "\nCheck a balance\n";
    hr();
    if (!ensureKeystore(s))
      return 1;
    auto id = askU64(s,
                     "Enter a token id, or 0 for the native coin (CLRTY).",
                     "token id (0 = native) [0]: ", /*allow_empty=*/true, 0);
    if (!id)
      return 1;
    s.args.token_id = static_cast<uint32_t>(*id);
    std::cout << "\n";
    return dispatch(s);
  }

  int walkWhoami(Session &s)
  {
    s.args.cmd = Command::Whoami;
    std::cout << "\nYour account's stats\n";
    hr();
    if (!ensureKeystore(s))
      return 1;
    std::cout << "\n";
    return dispatch(s);
  }

  int walkMempool(Session &s)
  {
    s.args.cmd = Command::Mempool;
    std::cout << "\nPending transactions (top 50 by fee)\n";
    hr();
    std::cout << "\n";
    return dispatch(s);
  }

  int walkStats(Session &s)
  {
    s.args.cmd = Command::Stats;
    std::cout << "\nChain statistics\n";
    hr();
    std::cout << "\n";
    return dispatch(s);
  }

  // ===========================================================================
  //  Walkthrough top level
  // ===========================================================================

  void printMenu(const Session &s)
  {
    std::cout << "\nWhat would you like to do?\n\n";
    std::cout << "  1  create a new token\n";
    std::cout << "  2  mint units of a token you created\n";
    std::cout << "  3  burn units of a token you hold\n";
    std::cout << "  4  update a token's name, symbol, or royalty\n";
    std::cout << "\n";
    std::cout << "  5  look up a token by id\n";
    std::cout << "  6  look up a token's supply\n";
    std::cout << "  7  list all tokens\n";
    std::cout << "  8  submit a pre-signed transaction\n";
    std::cout << "\n";
    std::cout << "  9  your balance\n";
    std::cout << " 10  your account stats\n";
    std::cout << " 11  pending transactions (mempool)\n";
    std::cout << " 12  chain statistics\n";
    std::cout << "\n";
    std::cout << "  s  session settings (fee, nonce, RPC, keystore)\n";
    std::cout << "  h  help\n";
    std::cout << "  q  quit\n";
    if (!s.ks_loaded)
      std::cout << "\n(no keystore loaded — signing commands will ask for one)\n";
  }

  void printHelp()
  {
    std::cout << "\nAbout this walkthrough\n";
    hr();
    explain(
        "This tool walks you through token operations on a Conceal / "
        "CLRTY node. Each wizard explains every field before it asks "
        "for it, and shows a review block before signing.\n\n"
        "Signing commands — create, mint, burn, update-meta — need "
        "a keystore and a fee. The keystore is a file holding your "
        "encrypted seed; the fee is paid in the native coin. If you "
        "haven't set either, the wizard will ask.\n\n"
        "Query commands — lookups, list, stats, mempool — don't need "
        "a keystore and don't sign anything.\n\n"
        "Nothing is submitted unless you confirm it at the review "
        "step, or unless you launched the tool with --send in one-shot "
        "mode. Ctrl+D at any prompt cancels the current operation.");
  }

  int runSettings(Session &s)
  {
    for (;;)
    {
      std::cout << "\nSession settings\n";
      hr();
      std::cout << "  keystore path: "
                << (s.args.keystore.empty() ? "(unset)" : s.args.keystore) << "\n";
      std::cout << "  loaded:        "
                << (s.ks_loaded ? "yes" : "no") << "\n";
      std::cout << "  rpc endpoint:  "
                << s.args.rpc.host << ":" << s.args.rpc.port << "\n";
      std::cout << "  fee:           "
                << s.args.fee << " atomic units\n";
      std::cout << "  nonce:         "
                << (s.args.nonce ? std::to_string(*s.args.nonce) : "auto")
                << "\n";
      std::cout << "  output:        "
                << (s.args.raw ? "raw hex only" : "summary") << "\n";
      std::cout << "  auto-confirm:  "
                << (s.args.yes ? "yes" : "no") << "\n";
      std::cout << "\n";
      std::cout << "  k  change keystore\n";
      std::cout << "  l  lock the keystore\n";
      std::cout << "  r  change rpc endpoint\n";
      std::cout << "  f  change fee\n";
      std::cout << "  n  change nonce policy\n";
      std::cout << "  o  toggle output mode\n";
      std::cout << "  c  toggle auto-confirm\n";
      std::cout << "  b  back\n";

      auto v = s.repl.readLine("\nsettings> ");
      if (!v)
        return 0;
      if (v->empty())
        continue;

      const char c = (*v)[0];
      if (c == 'b')
        return 0;
      if (c == 'k')
      {
        if (!promptForKeystore(s))
          continue;
        s.ks_loaded = false;
        s.ks.reset();
        s.from_addr.reset();
        ensureKeystore(s);
        continue;
      }
      if (c == 'l')
      {
        s.ks_loaded = false;
        s.ks.reset();
        s.from_addr.reset();
        std::cout << "  locked\n";
        continue;
      }
      if (c == 'r')
      {
        auto ep = s.repl.readLine("  host:port [127.0.0.1:9633]: ");
        if (!ep)
          continue;
        if (!ep->empty())
        {
          std::string err;
          if (!parseEndpoint(*ep, s.args.rpc, err))
            std::cout << "  " << err << "\n";
          else
            std::cout << "  rpc = " << s.args.rpc.host << ":"
                      << s.args.rpc.port << "\n";
        }
        continue;
      }
      if (c == 'f')
      {
        auto f = s.repl.readLine("  fee (atomic): ");
        if (!f || f->empty())
          continue;
        try
        {
          s.args.fee = parseU64OrDie(*f, "fee");
        }
        catch (const std::exception &e)
        {
          std::cout << "  " << e.what() << "\n";
        }
        continue;
      }
      if (c == 'n')
      {
        auto n = s.repl.readLine("  nonce (number or 'auto'): ");
        if (!n || n->empty())
          continue;
        if (*n == "auto")
          s.args.nonce = std::nullopt;
        else
        {
          try
          {
            s.args.nonce = parseU64OrDie(*n, "nonce");
          }
          catch (const std::exception &e)
          {
            std::cout << "  " << e.what() << "\n";
          }
        }
        continue;
      }
      if (c == 'o')
      {
        s.args.raw = !s.args.raw;
        continue;
      }
      if (c == 'c')
      {
        s.args.yes = !s.args.yes;
        continue;
      }
    }
  }

  // Returns 1..12 for numeric choices, 's'/'h'/'q' for the letters, 0 on EOF.
  int readChoice(Session &s)
  {
    for (;;)
    {
      auto v = s.repl.readLine("\nchoice: ");
      if (!v)
        return 0;
      if (v->empty())
        continue;
      const std::string t = *v;
      if (t == "q" || t == "quit" || t == "exit")
        return 'q';
      if (t == "h" || t == "help" || t == "?")
        return 'h';
      if (t == "s" || t == "settings")
        return 's';

      errno = 0;
      char *end = nullptr;
      const long n = std::strtol(t.c_str(), &end, 10);
      if (errno == 0 && end != t.c_str() && *end == '\0' && n >= 1 && n <= 12)
        return static_cast<int>(n);

      std::cout << "  please enter a number from 1 to 12, or s/h/q\n";
    }
  }

  int runWalkthrough()
  {
    Session s;
    s.args.send = true; // walkthrough submits by default
    s.args.yes = false; // but always confirms

    std::cout << "\n";
    hr();
    std::cout << "CLRTY token tool\n";
    hr();
    explain(
        "This is a guided tool for working with fungible tokens on a "
        "CLRTY node. It will walk you through each operation.\n\n"
        "First, we need a keystore. A keystore is a file holding your "
        "encrypted BIP-39 seed. It is the thing that signs transactions "
        "on your behalf, so the tool cannot do anything that spends "
        "money without one.");

    if (!promptForKeystore(s))
    {
      std::cout << "\nNo keystore given. Exiting.\n";
      return 0;
    }

    if (!ensureKeystore(s))
    {
      std::cout << "\nCouldn't load that keystore. Exiting.\n";
      return 1;
    }

    std::cout << "\nWhat fee would you like to use for signed transactions?\n\n";
    explain(
        "The fee is paid in the native coin (atomic units of CLRTY). "
        "On a regtest chain, a small fee like 1000 is fine. On mainnet "
        "you'll want something the network will accept.");
    auto f = s.repl.readLine("fee in atomic units [1000]: ");
    if (f && !f->empty())
    {
      try
      {
        s.args.fee = parseU64OrDie(*f, "fee");
      }
      catch (const std::exception &e)
      {
        std::cout << "  " << e.what() << "\n";
      }
    }
    if (s.args.fee == 0)
      s.args.fee = 1000;
    std::cout << "  fee: " << s.args.fee << " atomic units\n";

    for (;;)
    {
      printMenu(s);
      const int c = readChoice(s);
      if (c == 0 || c == 'q')
        break;

      try
      {
        switch (c)
        {
        case 'h':
          printHelp();
          continue;
        case 's':
          runSettings(s);
          continue;
        case 1:
          walkCreate(s);
          continue;
        case 2:
          walkMint(s);
          continue;
        case 3:
          walkBurn(s);
          continue;
        case 4:
          walkUpdateMeta(s);
          continue;
        case 5:
          walkInfo(s);
          continue;
        case 6:
          walkSupply(s);
          continue;
        case 7:
        {
          s.args.cmd = Command::List;
          std::cout << "\nListing all tokens…\n";
          runListAll(s.args.rpc);
          continue;
        }
        case 8:
          walkSend(s);
          continue;
        case 9:
          walkBalance(s);
          continue;
        case 10:
          walkWhoami(s);
          continue;
        case 11:
          walkMempool(s);
          continue;
        case 12:
          walkStats(s);
          continue;
        default:
          std::cout << "  (not handled)\n";
          continue;
        }
      }
      catch (const std::exception &e)
      {
        std::cout << "  error: " << e.what() << "\n";
      }
    }

    std::cout << "\nGoodbye.\n";
    return 0;
  }

  // ===========================================================================
  //  Usage
  // ===========================================================================

  void printUsage()
  {
    std::cout
        << "Usage: token                          guided walkthrough (default)\n"
        << "       token <command> [options]      one-shot, scriptable\n"
        << "\n"
        << "Signing commands:\n"
        << "  create        create a new fungible token\n"
        << "  mint          mint units of a token you created\n"
        << "  burn          burn units of a token you hold\n"
        << "  update-meta   change a token's name, symbol, or royalty\n"
        << "\n"
        << "Query commands (no keystore needed):\n"
        << "  info <id>     fetch token metadata\n"
        << "  supply <id>   fetch current supply\n"
        << "  list          fetch all tokens (all pages)\n"
        << "  send <hex>    submit a pre-signed hex\n"
        << "  balance       getBalance for the unlocked address\n"
        << "  whoami        getAddressStats for the unlocked address\n"
        << "  mempool       getMempoolList (top 50 by fee)\n"
        << "  stats         getChainStats\n"
        << "\n"
        << "Common options:\n"
        << "  --keystore <path>        encrypted keystore to sign with\n"
        << "  --password-file <path>   read password from file (default: prompt)\n"
        << "  --nonce <n|auto>         transaction nonce (default: auto)\n"
        << "  --fee <atomic>           fee in atomic units (required to sign)\n"
        << "  --rpc <host:port>        node endpoint (default: 127.0.0.1:9633)\n"
        << "  --send                   submit after signing\n"
        << "  --yes                    skip the submit confirmation\n"
        << "  --raw                    print only the hex on stdout\n"
        << "  --dry-run                sign, then simulateTransaction\n"
        << "\n"
        << "create options:\n"
        << "  --name <text>            token name (required)\n"
        << "  --symbol <text>          token symbol (required)\n"
        << "  --decimals <d>           decimal places (default: 8, max: 18)\n"
        << "  --backing <0|1>          0 = unbacked, 1 = bridged (default: 0)\n"
        << "  --max-supply <n>         max supply in atomic units; 0 = unlimited\n"
        << "  --royalty <bps>          royalty in basis points (default: 0)\n"
        << "  --fingerprint <hex>      32-byte hex content hash (bridged only)\n"
        << "\n"
        << "mint options:\n"
        << "  --token <id>             token id to mint (required)\n"
        << "  --amount <atomic>        amount in atomic units (required)\n"
        << "  --to <addr>              recipient address (required)\n"
        << "\n"
        << "burn options:\n"
        << "  --token <id>             token id to burn (required)\n"
        << "  --amount <atomic>        amount in atomic units (required)\n"
        << "\n"
        << "update-meta options:\n"
        << "  --token <id>             token id to update (required)\n"
        << "  --new-name <text>        new name (optional)\n"
        << "  --new-symbol <text>      new symbol (optional)\n"
        << "  --new-royalty <bps>      new royalty in basis points (optional)\n"
        << "\n"
        << "Run 'token' with no arguments for the walkthrough.\n";
  }
} // anonymous namespace

// ===========================================================================
//  main
// ===========================================================================

int main(int argc, char **argv)
{
  if (argc < 2)
    return runWalkthrough();

  const std::string top = argv[1];
  if (top == "-h" || top == "--help")
  {
    printUsage();
    return 0;
  }

  try
  {
    Args args = parseArgs(argc - 1, argv + 1);
    Session s;
    s.args = args;
    return dispatch(s);
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}