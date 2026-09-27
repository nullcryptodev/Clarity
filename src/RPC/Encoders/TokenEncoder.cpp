// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TokenEncoder.h"
#include "Encoding.h"

namespace Rpc
{

  namespace
  {
    const char *backingName(Core::BackingModel b) noexcept
    {
      switch (b)
      {
      case Core::BackingModel::Unbacked:
        return "unbacked";
      case Core::BackingModel::Backed:
        return "backed";
      case Core::BackingModel::Hybrid:
        return "hybrid";
      }
      return "unknown";
    }
  } // anonymous namespace

  Common::Json encodeToken(const Core::TokenInfo &token, const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putU64(j, "id", token.id);
    j["name"] = token.name;
    j["symbol"] = token.symbol;
    j["decimals"] = static_cast<uint32_t>(token.decimals);

    // The native token has a zero creator address. Emit null instead
    // of an empty string so clients don't try to parse "" as an
    // address.
    if (token.creator.isNull())
      j["creator"] = nullptr;
    else
      putAddress(j, "creator", token.creator, hrp);

    j["backing"] = backingName(token.backing);
    j["backing_code"] = static_cast<uint32_t>(token.backing);

    putU64(j, "max_supply", token.maxSupply);
    j["royalty_bps"] = token.royaltyBps;

    if (token.fingerprint.has_value())
      putHash(j, "fingerprint", *token.fingerprint);
    else
      j["fingerprint"] = nullptr;

    j["is_native"] = token.isNative();
    j["is_bridged"] = token.isBridged();

    return j;
  }

} // namespace RpcS