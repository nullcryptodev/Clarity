// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TokenTypes.h"

#include "Common/Put.h"
#include "Common/Reader.h"

namespace Core
{
  //  State serialization

  std::vector<uint8_t> TokenInfo::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(4 + 1 + 1 + 1 + name.size() + 1 + symbol.size() + 8 + 2 + 32 + 1 + (fingerprint.has_value() ? 32 : 0));

    Common::putU32(out, id);
    out.push_back(decimals);
    out.push_back(static_cast<uint8_t>(backing));

    // Name (length-prefixed, max 64)
    uint8_t name_len = static_cast<uint8_t>(
        name.size() > TOKEN_NAME_MAX ? TOKEN_NAME_MAX : name.size());
    out.push_back(name_len);
    Common::putBytes(out, reinterpret_cast<const uint8_t *>(name.data()), name_len);

    // Symbol (length-prefixed, max 8)
    uint8_t sym_len = static_cast<uint8_t>(
        symbol.size() > TOKEN_SYMBOL_MAX ? TOKEN_SYMBOL_MAX : symbol.size());
    out.push_back(sym_len);
    Common::putBytes(out, reinterpret_cast<const uint8_t *>(symbol.data()), sym_len);

    Common::putU64(out, maxSupply);
    Common::putU16(out, royaltyBps);
    Common::putBytes(out, creator.data.data(), creator.data.size());

    // Optional fingerprint
    if (fingerprint.has_value())
    {
      out.push_back(1);
      Common::putBytes(out, fingerprint->data.data(), fingerprint->data.size());
    }
    else
    {
      out.push_back(0);
    }

    return out;
  }

  bool TokenInfo::deserializeState(const uint8_t *data, size_t len, TokenInfo &out)
  {
    Common::Reader r(data, len);

    out.id = r.readU32();
    out.decimals = r.readU8();
    out.backing = static_cast<BackingModel>(r.readU8());

    uint8_t name_len = r.readU8();
    if (name_len > TOKEN_NAME_MAX)
      return false;
    out.name = r.readString(name_len);

    uint8_t sym_len = r.readU8();
    if (sym_len > TOKEN_SYMBOL_MAX)
      return false;
    out.symbol = r.readString(sym_len);

    out.maxSupply = r.readU64();
    out.royaltyBps = r.readU16();
    r.readBytes(out.creator.data.data(), out.creator.data.size());

    uint8_t has_fp = r.readU8();
    if (has_fp)
    {
      Crypto::Hash fp;
      r.readBytes(fp.data.data(), fp.data.size());
      out.fingerprint = fp;
    }
    else
    {
      out.fingerprint.reset();
    }

    return r.ok();
  }

  //  Framework serialization

  void TokenInfo::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(name, "name");
    s(symbol, "symbol");
    s(decimals, "decimals");
    s(creator, "creator");
    s(backing, "backing");
    s(maxSupply, "max_supply");
    s(royaltyBps, "royalty_bps");

    bool hasFp = fingerprint.has_value();
    s(hasFp, "has_fingerprint");
    if (hasFp)
      s(*fingerprint, "fingerprint");
  }

  void TokenInfo::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(name, "name");
    s(symbol, "symbol");
    s(decimals, "decimals");
    s(creator, "creator");
    s(backing, "backing");
    s(maxSupply, "max_supply");
    s(royaltyBps, "royalty_bps");

    bool hasFp = fingerprint.has_value();
    s(hasFp, "has_fingerprint");
    if (hasFp)
      s(*fingerprint, "fingerprint");
  }

} // namespace Core