// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "VersionMessage.h"

#include "Common/Wire.h"

#include <cstring>

namespace P2P
{
  //  Version

  std::vector<uint8_t> serializeVersion(const VersionMessage &v)
  {
    std::vector<uint8_t> out;
    out.reserve(4 + 8 + 8 + 2 + 1 + 32 + 8 + 8);

    Common::Writer w(out);
    w.writeU32(v.protocolVersion);
    w.writeU64(v.networkNonce);
    w.writeI64(v.timestamp);
    w.writeU16(v.listenPort);
    w.writeLengthPrefixedString(v.agentString);
    w.writeU64(v.bestHeight);
    w.writeU64(v.peerNonce);

    return out;
  }

  bool deserializeVersion(const uint8_t *data, size_t len, VersionMessage &out)
  {
    Common::Reader r(data, len);

    out.protocolVersion = r.readU32();
    out.networkNonce = r.readU64();
    out.timestamp = r.readI64();
    out.listenPort = r.readU16();
    out.agentString = r.readLengthPrefixedString();
    out.bestHeight = r.readU64();
    out.peerNonce = r.readU64();

    return r.ok();
  }

  //  Peers

  std::vector<uint8_t> serializePeers(const std::vector<PeerAddressEntry> &peers)
  {
    std::vector<uint8_t> out;
    out.reserve(2 + peers.size() * 8);

    size_t count = peers.size();
    if (count > 0xFFFF)
      count = 0xFFFF;

    Common::Writer w(out);
    w.writeU16(static_cast<uint16_t>(count));

    for (size_t i = 0; i < count; ++i)
    {
      w.writeLengthPrefixedString(peers[i].ip);
      w.writeU16(peers[i].port);
    }

    return out;
  }

  bool deserializePeers(const uint8_t *data, size_t len,
                        std::vector<PeerAddressEntry> &out)
  {
    Common::Reader r(data, len);
    uint16_t count = r.readU16();
    out.clear();
    out.reserve(count);

    for (uint16_t i = 0; i < count && r.ok(); ++i)
    {
      PeerAddressEntry e;
      e.ip = r.readLengthPrefixedString();
      e.port = r.readU16();
      if (r.ok())
        out.push_back(std::move(e));
    }

    return r.ok();
  }

  //  GetHeaders

  std::vector<uint8_t> serializeGetHeaders(const GetHeadersMessage &m)
  {
    std::vector<uint8_t> out;

    Common::Writer w(out);
    w.writeU64(m.startHeight);
    w.writeU32(m.limit);

    return out;
  }

  bool deserializeGetHeaders(const uint8_t *data, size_t len,
                             GetHeadersMessage &out)
  {
    Common::Reader r(data, len);
    out.startHeight = r.readU64();
    out.limit = r.readU32();
    return r.ok();
  }

  //  Inv / GetData

  std::vector<uint8_t> serializeInv(const std::vector<InvEntry> &entries)
  {
    std::vector<uint8_t> out;

    Common::Writer w(out);
    w.writeU32(static_cast<uint32_t>(entries.size()));

    for (const auto &e : entries)
    {
      w.writeU8(static_cast<uint8_t>(e.type));
      w.writeBytes(e.hash.data(), 32);
    }

    return out;
  }

  bool deserializeInv(const uint8_t *data, size_t len, std::vector<InvEntry> &out)
  {
    Common::Reader r(data, len);
    uint32_t count = r.readU32();
    if (count > 10000)
      return false;

    out.clear();
    out.reserve(count);

    for (uint32_t i = 0; i < count && r.ok(); ++i)
    {
      InvEntry e;
      e.type = static_cast<InvType>(r.readU8());
      r.readBytes(e.hash.data(), 32);
      out.push_back(std::move(e));
    }

    return r.ok();
  }

  std::vector<uint8_t> serializeGetData(const GetDataMessage &m)
  {
    return serializeInv(m);
  }

  bool deserializeGetData(const uint8_t *data, size_t len, GetDataMessage &out)
  {
    return deserializeInv(data, len, out);
  }

} // namespace P2P