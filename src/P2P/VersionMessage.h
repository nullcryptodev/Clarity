// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "GlobalConfig.h"

namespace P2P
{
  struct VersionMessage
  {
    Version protocolVersion = 0;
    uint64_t networkNonce = 0;
    int64_t timestamp = 0;
    uint16_t listenPort = 0;
    std::string agentString;
    uint64_t bestHeight = 0;
    uint64_t peerNonce = 0;
  };

  std::vector<uint8_t> serializeVersion(const VersionMessage &v);
  bool deserializeVersion(const uint8_t *data, size_t len, VersionMessage &out);

  struct PeerAddressEntry
  {
    std::string ip;
    uint16_t port = 0;
  };

  std::vector<uint8_t> serializePeers(const std::vector<PeerAddressEntry> &peers);
  bool deserializePeers(const uint8_t *data, size_t len,
                        std::vector<PeerAddressEntry> &out);

  struct GetHeadersMessage
  {
    uint64_t startHeight = 0;
    uint32_t limit = 2000;
  };

  std::vector<uint8_t> serializeGetHeaders(const GetHeadersMessage &m);
  bool deserializeGetHeaders(const uint8_t *data, size_t len,
                             GetHeadersMessage &out);

  enum class InvType : uint8_t
  {
    Tx = 0,
    Block = 1,
  };

  struct InvEntry
  {
    InvType type;
    std::array<uint8_t, 32> hash;
  };

  std::vector<uint8_t> serializeInv(const std::vector<InvEntry> &entries);
  bool deserializeInv(const uint8_t *data, size_t len,
                      std::vector<InvEntry> &out);

  using GetDataMessage = std::vector<InvEntry>;
  std::vector<uint8_t> serializeGetData(const GetDataMessage &m);
  bool deserializeGetData(const uint8_t *data, size_t len,
                          GetDataMessage &out);

} // namespace P2P