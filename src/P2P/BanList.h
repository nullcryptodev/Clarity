// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "MessageTypes.h"

namespace P2P
{
  class BanList
  {
  public:
    BanList(std::string persistPath,
            uint32_t threshold,
            uint32_t durationSec);

    bool isBanned(const std::string &ip) const;
    bool recordMisbehavior(const std::string &ip, uint32_t score);
    void ban(const std::string &ip, BanReason reason);
    void unban(const std::string &ip);
    size_t size() const;

    void load();
    void save() const;
    void purgeExpired();

  private:
    struct Entry
    {
      uint32_t score = 0;
      int64_t bannedUntil = 0;
      int64_t bannedAt = 0;
      uint8_t reason = 0;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    std::string persistPath_;
    uint32_t threshold_;
    uint32_t durationSec_;
  };

} // namespace P2P