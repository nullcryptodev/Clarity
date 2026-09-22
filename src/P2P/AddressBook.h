// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace P2P
{
  struct PeerAddress
  {
    std::string ip;
    uint16_t port = 0;
    int64_t lastSeen = 0;
    uint32_t attempts = 0;
    bool isSeed = false;
  };

  class AddressBook
  {
  public:
    explicit AddressBook(std::string persistPath);

    void add(const std::string &ip, uint16_t port, bool isSeed = false);
    std::vector<PeerAddress> pickRandom(size_t n,
                                        const std::vector<std::string> &excludeIps = {}) const;

    void markConnected(const std::string &ip, uint16_t port);
    void markFailed(const std::string &ip, uint16_t port);

    size_t size() const;

    void load();
    void save() const;
    void purgeStale(int64_t maxAgeSec);

  private:
    mutable std::mutex mutex_;
    std::vector<PeerAddress> entries_;
    std::string persistPath_;
  };

} // namespace P2P