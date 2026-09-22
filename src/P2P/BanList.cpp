// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BanList.h"

#include <chrono>
#include <fstream>
#include <sstream>

namespace P2P
{
  namespace
  {
    int64_t nowUnix() noexcept
    {
      using namespace std::chrono;
      return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    }
  } // anonymous namespace

  BanList::BanList(std::string persistPath, uint32_t threshold, uint32_t durationSec)
      : persistPath_(std::move(persistPath)), threshold_(threshold), durationSec_(durationSec)
  {
    load();
  }

  bool BanList::isBanned(const std::string &ip) const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(ip);
    if (it == entries_.end())
      return false;
    return it->second.bannedUntil > nowUnix();
  }

  bool BanList::recordMisbehavior(const std::string &ip, uint32_t score)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto &e = entries_[ip];
    e.score += score;

    if (e.score >= threshold_ && e.bannedUntil <= nowUnix())
    {
      e.bannedUntil = nowUnix() + durationSec_;
      e.bannedAt = nowUnix();
      save();
      return true;
    }
    return false;
  }

  void BanList::ban(const std::string &ip, BanReason reason)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto &e = entries_[ip];
    e.bannedUntil = nowUnix() + durationSec_;
    e.bannedAt = nowUnix();
    e.reason = static_cast<uint8_t>(reason);
    e.score = threshold_;
    save();
  }

  void BanList::unban(const std::string &ip)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(ip);
    save();
  }

  size_t BanList::size() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

  void BanList::load()
  {
    std::ifstream in(persistPath_);
    if (!in.is_open())
      return;

    std::string line;
    while (std::getline(in, line))
    {
      std::istringstream ss(line);
      std::string ip;
      Entry e;
      ss >> ip >> e.score >> e.bannedUntil >> e.reason;
      if (!ip.empty())
      {
        entries_[ip] = e;
      }
    }
  }

  void BanList::save() const
  {
    std::ofstream out(persistPath_, std::ios::trunc);
    if (!out.is_open())
      return;

    for (const auto &[ip, e] : entries_)
    {
      out << ip << '\t' << e.score << '\t' << e.bannedUntil << '\t'
          << unsigned(e.reason) << '\n';
    }
  }

  void BanList::purgeExpired()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t now = nowUnix();
    for (auto it = entries_.begin(); it != entries_.end();)
    {
      if (it->second.bannedUntil <= now && it->second.score == 0)
      {
        it = entries_.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

} // namespace P2P