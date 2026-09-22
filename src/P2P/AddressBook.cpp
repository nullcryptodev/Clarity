// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AddressBook.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <random>
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

    std::mt19937 &rng()
    {
      static thread_local std::mt19937 gen(std::random_device{}());
      return gen;
    }
  } // anonymous namespace

  AddressBook::AddressBook(std::string persistPath)
      : persistPath_(std::move(persistPath))
  {
    load();
  }

  void AddressBook::add(const std::string &ip, uint16_t port, bool isSeed)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &e : entries_)
    {
      if (e.ip == ip && e.port == port)
      {
        e.lastSeen = nowUnix();
        if (isSeed)
          e.isSeed = true;
        return;
      }
    }

    PeerAddress e;
    e.ip = ip;
    e.port = port;
    e.lastSeen = nowUnix();
    e.isSeed = isSeed;
    entries_.push_back(std::move(e));
  }

  std::vector<PeerAddress> AddressBook::pickRandom(
      size_t n,
      const std::vector<std::string> &excludeIps) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<const PeerAddress *> candidates;
    candidates.reserve(entries_.size());

    for (const auto &e : entries_)
    {
      if (std::find(excludeIps.begin(), excludeIps.end(), e.ip) != excludeIps.end())
        continue;
      candidates.push_back(&e);
    }

    std::shuffle(candidates.begin(), candidates.end(), rng());

    std::vector<PeerAddress> out;
    out.reserve(std::min(n, candidates.size()));
    for (size_t i = 0; i < n && i < candidates.size(); ++i)
    {
      out.push_back(*candidates[i]);
    }
    return out;
  }

  void AddressBook::markConnected(const std::string &ip, uint16_t port)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &e : entries_)
    {
      if (e.ip == ip && e.port == port)
      {
        e.lastSeen = nowUnix();
        e.attempts = 0;
        return;
      }
    }
  }

  void AddressBook::markFailed(const std::string &ip, uint16_t port)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &e : entries_)
    {
      if (e.ip == ip && e.port == port)
      {
        e.attempts++;
        return;
      }
    }
  }

  size_t AddressBook::size() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

  void AddressBook::load()
  {
    std::ifstream in(persistPath_);
    if (!in.is_open())
      return;

    std::string line;
    while (std::getline(in, line))
    {
      std::istringstream ss(line);
      PeerAddress e;
      int seedInt = 0;
      ss >> e.ip >> e.port >> e.lastSeen >> e.attempts >> seedInt;
      e.isSeed = (seedInt != 0);
      if (!e.ip.empty() && e.port != 0)
      {
        entries_.push_back(std::move(e));
      }
    }
  }

  void AddressBook::save() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream out(persistPath_, std::ios::trunc);
    if (!out.is_open())
      return;

    for (const auto &e : entries_)
    {
      out << e.ip << '\t' << e.port << '\t' << e.lastSeen << '\t'
          << e.attempts << '\t' << (e.isSeed ? 1 : 0) << '\n';
    }
  }

  void AddressBook::purgeStale(int64_t maxAgeSec)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t cutoff = nowUnix() - maxAgeSec;
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [cutoff](const PeerAddress &e)
                       {
                         return !e.isSeed && e.lastSeen < cutoff && e.attempts > 3;
                       }),
        entries_.end());
  }

} // namespace P2P