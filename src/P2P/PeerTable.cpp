#include "PeerTable.h"

namespace P2P
{

  void PeerTable::add(PeerPtr peer)
  {
    if (!peer)
      return;
    peers_[peer->id()] = std::move(peer);
  }

  PeerPtr PeerTable::remove(PeerId id)
  {
    auto it = peers_.find(id);
    if (it == peers_.end())
      return nullptr;
    auto p = std::move(it->second);
    peers_.erase(it);
    return p;
  }

  Peer *PeerTable::find(PeerId id) const
  {
    auto it = peers_.find(id);
    return it == peers_.end() ? nullptr : it->second.get();
  }

  std::vector<PeerPtr> PeerTable::all() const
  {
    std::vector<PeerPtr> out;
    out.reserve(peers_.size());
    for (const auto &[id, p] : peers_)
      out.push_back(p);
    return out;
  }

  size_t PeerTable::countByState(PeerState s) const
  {
    size_t n = 0;
    for (const auto &[id, p] : peers_)
    {
      if (p->state() == s)
        ++n;
    }
    return n;
  }

  size_t PeerTable::countOutbound() const
  {
    size_t n = 0;
    for (const auto &[id, p] : peers_)
    {
      if (p->direction() == PeerDirection::Outbound)
        ++n;
    }
    return n;
  }

  size_t PeerTable::countInbound() const
  {
    size_t n = 0;
    for (const auto &[id, p] : peers_)
    {
      if (p->direction() == PeerDirection::Inbound)
        ++n;
    }
    return n;
  }

  bool PeerTable::hasPeerWithIp(const std::string &ip) const
  {
    for (const auto &[id, p] : peers_)
    {
      if (p->remoteIp() == ip)
        return true;
    }
    return false;
  }

} // namespace P2P