#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "Peer.h"

namespace P2P
{
  // Thread-confined registry of active peers. Only mutated on the event loop.
  class PeerTable
  {
  public:
    // Add a peer under its id. Overwrites if already present (shouldn't happen).
    void add(PeerPtr peer);

    // Remove a peer by id. Returns the removed peer or nullptr.
    PeerPtr remove(PeerId id);

    // Look up a peer.
    Peer *find(PeerId id) const;

    // All peers.
    std::vector<PeerPtr> all() const;

    // Counts by state.
    size_t size() const noexcept { return peers_.size(); }
    size_t countByState(PeerState s) const;
    size_t countOutbound() const;
    size_t countInbound() const;

    // Check if an IP is already connected (duplicate detection).
    bool hasPeerWithIp(const std::string &ip) const;

    // Iteration
    auto begin() { return peers_.begin(); }
    auto end() { return peers_.end(); }
    auto begin() const { return peers_.begin(); }
    auto end() const { return peers_.end(); }

  private:
    std::unordered_map<PeerId, PeerPtr> peers_;
  };

} // namespace P2P