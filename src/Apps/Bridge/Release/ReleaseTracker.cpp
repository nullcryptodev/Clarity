// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ReleaseTracker.h"

#include <iostream>
#include <utility>

namespace Bridge
{
  ReleaseTracker::~ReleaseTracker()
  {
    shutdown();
  }

  bool ReleaseTracker::launch(ChainRuntime &rt,
                              const ReleaseRequest &request,
                              uint64_t amount_source_atomic,
                              const std::vector<uint8_t> &ack_block)
  {
    if (stop_.load(std::memory_order_acquire))
    {
      //  Shutting down. Don't start new threads.
      return false;
    }

    auto entry = std::make_shared<InFlight>();
    entry->withdrawal_id = request.withdrawal_id;

    {
      std::lock_guard<std::mutex> lock(mutex_);

      if (in_flight_.find(request.withdrawal_id) != in_flight_.end())
      {
        //  Already in flight.
        return false;
      }

      //  Copy the request and ack_block into the worker. The
      //  caller is free to mutate or destroy its copies as soon as
      //  launch() returns.
      ReleaseRequest request_copy = request;
      std::vector<uint8_t> ack_copy = ack_block;

      in_flight_.emplace(request.withdrawal_id, entry);

      try
      {
        entry->thread = std::thread(
            &ReleaseTracker::runRelease,
            this,
            entry,
            &rt,
            std::move(request_copy),
            amount_source_atomic,
            std::move(ack_copy));
      }
      catch (...)
      {
        //  Thread creation failed. Remove the entry and rethrow:
        //  a failure here is a resource-exhaustion condition, not a
        //  recoverable per-withdrawal error.
        in_flight_.erase(request.withdrawal_id);
        throw;
      }
    }

    return true;
  }

  std::vector<ReleaseTracker::CompletedRelease> ReleaseTracker::drain_completed()
  {
    std::vector<CompletedRelease> out;

    std::vector<std::shared_ptr<InFlight>> finished;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto it = in_flight_.begin(); it != in_flight_.end();)
      {
        if (it->second->done.load(std::memory_order_acquire))
        {
          finished.push_back(it->second);
          it = in_flight_.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }

    //  Join the finished threads outside the lock. Their `done`
    //  flag was already set, so they're past the point of touching
    //  their entry's fields; joining is cheap and safe.
    for (auto &entry : finished)
    {
      if (entry->thread.joinable())
        entry->thread.join();

      CompletedRelease cr;
      cr.withdrawal_id = entry->withdrawal_id;
      cr.succeeded = entry->succeeded;
      if (entry->succeeded)
        cr.tx_hash = entry->tx_hash;
      else
        cr.reason = entry->reason;

      out.push_back(std::move(cr));
    }

    return out;
  }

  void ReleaseTracker::shutdown()
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (shutdown_called_)
        return;
      shutdown_called_ = true;
    }

    stop_.store(true, std::memory_order_release);

    //  Move the in-flight entries out of the map under the lock,
    //  then join them all outside the lock.
    std::vector<std::shared_ptr<InFlight>> to_join;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      to_join.reserve(in_flight_.size());
      for (auto &[wid, entry] : in_flight_)
      {
        (void)wid;
        to_join.push_back(std::move(entry));
      }
      in_flight_.clear();
    }

    for (auto &entry : to_join)
    {
      if (entry->thread.joinable())
        entry->thread.join();
    }
  }

  bool ReleaseTracker::in_flight() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return !in_flight_.empty();
  }

  void ReleaseTracker::runRelease(std::shared_ptr<InFlight> entry,
                                  ChainRuntime *rt,
                                  ReleaseRequest request,
                                  uint64_t amount_source_atomic,
                                  std::vector<uint8_t> ack_block)
  {
    //  The worker runs entirely inside this function. It must never
    //  throw out — an exception escaping a thread would call
    //  std::terminate. Everything is wrapped in a try/catch and
    //  converted to a Failed result.

    try
    {
      if (!rt || !rt->adapter)
      {
        entry->reason = "chain runtime vanished before release started";
        entry->succeeded = false;
        entry->done.store(true, std::memory_order_release);
        return;
      }

      //  The adapter's submit_release call is expected to block
      //  until the release is confirmed on CCX (or returns an
      //  error). It internally reaches the wallet RPC; the
      //  RpcClient argument is required by the interface but is
      //  not used by the current implementation.
      Wallet::RpcClient dummy({/*host=*/"", /*port=*/0});
      const ReleaseSubmission result = rt->adapter->submit_release(
          dummy, request, amount_source_atomic, ack_block);

      if (result.ok)
      {
        entry->tx_hash = result.source_tx_hash;
        entry->succeeded = true;
      }
      else
      {
        entry->reason =
            result.reason.empty() ? "submit_release failed (no reason)"
                                  : result.reason;
        entry->succeeded = false;
      }
    }
    catch (const std::exception &e)
    {
      entry->reason = std::string("exception in release worker: ") + e.what();
      entry->succeeded = false;
    }
    catch (...)
    {
      entry->reason = "unknown exception in release worker";
      entry->succeeded = false;
    }

    entry->done.store(true, std::memory_order_release);
  }

} // namespace Bridge