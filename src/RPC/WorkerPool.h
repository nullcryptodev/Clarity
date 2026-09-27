// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace Rpc
{
  //  WorkerPool
  //
  //  Fixed-size thread pool with a bounded job queue.
  //
  //  Difference from P2P::WorkerPool:
  //    - Bounded queue. submit() returns false when full instead of
  //      silently growing the queue. Callers that care about backpressure
  //      can react (HttpServer sends 503).
  //    - submit() returns bool. Cheap to ignore for callers that don't
  //      care.
  //    - No templated work/callback overload. That overload spawned a
  //      detached thread per call, which is fine at P2P's message rate
  //      but wrong for RPC. RPC's workers run their job to completion
  //      on the pool thread; a "callback" is just the tail of the job.
  //
  //  This pool is duplicated from P2P rather than shared because P2P's
  //  semantics (unbounded queue, detached-thread callback) are wrong for
  //  RPC, and changing P2P's pool would require auditing every P2P use
  //  site. If the two ever converge on the same semantics, they should be
  //  unified into Common/.
  //
  //  Threading: submit() is safe from any thread. The worker loop is
  //  internal.

  class WorkerPool
  {
  public:
    // Construct with `thread_count` workers. 0 means "auto", which uses
    // max(1, hardware_concurrency() - 1), capped at 8. `max_queue_size`
    // is the maximum number of pending jobs; submit() returns false when
    // the queue is full.
    explicit WorkerPool(size_t thread_count = 0,
                        size_t max_queue_size = 1024);

    ~WorkerPool();

    WorkerPool(const WorkerPool &) = delete;
    WorkerPool &operator=(const WorkerPool &) = delete;

    // Enqueue a job. Returns false if the pool is stopping or the queue
    // is full. In either case the job is dropped — the caller decides
    // whether that's a hard failure (RPC: send 503) or ignorable.
    //
    // `job` must not throw. If it does, the exception is caught and
    // swallowed; the worker continues.
    bool submit(std::function<void()> job);

    size_t threadCount() const noexcept { return threads_.size(); }
    size_t pendingJobs() const;

    // Stop accepting jobs and drain. Blocks until every worker has
    // exited. Called from the destructor; safe to call explicitly if
    // the owner needs to control the shutdown order.
    void stop();

  private:
    void workerLoop();

    std::vector<std::thread> threads_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> queue_;
    size_t max_queue_size_;
    bool stopping_ = false;
  };

} // namespace Rpc