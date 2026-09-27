// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WorkerPool.h"

#include <algorithm>

namespace Rpc
{

  WorkerPool::WorkerPool(size_t thread_count, size_t max_queue_size)
      : max_queue_size_(max_queue_size)
  {
    if (thread_count == 0)
    {
      unsigned hw = std::thread::hardware_concurrency();
      thread_count = hw > 1 ? std::min<size_t>(hw - 1, 8) : 1;
    }

    threads_.reserve(thread_count);
    for (size_t i = 0; i < thread_count; ++i)
    {
      threads_.emplace_back([this]
                            { workerLoop(); });
    }
  }

  WorkerPool::~WorkerPool()
  {
    stop();
  }

  void WorkerPool::stop()
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_)
        return;
      stopping_ = true;
    }
    cv_.notify_all();

    for (auto &t : threads_)
    {
      if (t.joinable())
        t.join();
    }
    threads_.clear();
  }

  bool WorkerPool::submit(std::function<void()> job)
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_)
        return false;
      if (queue_.size() >= max_queue_size_)
        return false;
      queue_.push(std::move(job));
    }
    cv_.notify_one();
    return true;
  }

  size_t WorkerPool::pendingJobs() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

  void WorkerPool::workerLoop()
  {
    for (;;)
    {
      std::function<void()> job;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this]
                 { return stopping_ || !queue_.empty(); });

        if (stopping_ && queue_.empty())
          return;

        job = std::move(queue_.front());
        queue_.pop();
      }

      try
      {
        job();
      }
      catch (...)
      {
        // A worker must never die from a job's exception. The job
        // itself is responsible for catching anything it can handle;
        // anything that reaches here is logged-and-dropped by design.
      }
    }
  }

} // namespace Rpc