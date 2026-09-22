// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WorkerPool.h"

#include <algorithm>

namespace P2P
{

  WorkerPool::WorkerPool(size_t threadCount)
  {
    if (threadCount == 0)
    {
      unsigned hw = std::thread::hardware_concurrency();
      threadCount = hw > 1 ? hw - 1 : 1;
    }

    threads_.reserve(threadCount);
    for (size_t i = 0; i < threadCount; ++i)
    {
      threads_.emplace_back([this]
                            { workerLoop(); });
    }
  }

  WorkerPool::~WorkerPool()
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopping_ = true;
    }
    cv_.notify_all();
    for (auto &t : threads_)
    {
      if (t.joinable())
        t.join();
    }
  }

  void WorkerPool::submit(std::function<void()> job)
  {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (stopping_)
        return;
      queue_.push(std::move(job));
    }
    cv_.notify_one();
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
        // Workers must never die from an exception.
      }
    }
  }

} // namespace P2P