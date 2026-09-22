// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <vector>

namespace P2P
{
  class WorkerPool
  {
  public:
    explicit WorkerPool(size_t threadCount);
    ~WorkerPool();

    WorkerPool(const WorkerPool &) = delete;
    WorkerPool &operator=(const WorkerPool &) = delete;

    void submit(std::function<void()> job);

    template <typename Work, typename Callback>
    void submit(Work &&work, Callback &&cb)
    {
      using Result = std::invoke_result_t<Work>;
      auto task = std::make_shared<std::packaged_task<Result()>>(
          std::forward<Work>(work));

      auto future = task->get_future();

      submit([task]()
             { (*task)(); });

      std::thread([fut = std::move(future),
                   callback = std::forward<Callback>(cb)]() mutable
                  {
        try {
          if constexpr (std::is_void_v<Result>) {
            fut.get();
            callback();
          } else {
            callback(fut.get());
          }
        } catch (...) {
          // Swallow — the caller cannot handle exceptions here.
        } })
          .detach();
    }

    size_t threadCount() const noexcept { return threads_.size(); }
    size_t pendingJobs() const;

  private:
    void workerLoop();

    std::vector<std::thread> threads_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> queue_;
    bool stopping_ = false;
  };

} // namespace P2P