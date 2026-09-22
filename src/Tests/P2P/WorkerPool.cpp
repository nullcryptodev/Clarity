// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <gtest/gtest.h>

#include "P2P/WorkerPool.h"

using namespace P2P;
using namespace std::chrono_literals;

TEST(WorkerPool, ThreadCountNonZero)
{
  WorkerPool pool(1);
  EXPECT_EQ(pool.threadCount(), 1u);
}

TEST(WorkerPool, AutoThreadCount)
{
  WorkerPool pool(0);
  EXPECT_GE(pool.threadCount(), 1u);
}

TEST(WorkerPool, RunsJob)
{
  WorkerPool pool(1);

  std::atomic<bool> ran{false};
  pool.submit([&ran]()
              { ran = true; });

  // Wait briefly for the job to complete.
  auto deadline = std::chrono::steady_clock::now() + 2s;
  while (!ran.load() && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);

  EXPECT_TRUE(ran.load());
}

TEST(WorkerPool, RunsMultipleJobs)
{
  WorkerPool pool(2);

  std::atomic<int> count{0};
  for (int i = 0; i < 10; ++i)
    pool.submit([&count]()
                { count.fetch_add(1); });

  auto deadline = std::chrono::steady_clock::now() + 2s;
  while (count.load() < 10 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);

  EXPECT_EQ(count.load(), 10);
}

TEST(WorkerPool, ExceptionInJobDoesNotKillWorker)
{
  WorkerPool pool(1);

  std::atomic<int> ran{0};

  pool.submit([]()
              { throw std::runtime_error("boom"); });
  pool.submit([&ran]()
              { ran.fetch_add(1); });

  auto deadline = std::chrono::steady_clock::now() + 2s;
  while (ran.load() == 0 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(1ms);

  EXPECT_EQ(ran.load(), 1);
}

TEST(WorkerPool, PendingJobsCount)
{
  WorkerPool pool(1);
  // No jobs yet.
  EXPECT_EQ(pool.pendingJobs(), 0u);
}