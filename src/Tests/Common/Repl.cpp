// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <string>

#include "Common/Repl.h"

//  What can and cannot be tested here
// ====================================
//
//  Repl::readLine() calls linenoise(), which:
//
//    - reads from the process's controlling terminal (via /dev/tty,
//      not stdin, in most builds);
//    - installs a raw-mode terminal handler;
//    - falls back to plain line-read on non-tty stdin for some
//      versions, and to nothing useful on others.
//
//  None of that is reliably testable from a gtest binary. Swapping
//  stdin's streambuf does not help: linenoise ignores std::cin and
//  talks to the terminal directly. Running the test under a pty
//  would work but adds a heavy dependency to the test suite for
//  very little signal.
//
//  So the tests below cover the parts of Repl that DON'T go through
//  linenoise:
//
//    - construction and destruction are safe
//    - the object is non-copyable (compile-time contract)
//    - addHistory() with an empty line is a no-op
//    - addHistory() with a non-empty line does not crash
//
//  readLine()'s actual behavior — the prompt string, the returned
//  line, EOF handling — is covered by manual use and by the CLI
//  integration tests. A bug in the linenoise glue would show up
//  there, and would be nearly impossible to reproduce in a unit
//  test anyway.

// ============================================================================
//  Lifecycle
// ============================================================================

TEST(Repl, ConstructAndDestructIsSafe)
{
  EXPECT_NO_THROW({
    Common::Repl repl;
    (void)repl;
  });
}

TEST(Repl, MultipleInstancesInSequenceAreSafe)
{
  //  Repl does not install any process-global state on construction;
  //  two sequential instances must not interfere. Constructing two
  //  at once is also fine — nothing is global — but sequential
  //  construction is the case that matters in practice.
  EXPECT_NO_THROW({
    Common::Repl a;
    Common::Repl b;
    (void)a;
    (void)b;
  });
}

// ============================================================================
//  addHistory
// ============================================================================

TEST(Repl, AddHistoryEmptyIsNoOp)
{
  //  The contract is: empty lines are not added. We can't read the
  //  history back through the public API, but calling with an empty
  //  line must at minimum not crash and must not throw.
  Common::Repl repl;
  EXPECT_NO_THROW(repl.addHistory(""));
}

TEST(Repl, AddHistoryNonEmptyDoesNotThrow)
{
  Common::Repl repl;
  EXPECT_NO_THROW(repl.addHistory("hello"));
}

TEST(Repl, AddHistoryManyLinesDoesNotThrow)
{
  //  Exercise the history buffer a bit so any obvious bookkeeping
  //  bug (off-by-one, null deref on the Nth entry) shows up.
  Common::Repl repl;
  for (int i = 0; i < 100; ++i)
    EXPECT_NO_THROW(repl.addHistory("line " + std::to_string(i)));
}

TEST(Repl, AddHistoryWithEmbeddedNewlineDoesNotThrow)
{
  //  Callers are expected to pass whole lines without a trailing
  //  newline, but the function must not crash if one slips through.
  Common::Repl repl;
  EXPECT_NO_THROW(repl.addHistory("line with\nembedded newline"));
}

TEST(Repl, AddHistoryWithBinaryBytesDoesNotThrow)
{
  //  A line containing NUL and high bytes must not crash linenoise's
  //  history insertion. It will truncate at the NUL internally, but
  //  that's linenoise's problem — we're asserting only that we don't
  //  segfault.
  std::string s;
  s.push_back('\x00');
  s.push_back('\xFF');
  s.push_back('a');
  Common::Repl repl;
  EXPECT_NO_THROW(repl.addHistory(s));
}

// ============================================================================
//  Compile-time contract: non-copyable
// ============================================================================

TEST(Repl, IsNotCopyConstructible)
{
  EXPECT_FALSE(std::is_copy_constructible_v<Common::Repl>);
}

TEST(Repl, IsNotCopyAssignable)
{
  EXPECT_FALSE(std::is_copy_assignable_v<Common::Repl>);
}
