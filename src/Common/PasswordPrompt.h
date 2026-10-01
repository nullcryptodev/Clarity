// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <optional>
#include <string>

namespace Apps
{
  //  readLineNoEcho
  //
  //  Read one line from stdin with terminal echo disabled if stdin
  //  is a tty. If stdin is not a tty (piped input, redirect), reads
  //  a line normally. The prompt is written to stderr so that stdout
  //  stays clean for piping.
  //
  //  Trailing newline is stripped from the return value. Returns
  //  std::nullopt only on I/O failure; an empty line is a valid
  //  (empty) password.
  std::optional<std::string> readLineNoEcho(const char *prompt);

  //  promptForPassword
  //
  //  Convenience wrapper: reads a password once with the given
  //  prompt. Does not do confirmation; callers that want a
  //  confirm-and-compare loop (like keystore creation) implement it
  //  themselves using readLineNoEcho twice.
  std::optional<std::string> promptForPassword(const char *prompt);

  //  readPasswordFile
  //
  //  Read a password from a file, stripping trailing whitespace
  //  (including the newline that text editors add). Returns
  //  std::nullopt if the file cannot be opened or read.
  //
  //  The special path "-" reads from stdin instead of a file. This
  //  lets scripts pipe a password in:
  //
  //      echo "hunter2" | transaction_signer ... --password-file -
  //
  //  Callers that use "-" should be aware that stdin has already
  //  been consumed once the function returns, so no further
  //  interactive reads are possible.
  std::optional<std::string> readPasswordFile(const std::string &path);

} // namespace Apps