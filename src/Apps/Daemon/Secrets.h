// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

#include "Crypto/Types.h"

namespace Daemon
{
  // Parse a 64-hex-character string into a 32-byte Ed25519 secret key.
  //
  // Shared by --consensus-key (argv form) and the file loader below so
  // both go through exactly the same validation. On failure, throws
  // std::runtime_error with a message that names the offending
  // character and its index, so an operator hand-editing a key file
  // can fix a typo without guessing.
  Crypto::SecretKey parseSecretKey(const std::string &hex);

  // Load the validator consensus secret key from a file.
  //
  // The file must contain exactly 64 hex characters, optionally
  // followed by a single trailing newline. Anything else is rejected.
  //
  // Hard requirements, all enforced before the file is read:
  //
  //   - The path exists.
  //   - It is a regular file (not a directory, FIFO, device, etc.).
  //   - It is not a symlink. A symlink could be repointed by an
  //     attacker with write access to the parent directory after the
  //     permission check, and the daemon would then read a different
  //     file than the one it validated. Rejecting symlinks closes that
  //     TOCTOU window.
  //   - It is owned by either the daemon's effective uid or root.
  //   - It is not readable or writable by group or other
  //     (mode 0600 or stricter).
  //
  // The contents are parsed by parseSecretKey and the raw buffer is
  // zeroed with Crypto::SecureZero before returning, so a core dump or
  // swap file after this call does not contain the key.
  //
  // On failure, throws std::runtime_error with a message that names
  // the path and the specific violation (bad mode, wrong owner,
  // symlink, wrong length, non-hex byte, etc.).
  Crypto::SecretKey loadConsensusKeyFile(const std::string &path);
} // namespace Daemon