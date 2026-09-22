#pragma once

#include <cstdint>

namespace P2P
{
  // Generate a random 64-bit nonce for self-connection detection.
  // Uses the OS CSPRNG via Crypto::randomBytes.
  uint64_t generateNetworkNonce();
}