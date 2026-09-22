// KV/KVBinaryCommon.hpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <cstdint>
#include <cstddef>

namespace Serialization
{

  // Magic Numbers & Version

  constexpr uint32_t SIGNATURE_A = 0x01011101;
  constexpr uint32_t SIGNATURE_B = 0x01020101;
  constexpr uint8_t FORMAT_VERSION = 1;

  // Size Markers

  constexpr uint8_t SIZE_MARK_MASK = 0x03;
  constexpr uint8_t SIZE_MARK_BYTE = 0x00;
  constexpr uint8_t SIZE_MARK_WORD = 0x01;
  constexpr uint8_t SIZE_MARK_DWORD = 0x02;
  constexpr uint8_t SIZE_MARK_INT64 = 0x03;

  // Type Constants

  constexpr uint8_t TYPE_INT64 = 1;
  constexpr uint8_t TYPE_INT32 = 2;
  constexpr uint8_t TYPE_INT16 = 3;
  constexpr uint8_t TYPE_INT8 = 4;
  constexpr uint8_t TYPE_UINT64 = 5;
  constexpr uint8_t TYPE_UINT32 = 6;
  constexpr uint8_t TYPE_UINT16 = 7;
  constexpr uint8_t TYPE_UINT8 = 8;
  constexpr uint8_t TYPE_DOUBLE = 9;
  constexpr uint8_t TYPE_STRING = 10;
  constexpr uint8_t TYPE_BOOL = 11;
  constexpr uint8_t TYPE_OBJECT = 12;
  constexpr uint8_t TYPE_ARRAY = 13;
  constexpr uint8_t FLAG_ARRAY = 0x80;

  // Header Structure

#pragma pack(push, 1)
  struct Header
  {
    uint32_t signatureA;
    uint32_t signatureB;
    uint8_t version;

    bool valid() const
    {
      return signatureA == SIGNATURE_A &&
             signatureB == SIGNATURE_B &&
             version == FORMAT_VERSION;
    }
  };
#pragma pack(pop)
  static_assert(sizeof(Header) == 9, "Header size must be 9 bytes");

} // namespace Serialization