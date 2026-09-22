#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace Common
{
  // Base58 - uses cryptonotes special base58.
  // We should add the proper base58 too or replace this
  std::string encodeBase58(std::string_view data);
  bool decodeBase58(std::string_view enc, std::string &data);

  // Base64
  std::string encodeBase64(std::string_view data);
  std::string decodeBase64(std::string_view data);
}