// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Common/Json.h"
#include "Wallet/KeyStoreFormat.h"
#include "Wallet/WalletTypes.h"

using namespace Wallet;

namespace fs = std::filesystem;

//  KeyStoreFormat test suite.
//
//  Tests the JSON schema, parsing, serialization, validation, and
//  file I/O. Does not test encryption; that's EncryptedKeyStore.

namespace
{
  // Build a minimal valid KeyStoreFile for round-trip testing.
  KeyStoreFile makeValidFile()
  {
    KeyStoreFile f;
    f.version = KEYSTORE_VERSION;
    f.id = "8e4f1234-5678-4abc-9def-0123456789ab";
    f.label = "test-wallet";
    f.network = "mainnet";
    f.chain_id = GlobalConfig::CHAIN_ID;
    f.address = "clrty1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    f.pubkey.assign(32, 0xAB);

    f.crypto.cipher = CIPHER_XCHACHA20_POLY1305;
    f.crypto.nonce.assign(KEYSTORE_NONCE_LENGTH, 0x42);
    f.crypto.aad = KEYSTORE_AAD;
    f.crypto.ciphertext.assign(64, 0x11);
    f.crypto.mac.assign(16, 0x22);
    f.crypto.kdf = KDF_ARGON2ID;

    Argon2ParamsJson argon;
    argon.salt.assign(KEYSTORE_SALT_LENGTH, 0x33);
    argon.m_cost_kib = KEYSTORE_ARGON2_M_COST_KIB;
    argon.t_cost = KEYSTORE_ARGON2_T_COST;
    argon.p_cost = KEYSTORE_ARGON2_P_COST;
    f.crypto.argon2 = std::move(argon);

    f.hd.seed_fingerprint = {0xDE, 0xAD, 0xBE, 0xEF};
    f.hd.default_path = "m/44'/9000'/0'/0'/0'";

    f.created_at_ms = 1767225600000ULL;
    return f;
  }

  // Build a valid file using the PBKDF2 KDF.
  KeyStoreFile makeValidPbkdf2File()
  {
    KeyStoreFile f = makeValidFile();
    f.crypto.kdf = KDF_PBKDF2_HMAC_SHA512;
    f.crypto.argon2.reset();

    Pbkdf2ParamsJson p;
    p.salt.assign(KEYSTORE_SALT_LENGTH, 0x44);
    p.iterations = KEYSTORE_PBKDF2_ITERATIONS;
    f.crypto.pbkdf2 = std::move(p);

    return f;
  }

  // Parse a JSON string and return the KeyStoreFile, asserting success.
  KeyStoreFile parseOrDie(const std::string &json)
  {
    WalletStatus st;
    auto f = parseKeyStoreFile(json, &st);
    EXPECT_TRUE(f.has_value())
        << "parse failed: " << walletErrorMessage(st.code)
        << " detail: " << st.detail;
    return f.value_or(KeyStoreFile{});
  }

  // Parse and expect failure with a specific error code.
  void parseMustFail(const std::string &json, WalletError expected)
  {
    WalletStatus st;
    auto f = parseKeyStoreFile(json, &st);
    EXPECT_FALSE(f.has_value()) << "expected failure but parse succeeded";
    EXPECT_EQ(st.code, expected)
        << "expected " << walletErrorName(expected)
        << " got " << walletErrorName(st.code)
        << " detail: " << st.detail;
  }

  // A unique temp path for tests that touch the filesystem.
  std::string tempPath(const std::string &suffix = ".json")
  {
    static int counter = 0;
    return (fs::temp_directory_path() /
            ("clrty_test_keystore_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter++) + suffix))
        .string();
  }

  // RAII cleanup for temp files.
  struct TempCleanup
  {
    std::string path;
    TempCleanup(std::string p) : path(std::move(p)) {}
    ~TempCleanup()
    {
      std::error_code ec;
      fs::remove(path, ec);
      fs::remove(path + ".tmp", ec);
    }
  };
} // namespace

//  Serialize — structural

TEST(Wallet_KeyStoreFormat, SerializeProducesValidJson)
{
  const auto f = makeValidFile();
  const std::string json = serializeKeyStoreFile(f);

  // Must parse as valid JSON.
  EXPECT_NO_THROW({
    auto parsed = Common::Json::parse(json);
    EXPECT_TRUE(parsed.is_object());
  });
}

TEST(Wallet_KeyStoreFormat, SerializeContainsAllRequiredFields)
{
  const auto f = makeValidFile();
  const std::string json = serializeKeyStoreFile(f);
  const auto parsed = Common::Json::parse(json);

  EXPECT_TRUE(parsed.contains("version"));
  EXPECT_TRUE(parsed.contains("id"));
  EXPECT_TRUE(parsed.contains("network"));
  EXPECT_TRUE(parsed.contains("chain_id"));
  EXPECT_TRUE(parsed.contains("pubkey"));
  EXPECT_TRUE(parsed.contains("crypto"));
  EXPECT_TRUE(parsed.contains("hd"));

  EXPECT_TRUE(parsed["crypto"].contains("cipher"));
  EXPECT_TRUE(parsed["crypto"].contains("nonce"));
  EXPECT_TRUE(parsed["crypto"].contains("aad"));
  EXPECT_TRUE(parsed["crypto"].contains("ciphertext"));
  EXPECT_TRUE(parsed["crypto"].contains("mac"));
  EXPECT_TRUE(parsed["crypto"].contains("kdf"));
  EXPECT_TRUE(parsed["crypto"].contains("kdfparams"));

  EXPECT_TRUE(parsed["hd"].contains("seed_fingerprint"));
  EXPECT_TRUE(parsed["hd"].contains("default_path"));
}

TEST(Wallet_KeyStoreFormat, SerializeHexIsLowercase)
{
  const auto f = makeValidFile();
  const std::string json = serializeKeyStoreFile(f);
  const auto parsed = Common::Json::parse(json);

  // pubkey hex should be lowercase.
  const std::string pubkey_hex = parsed["pubkey"];
  for (char c : pubkey_hex)
  {
    EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
        << "non-lowercase-hex char: " << c;
  }
}

//  Round trip

TEST(Wallet_KeyStoreFormat, RoundTripArgon2)
{
  const auto original = makeValidFile();
  const std::string json = serializeKeyStoreFile(original);
  const auto parsed = parseOrDie(json);

  EXPECT_EQ(parsed.version, original.version);
  EXPECT_EQ(parsed.id, original.id);
  EXPECT_EQ(parsed.label, original.label);
  EXPECT_EQ(parsed.network, original.network);
  EXPECT_EQ(parsed.chain_id, original.chain_id);
  EXPECT_EQ(parsed.address, original.address);
  EXPECT_EQ(parsed.pubkey, original.pubkey);

  EXPECT_EQ(parsed.crypto.cipher, original.crypto.cipher);
  EXPECT_EQ(parsed.crypto.nonce, original.crypto.nonce);
  EXPECT_EQ(parsed.crypto.aad, original.crypto.aad);
  EXPECT_EQ(parsed.crypto.ciphertext, original.crypto.ciphertext);
  EXPECT_EQ(parsed.crypto.mac, original.crypto.mac);
  EXPECT_EQ(parsed.crypto.kdf, original.crypto.kdf);

  ASSERT_TRUE(parsed.crypto.argon2.has_value());
  ASSERT_TRUE(original.crypto.argon2.has_value());
  EXPECT_EQ(parsed.crypto.argon2->salt, original.crypto.argon2->salt);
  EXPECT_EQ(parsed.crypto.argon2->m_cost_kib, original.crypto.argon2->m_cost_kib);
  EXPECT_EQ(parsed.crypto.argon2->t_cost, original.crypto.argon2->t_cost);
  EXPECT_EQ(parsed.crypto.argon2->p_cost, original.crypto.argon2->p_cost);

  EXPECT_EQ(parsed.hd.seed_fingerprint, original.hd.seed_fingerprint);
  EXPECT_EQ(parsed.hd.default_path, original.hd.default_path);

  EXPECT_EQ(parsed.created_at_ms, original.created_at_ms);
}

TEST(Wallet_KeyStoreFormat, RoundTripPbkdf2)
{
  const auto original = makeValidPbkdf2File();
  const std::string json = serializeKeyStoreFile(original);
  const auto parsed = parseOrDie(json);

  EXPECT_EQ(parsed.crypto.kdf, KDF_PBKDF2_HMAC_SHA512);
  EXPECT_FALSE(parsed.crypto.argon2.has_value());
  ASSERT_TRUE(parsed.crypto.pbkdf2.has_value());
  EXPECT_EQ(parsed.crypto.pbkdf2->salt, original.crypto.pbkdf2->salt);
  EXPECT_EQ(parsed.crypto.pbkdf2->iterations,
            original.crypto.pbkdf2->iterations);
}

//  Parse — malformed JSON

TEST(Wallet_KeyStoreFormat, ParseRejectsInvalidJson)
{
  parseMustFail("{ not json", WalletError::KeyStoreCorrupt);
  parseMustFail("", WalletError::KeyStoreCorrupt);
  parseMustFail("[1,2,3]", WalletError::KeyStoreCorrupt); // root not object
  parseMustFail("null", WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsMissingVersion)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j.erase("version");
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsUnsupportedVersion)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["version"] = 99;
  parseMustFail(j.dump(), WalletError::KeyStoreUnsupportedVersion);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsUnknownCipher)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["cipher"] = "aes-256-gcm";
  parseMustFail(j.dump(), WalletError::KeyStoreUnsupportedCipher);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsUnknownKdf)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdf"] = "scrypt";
  parseMustFail(j.dump(), WalletError::KeyStoreUnsupportedKdf);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsMissingPubkey)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j.erase("pubkey");
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsUnknownNetwork)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["network"] = "moonnet";
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsMissingCrypto)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j.erase("crypto");
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsMissingKdfParams)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"].erase("kdfparams");
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  Parse — type mismatches

TEST(Wallet_KeyStoreFormat, ParseRejectsStringVersion)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["version"] = "1";
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsNumericId)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["id"] = 12345;
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsNullChainId)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["chain_id"] = nullptr;
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  Parse — hex validation

TEST(Wallet_KeyStoreFormat, ParseAcceptsUppercaseHex)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));

  // Uppercase the pubkey hex.
  std::string pk = j["pubkey"];
  for (char &c : pk)
    if (c >= 'a' && c <= 'f')
      c = char(c - 'a' + 'A');
  j["pubkey"] = pk;

  WalletStatus st;
  auto f = parseKeyStoreFile(j.dump(), &st);
  EXPECT_TRUE(f.has_value()) << walletErrorMessage(st.code);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsOddLengthHex)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["pubkey"] = "abc"; // odd length
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ParseRejectsNonHexChars)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["pubkey"] = "zzzz"; // not hex
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  Validation — cryptographic field lengths

TEST(Wallet_KeyStoreFormat, ValidationRejectsShortNonce)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["nonce"] = "00010203"; // 4 bytes, must be 24
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsLongNonce)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["nonce"] = std::string(64, 'a'); // 32 bytes, must be 24
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsShortMac)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["mac"] = "00010203"; // 4 bytes, must be 16
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsShortSalt)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdfparams"]["salt"] = "00010203"; // 4 bytes, must be 16
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsEmptyCiphertext)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["ciphertext"] = "";
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsTooLongCiphertext)
{
  // Ciphertext max is 64 bytes (the seed length); the format is a
  // hard constraint. 65 bytes should be rejected.
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["ciphertext"] = std::string(130, 'a'); // 65 bytes
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsShortSeedFingerprint)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["hd"]["seed_fingerprint"] = "0001"; // 2 bytes, must be 4
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsEmptyDefaultPath)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["hd"]["default_path"] = "";
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  Validation — AAD binding

TEST(Wallet_KeyStoreFormat, ValidationRejectsWrongAad)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["aad"] = "clrty-keystore-v2"; // not what we emit
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsEmptyAad)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["aad"] = "";
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  Validation — Argon2 parameters

TEST(Wallet_KeyStoreFormat, ValidationRejectsArgon2TooLittleMemory)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdfparams"]["m_cost_kib"] = 4; // < 8
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsArgon2MemoryLessThanEightTimesParallelism)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdfparams"]["m_cost_kib"] = 32;
  j["crypto"]["kdfparams"]["p_cost"] = 5; // requires m_cost >= 40
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsArgon2ZeroTimeCost)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdfparams"]["t_cost"] = 0;
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsArgon2ZeroParallelism)
{
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdfparams"]["p_cost"] = 0;
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsArgon2InsaneMemory)
{
  // 16 GiB is above the 8 GiB ceiling in validateKeyStoreFile.
  Common::Json j = Common::Json::parse(serializeKeyStoreFile(makeValidFile()));
  j["crypto"]["kdfparams"]["m_cost_kib"] = 16 * 1024 * 1024;
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  Validation — PBKDF2 parameters

TEST(Wallet_KeyStoreFormat, ValidationRejectsPbkdf2LowIterations)
{
  auto f = makeValidPbkdf2File();
  f.crypto.pbkdf2->iterations = 1000; // below 100,000 floor

  std::string json = serializeKeyStoreFile(f);
  WalletStatus st;
  auto parsed = parseKeyStoreFile(json, &st);
  EXPECT_FALSE(parsed.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidationRejectsPbkdf2MissingSalt)
{
  Common::Json j = Common::Json::parse(
      serializeKeyStoreFile(makeValidPbkdf2File()));
  j["crypto"]["kdfparams"].erase("salt");
  parseMustFail(j.dump(), WalletError::KeyStoreCorrupt);
}

//  File I/O

TEST(Wallet_KeyStoreFormat, WriteAndReadRoundTrip)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  const auto original = makeValidFile();
  WalletStatus write_st;
  ASSERT_TRUE(writeKeyStoreFile(path, original, &write_st))
      << walletErrorMessage(write_st.code);

  ASSERT_TRUE(fs::exists(path));

  WalletStatus read_st;
  auto read_back = readKeyStoreFile(path, &read_st);
  ASSERT_TRUE(read_back.has_value()) << walletErrorMessage(read_st.code);

  EXPECT_EQ(read_back->id, original.id);
  EXPECT_EQ(read_back->pubkey, original.pubkey);
  EXPECT_EQ(read_back->crypto.ciphertext, original.crypto.ciphertext);
}

TEST(Wallet_KeyStoreFormat, WriteLeavesNoTempFile)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  WalletStatus st;
  ASSERT_TRUE(writeKeyStoreFile(path, makeValidFile(), &st));

  // The .tmp file must not linger.
  EXPECT_FALSE(fs::exists(path + ".tmp"));
}

TEST(Wallet_KeyStoreFormat, WriteOverwritesExistingFile)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto f1 = makeValidFile();
  f1.label = "first";

  auto f2 = makeValidFile();
  f2.label = "second";

  WalletStatus st;
  ASSERT_TRUE(writeKeyStoreFile(path, f1, &st));
  ASSERT_TRUE(writeKeyStoreFile(path, f2, &st));

  auto back = readKeyStoreFile(path, &st);
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(back->label, "second");
}

TEST(Wallet_KeyStoreFormat, ReadMissingFile)
{
  WalletStatus st;
  auto f = readKeyStoreFile("/nonexistent/path/to/keystore.json", &st);
  EXPECT_FALSE(f.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreNotFound);
}

TEST(Wallet_KeyStoreFormat, ReadInvalidFileContent)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  {
    std::ofstream out(path);
    out << "{ not valid json";
  }

  WalletStatus st;
  auto f = readKeyStoreFile(path, &st);
  EXPECT_FALSE(f.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ReadEmptyFile)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  {
    std::ofstream out(path); // creates empty file
  }

  WalletStatus st;
  auto f = readKeyStoreFile(path, &st);
  EXPECT_FALSE(f.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, WriteToUnwritablePathFailsCleanly)
{
  // A path in a directory that doesn't exist.
  const std::string path = "/nonexistent/dir/keystore.json";

  WalletStatus st;
  EXPECT_FALSE(writeKeyStoreFile(path, makeValidFile(), &st));
  EXPECT_EQ(st.code, WalletError::Internal);

  // And no stray temp file.
  EXPECT_FALSE(fs::exists(path + ".tmp"));
}

//  validateKeyStoreFile — direct calls

TEST(Wallet_KeyStoreFormat, ValidateAcceptsValidFile)
{
  EXPECT_EQ(validateKeyStoreFile(makeValidFile()), WalletError::Ok);
  EXPECT_EQ(validateKeyStoreFile(makeValidPbkdf2File()), WalletError::Ok);
}

TEST(Wallet_KeyStoreFormat, ValidateRejectsWrongVersion)
{
  auto f = makeValidFile();
  f.version = 99;
  EXPECT_EQ(validateKeyStoreFile(f), WalletError::KeyStoreUnsupportedVersion);
}

TEST(Wallet_KeyStoreFormat, ValidateRejectsZeroChainId)
{
  auto f = makeValidFile();
  f.chain_id = 0;
  EXPECT_EQ(validateKeyStoreFile(f), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidateRejectsWrongPubkeyLength)
{
  auto f = makeValidFile();
  f.pubkey.resize(16); // must be 32
  EXPECT_EQ(validateKeyStoreFile(f), WalletError::KeyStoreCorrupt);
}

TEST(Wallet_KeyStoreFormat, ValidateRejectsWrongNetworkString)
{
  auto f = makeValidFile();
  f.network = "invalid";
  EXPECT_EQ(validateKeyStoreFile(f), WalletError::KeyStoreCorrupt);
}