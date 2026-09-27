#pragma once

#include <gtest/gtest.h>

#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/WalletError.h"

namespace fs = std::filesystem;

namespace Tests
{
  constexpr char kPassword[] = "correct horse battery staple";

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

  std::string tempPath()
  {
    static int counter = 0;
    return (fs::temp_directory_path() /
            ("clrty_signer_test_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter++) + ".json"))
        .string();
  }

  // Shared fixture: creates a keystore on a temp path and provides
  // helpers to construct signers from it.
  class Wallet_LocalSignerFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      path_ = tempPath();
      std::string mnemonic;
      Wallet::WalletStatus st;
      auto ks = Wallet::EncryptedKeyStore::create(
          path_, kPassword, Wallet::Network::Mainnet, 256, mnemonic,
          Wallet::KDF_PBKDF2_HMAC_SHA512, &st);
      ASSERT_TRUE(ks.has_value())
          << "keystore create failed: " << walletErrorMessage(st.code);
      ks_ = std::move(*ks);
      ASSERT_NE(ks_, nullptr);
      ASSERT_TRUE(ks_->isUnlocked());
    }

    void TearDown() override
    {
      ks_.reset();
      std::error_code ec;
      fs::remove(path_, ec);
      fs::remove(path_ + ".tmp", ec);
    }

    // Return a reference to the underlying keystore. This is the
    // shape LocalSigner expects.
    Wallet::KeyStore &ks() { return *ks_; }

    std::string path_;
    std::unique_ptr<Wallet::EncryptedKeyStore> ks_;
  };
}