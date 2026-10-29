// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/BitcoinBip32.h"

namespace Bridge
{
  //  =========================================================================
  //  BitcoinCustody
  //
  //  Per-ChainRuntime state for Bitcoin deposit-address derivation.
  //
  //  Owns the BIP84 account xpub, the network, the derived-script
  //  cache, and the gap-window cursor. BitcoinAdapter holds a
  //  non-owning pointer to it.
  //
  //  Two modes:
  //
  //    Generated (default):
  //      On first launch, generate a BIP39 mnemonic, derive the
  //      BIP84 account xpub, persist the mnemonic in an encrypted
  //      file at <custody_dir>/custody.keystore.
  //      On subsequent launches, load and decrypt it. The operator
  //      supplies nothing but the existing keystore password.
  //
  //    FromXpub (watch-only, not the default):
  //      Take an externally-supplied xpub. Addresses are derived,
  //      but the bridge cannot spend from them. Reserved for a
  //      future hardware-wallet / multisig custody model.
  //
  //  BIP84 P2WPKH address space:
  //    account xpub at  m/84'/<coin_type>'/0'
  //    deposit address  m/84'/<coin_type>'/0'/0/<index>
  //
  //  coin_type = 0 for mainnet, 1 for testnet and regtest.
  //  =========================================================================

  struct DerivedScript
  {
    uint64_t index{0};
    std::array<uint8_t, 22> script{};
    std::string address;
  };

  class BitcoinCustody
  {
  public:
    enum class Source
    {
      Generated,
      FromXpub,
    };

    ~BitcoinCustody();

    BitcoinCustody(const BitcoinCustody &) = delete;
    BitcoinCustody &operator=(const BitcoinCustody &) = delete;

    //  Create-or-load the generated custody key.
    //
    //  If <custody_dir>/custody.keystore exists, it is opened and
    //  decrypted with `password` (the same password used to unlock
    //  the session keystore). On first launch the file does not
    //  exist and a fresh BIP39 mnemonic (256-bit) is generated,
    //  encrypted with `password`, and written.
    //
    //  `custody_dir` is created if it does not exist.
    //
    //  Returns nullptr on any failure and fills error_out.
    static std::unique_ptr<BitcoinCustody>
    create_or_load(const std::string &custody_dir,
                   Crypto::BitcoinNetwork network,
                   const std::string &password,
                   std::string *error_out);

    //  Configure from an externally-supplied xpub (watch-only mode).
    static std::unique_ptr<BitcoinCustody>
    from_xpub(const std::string &account_xpub,
              Crypto::BitcoinNetwork network,
              const std::vector<uint32_t> &derivation_tail,
              std::string *error_out);

    std::optional<DerivedScript> deriveScript(
        uint64_t index, std::string *error_out = nullptr) const;

    std::optional<std::string> deriveAddress(
        uint64_t index, std::string *error_out = nullptr) const;

    const std::map<std::array<uint8_t, 22>, DerivedScript> &
    scriptsInWindow() const noexcept;

    void onDepositSeen(uint64_t index);

    bool ensureIndexInWindow(uint64_t index);

    uint64_t highestDerivedIndex() const noexcept { return highest_derived_; }
    uint64_t highestUsedIndex() const noexcept { return highest_used_; }
    uint32_t masterFingerprint() const noexcept { return master_fp_; }
    Crypto::BitcoinNetwork network() const noexcept { return network_; }
    Source source() const noexcept { return source_; }
    bool canSpend() const noexcept { return source_ == Source::Generated; }

    std::string accountXpubDisplay() const;

  private:
    BitcoinCustody() = default;

    bool init_common(Crypto::BitcoinNetwork network,
                     const std::vector<uint32_t> &derivation_tail,
                     std::string *error_out);

    bool deriveInto(uint64_t index, std::string *error_out) const;

    Crypto::ExtendedPubKey account_{};
    Crypto::BitcoinNetwork network_{Crypto::BitcoinNetwork::Testnet};
    std::vector<uint32_t> tail_;
    uint32_t master_fp_{0};
    Source source_{Source::Generated};

    mutable std::map<uint64_t, DerivedScript> derived_;
    mutable std::map<std::array<uint8_t, 22>, DerivedScript> by_script_;
    mutable uint64_t highest_derived_{0};
    mutable bool have_derived_{false};

    uint64_t highest_used_{0};
    bool have_used_{false};
  };
} // namespace Bridge