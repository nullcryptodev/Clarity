#pragma once

#include "Core/Transaction.h"

namespace Tests
{
  // TransactionBuilder - Creates well-formed, real-signed
  // transactions for tests. Each call uses the same keypair
  // so we can control the sender.
  class TransactionBuilder
  {
  public:
    TransactionBuilder(uint64_t chain_id = 0x434C5247);

    TransactionBuilder &type(Core::TxType t);
    TransactionBuilder &from(const Crypto::KeyPair &kp);
    TransactionBuilder &to(const Crypto::Address &a);
    TransactionBuilder &amount(uint64_t a);
    TransactionBuilder &fee(uint64_t f);
    TransactionBuilder &nonce(uint64_t n);
    TransactionBuilder &tokenId(Id t);
    TransactionBuilder &chainId(uint64_t c);
    TransactionBuilder &expiry(uint64_t h);
    TransactionBuilder &payload(std::vector<uint8_t> p);

    Core::Transaction build() const;

    // The address that will appear as `from` in built txs.
    Crypto::Address senderAddress() const { return kp_.publicKey; }
    const Crypto::KeyPair &keyPair() const { return kp_; }

    // Set the sender to a different keypair.
    void setSender(const Crypto::KeyPair &kp) { kp_ = kp; }

    // Build and sign a transfer transaction.
    Core::Transaction buildTransfer(uint64_t nonce, uint64_t amount,
                                    uint64_t fee, Crypto::Address to = Crypto::Address{}) const;

    // Build a transfer with an explicit token ID (for custom-token tests).
    Core::Transaction buildTokenTransfer(uint64_t nonce, Id token_id,
                                         uint64_t amount, uint64_t fee) const;

  private:
    static Crypto::Address makeToAddress();

    Core::Transaction tx_{};
    Crypto::KeyPair kp_{};
    uint64_t chain_id_{0};
  };
}