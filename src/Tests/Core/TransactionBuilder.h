#pragma once

#include "Core/Transaction.h"
#include "Crypto/Ed25519.h"

namespace Tests
{
  // TransactionBuilder - Creates well-formed, real-signed
  // transactions for tests. Each call uses the same keypair
  // so we can control the sender.
  class TransactionBuilder
  {
  public:
    TransactionBuilder(uint64_t chain_id = 0x434C5247) : chain_id_(chain_id)
    {
      kp_ = Crypto::generateKeyPair();
    };

    TransactionBuilder &type(Core::TxType t)
    {
      tx_.tx_type = t;
      return *this;
    };
    TransactionBuilder &from(const Crypto::KeyPair &kp)
    {
      tx_.from = kp.publicKey;
      kp_ = kp;
      return *this;
    }
    TransactionBuilder &to(const Crypto::Address &a)
    {
      tx_.to = a;
      return *this;
    }
    TransactionBuilder &amount(uint64_t a)
    {
      tx_.amount = a;
      return *this;
    }
    TransactionBuilder &fee(uint64_t f)
    {
      tx_.fee = f;
      return *this;
    }
    TransactionBuilder &nonce(uint64_t n)
    {
      tx_.nonce = n;
      return *this;
    }
    TransactionBuilder &tokenId(Id t)
    {
      tx_.token_id = t;
      return *this;
    }
    TransactionBuilder &chainId(uint64_t c)
    {
      tx_.chain_id = c;
      return *this;
    }
    TransactionBuilder &expiry(uint64_t h)
    {
      tx_.valid_until_height = h;
      return *this;
    }
    TransactionBuilder &payload(std::vector<uint8_t> p)
    {
      tx_.payload = std::move(p);
      return *this;
    }

    Core::Transaction build() const
    {
      Core::Transaction tx = tx_;
      Crypto::Hash sighash = tx.signingHash();
      tx.signature = Crypto::sign(sighash, kp_.secretKey);
      return tx;
    }

    // The address that will appear as `from` in built txs.
    Crypto::Address senderAddress() const { return kp_.publicKey; }
    const Crypto::KeyPair &keyPair() const { return kp_; }

    // Set the sender to a different keypair.
    void setSender(const Crypto::KeyPair &kp) { kp_ = kp; }

    // Build and sign a transfer transaction.
    Core::Transaction buildTransfer(uint64_t nonce, uint64_t amount,
                                    uint64_t fee, Crypto::Address to = Crypto::Address{}) const
    {
      Core::Transaction tx;
      tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
      tx.chain_id = chain_id_;
      tx.tx_type = Core::TxType::Transfer;
      tx.nonce = nonce;
      tx.valid_until_height = 0;
      tx.from = kp_.publicKey;
      tx.to = to.isNull() ? makeToAddress() : to;
      tx.token_id = 0;
      tx.amount = amount;
      tx.fee = fee;

      // Sign.
      Crypto::Hash sighash = tx.signingHash();
      tx.signature = Crypto::sign(sighash, kp_.secretKey);
      return tx;
    };

    // Build a transfer with an explicit token ID (for custom-token tests).
    Core::Transaction buildTokenTransfer(uint64_t nonce, Id token_id,
                                         uint64_t amount, uint64_t fee) const
    {
      Core::Transaction tx;
      tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
      tx.chain_id = chain_id_;
      tx.tx_type = Core::TxType::Transfer;
      tx.nonce = nonce;
      tx.valid_until_height = 0;
      tx.from = kp_.publicKey;
      tx.to = makeToAddress();
      tx.token_id = token_id;
      tx.amount = amount;
      tx.fee = fee;

      Crypto::Hash sighash = tx.signingHash();
      tx.signature = Crypto::sign(sighash, kp_.secretKey);
      return tx;
    };

  private:
    static Crypto::Address makeToAddress()
    {
      Crypto::Address a;
      for (size_t i = 0; i < 32; ++i)
      {
        a.data[i] = static_cast<uint8_t>(0xC0 + i);
      }
      return a;
    };

    Core::Transaction tx_{};
    Crypto::KeyPair kp_{};
    uint64_t chain_id_{0};
  };
}