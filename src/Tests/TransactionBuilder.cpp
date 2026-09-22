
#include "TransactionBuilder.h"
#include "Utils.h"

#include "Crypto/Ed25519.h"

namespace Tests
{
  TransactionBuilder::TransactionBuilder(uint64_t chain_id) :
    chain_id_(chain_id)
  {
    kp_ = Crypto::generateKeyPair();
  }

  TransactionBuilder &TransactionBuilder::type(Core::TxType t)
  {
    tx_.tx_type = t;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::from(const Crypto::KeyPair &kp)
  {
    tx_.from = kp.publicKey;
    kp_ = kp;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::to(const Crypto::Address &a)
  {
    tx_.to = a;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::amount(uint64_t a)
  {
    tx_.amount = a;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::fee(uint64_t f)
  {
    tx_.fee = f;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::nonce(uint64_t n)
  {
    tx_.nonce = n;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::tokenId(Id t)
  {
    tx_.token_id = t;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::chainId(uint64_t c)
  {
    tx_.chain_id = c;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::expiry(uint64_t h)
  {
    tx_.valid_until_height = h;
    return *this;
  }
  TransactionBuilder &TransactionBuilder::payload(std::vector<uint8_t> p)
  {
    tx_.payload = std::move(p);
    return *this;
  }

  Core::Transaction TransactionBuilder::build() const
  {
    Core::Transaction tx = tx_;
    Crypto::Hash sighash = tx.signingHash();
    tx.signature = Crypto::sign(sighash, kp_.secretKey);
    return tx;
  }

  // Build and sign a transfer transaction.
  Core::Transaction TransactionBuilder::buildTransfer(uint64_t nonce,
                                             uint64_t amount,
                                             uint64_t fee,
                                             Crypto::Address to) const
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
  }

  // Build a transfer with an explicit token ID (for custom-token tests).
  Core::Transaction TransactionBuilder::buildTokenTransfer(uint64_t nonce,
                                                  Id token_id,
                                                  uint64_t amount,
                                                  uint64_t fee) const
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
  }

  Crypto::Address TransactionBuilder::makeToAddress()
  {
    Crypto::Address a;
    for (size_t i = 0; i < 32; ++i)
    {
      a.data[i] = static_cast<uint8_t>(0xC0 + i);
    }
    return a;
  }
}