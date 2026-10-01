// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Receipt.h"
#include "Core/Transaction.h"
#include "Core/TransactionTypes.h"
#include "RPC/Encoders.h"

using Common::Json;
using Rpc::encodeReceipt;
using Rpc::encodeTransaction;

TEST(RPC_TxEncoder, MinimalTransaction)
{
  Core::Transaction tx;
  tx.version = 1;
  tx.chain_id = 0x434C5254;
  tx.tx_type = Core::TxType::Transfer;
  tx.nonce = 7;
  tx.from = Crypto::addrFromHex(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  tx.to = Crypto::addrFromHex(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  tx.amount = 1000;
  tx.fee = 500;

  Json j = encodeTransaction(tx, "clrty");

  EXPECT_EQ(j["version"], 1);
  EXPECT_EQ(j["chain_id"], "0x434c5254");
  EXPECT_EQ(j["type"], "transfer");
  EXPECT_EQ(j["type_code"], 0);
  EXPECT_EQ(j["nonce"], "0x7");
  EXPECT_EQ(j["amount"], "0x3e8"); // 1000
  EXPECT_EQ(j["fee"], "0x1f4");    // 500
  EXPECT_EQ(j["token_id"], "0x0");
  ASSERT_TRUE(j["from"].is_string());
  ASSERT_TRUE(j["to"].is_string());
  EXPECT_EQ(j["from"].get<std::string>().substr(0, 5), "clrty");
  EXPECT_EQ(j["to"].get<std::string>().substr(0, 5), "clrty");
  EXPECT_TRUE(j.contains("hash"));
}

TEST(RPC_TxEncoder, PayloadAndSignatureIncluded)
{
  Core::Transaction tx;
  tx.from = Crypto::addrFromHex(
      "0101010101010101010101010101010101010101010101010101010101010101");
  tx.to = tx.from;
  tx.amount = 1;
  tx.fee = 1;
  tx.payload = {0xde, 0xad, 0xbe, 0xef};
  tx.signature.data[0] = 0xff;

  Json j = encodeTransaction(tx, "clrty");

  EXPECT_EQ(j["payload"], "0xdeadbeef");
  ASSERT_TRUE(j["signature"].is_string());
  EXPECT_EQ(j["signature"].get<std::string>().substr(0, 2), "0x");
}

TEST(ReceiptEncoder, SuccessReceipt)
{
  Core::Receipt r;
  r.status = Core::ReceiptStatus::Success;
  r.fee_paid = 500;

  Json j = encodeReceipt(r);
  EXPECT_EQ(j["status"], "success");
  EXPECT_EQ(j["status_code"], 0);
  EXPECT_EQ(j["fee_paid"], "0x1f4");
}

TEST(ReceiptEncoder, FailureReceipt)
{
  Core::Receipt r;
  r.status = Core::ReceiptStatus::Failure;
  r.fee_paid = 100;

  Json j = encodeReceipt(r);
  EXPECT_EQ(j["status"], "failure");
  EXPECT_EQ(j["status_code"], 1);
  EXPECT_EQ(j["fee_paid"], "0x64");
}