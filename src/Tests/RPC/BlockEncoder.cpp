// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Block.h"
#include "RPC/Encoders.h"
#include "Tests/Utils.h"

using Common::Json;
using Rpc::encodeBlock;
using Rpc::encodeBlockHeader;

using namespace Tests;

TEST(RPC_BlockEncoder, HeaderFieldsPresent)
{
  Json j = encodeBlockHeader(makeBlockHeader(), "clrty");

  // Values should match makeBlockHeader
  EXPECT_EQ(j["version"], 1);
  EXPECT_EQ(j["chain_id"], 0x434C5247u);
  EXPECT_EQ(j["height"], "0x64"); 
  EXPECT_EQ(j["timestamp_ms"], "0x18bcfe56800");
  ASSERT_TRUE(j["proposer"].is_string());
  EXPECT_EQ(j["proposer"].get<std::string>().substr(0, 5), "clrty");
  EXPECT_TRUE(j.contains("state_root"));
  EXPECT_TRUE(j.contains("tx_root"));
  EXPECT_TRUE(j.contains("receipts_root"));
  EXPECT_TRUE(j.contains("validator_set_root"));
  EXPECT_EQ(j["total_fees"], "0x5dc");
  EXPECT_EQ(j["tx_count"], 0);
  EXPECT_EQ(j["active_validator_count"], 21);
  EXPECT_EQ(j["epoch"], "0x1");
  EXPECT_EQ(j["rotation_index"], "0x1");
  EXPECT_EQ(j["commit_round"], "0x0");
}

TEST(RPC_BlockEncoder, EmptyBlockHashesOnly)
{
  Core::Block b;
  b.header = makeBlockHeader();

  Json j = encodeBlock(b, /*include_transactions=*/false, "clrty");

  ASSERT_TRUE(j["transactions"].is_array());
  EXPECT_EQ(j["transactions"].size(), 0u);
  ASSERT_TRUE(j["participants"].is_array());
  EXPECT_EQ(j["participants"].size(), 0u);
  ASSERT_TRUE(j["quorum_signatures"].is_array());
  EXPECT_EQ(j["quorum_signatures"].size(), 0u);
  EXPECT_EQ(j["height"], "0x64"); // matches makeBlockHeader
}