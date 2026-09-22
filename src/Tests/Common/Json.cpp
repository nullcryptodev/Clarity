// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/Json.h"

using namespace Common;

TEST(Json, GetBoolOrDefault)
{
  Json j;
  j["flag"] = true;
  j["off"] = false;

  EXPECT_TRUE(getBoolOrDefault(j, "flag"));
  EXPECT_FALSE(getBoolOrDefault(j, "off"));
  EXPECT_FALSE(getBoolOrDefault(j, "missing"));
  EXPECT_TRUE(getBoolOrDefault(j, "missing", true));
}

TEST(Json, GetBoolOrDefaultWrongType)
{
  Json j;
  j["not_bool"] = "hello";

  EXPECT_FALSE(getBoolOrDefault(j, "not_bool"));
  EXPECT_TRUE(getBoolOrDefault(j, "not_bool", true));
}

TEST(Json, GetIntOrDefault)
{
  Json j;
  j["count"] = 42;

  EXPECT_EQ(getIntOrDefault(j, "count"), 42);
  EXPECT_EQ(getIntOrDefault(j, "missing"), 0);
  EXPECT_EQ(getIntOrDefault(j, "missing", 99), 99);
}

TEST(Json, GetStringOrDefault)
{
  Json j;
  j["name"] = "clarity";

  EXPECT_EQ(getStringOrDefault(j, "name"), "clarity");
  EXPECT_EQ(getStringOrDefault(j, "missing"), "");
  EXPECT_EQ(getStringOrDefault(j, "missing", "default"), "default");
}

TEST(Json, GetVectorOrDefaultStrings)
{
  Json j;
  j["items"] = {"one", "two", "three"};

  auto v = getVectorOrDefault<std::string>(j, "items");
  ASSERT_EQ(v.size(), 3);
  EXPECT_EQ(v[0], "one");
  EXPECT_EQ(v[1], "two");
  EXPECT_EQ(v[2], "three");
}

TEST(Json, GetVectorOrDefaultInts)
{
  Json j;
  j["nums"] = {1, 2, 3, 4};

  auto v = getVectorOrDefault<int>(j, "nums");
  ASSERT_EQ(v.size(), 4);
  EXPECT_EQ(v[0], 1);
  EXPECT_EQ(v[3], 4);
}

TEST(Json, GetVectorOrDefaultMissing)
{
  Json j;
  auto v = getVectorOrDefault<std::string>(j, "missing");
  EXPECT_TRUE(v.empty());
}