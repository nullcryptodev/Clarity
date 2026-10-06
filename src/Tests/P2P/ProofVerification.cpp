// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Temp.h"
#include "Tests/Utils.h"

#include "State/SmtProof.h"
#include "State/SparseMerkleTree.h"

using namespace State;
using namespace Tests;

//  proveAtRoot must produce proofs that verify against the given root.
//  This is what the P2P GetProof handler relies on: it walks from a
//  historical root and returns the proof, and the client verifies
//  against that same root.

TEST(P2P_ProofVerification, ProveAtCurrentRootMatchesProve)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Hash key = Tests::makeHash(0xAA);
  std::vector<uint8_t> value = {1, 2, 3, 4};

  tree.update(key, value, /*version=*/1);

  auto proof_current = prove(tree, key);
  auto proof_at_root = proveAtRoot(tree, tree.root(), key);

  ASSERT_TRUE(proof_current.has_value());
  ASSERT_TRUE(proof_at_root.has_value());

  // Both must verify against the current root.
  EXPECT_TRUE(verifyProof(tree.root(), *proof_current));
  EXPECT_TRUE(verifyProof(tree.root(), *proof_at_root));

  // And they must be byte-identical — same input, same walk.
  EXPECT_EQ(proof_current->serialize(), proof_at_root->serialize());
}

TEST(P2P_ProofVerification, ProveAtHistoricalRootVerifiesAgainstThatRoot)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Hash key = Tests::makeHash(0xBB);

  // Version 1: key exists with value A.
  tree.update(key, {0xAA}, /*version=*/1);
  tree.save(/*version=*/1);
  Crypto::Hash root_v1 = tree.root();

  // Version 2: key changes to value B.
  tree.update(key, {0xBB}, /*version=*/2);
  tree.save(/*version=*/2);
  Crypto::Hash root_v2 = tree.root();

  ASSERT_NE(root_v1, root_v2);

  //  To prove against root_v1, we need a tree whose node storage
  //  matches version 1. The SMT stores nodes content-addressed, so
  //  the version-1 nodes are still present in the DB — the version-1
  //  walk reads them because their hashes are still stored. Only the
  //  root differs.
  auto proof_v1 = proveAtRoot(tree, root_v1, key);
  ASSERT_TRUE(proof_v1.has_value());
  EXPECT_TRUE(verifyProof(root_v1, *proof_v1));

  // The version-1 proof must not verify against the version-2 root,
  // since the value differs.
  EXPECT_FALSE(verifyProof(root_v2, *proof_v1));
}

TEST(P2P_ProofVerification, ProveAtRootOfEmptyTreeIsNonInclusion)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Hash key = Tests::makeHash(0xCC);

  // Tree is empty.
  auto proof = proveAtRoot(tree, tree.root(), key);
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(verifyProof(tree.root(), *proof));
}

TEST(P2P_ProofVerification, ProveAtWrongRootProducesUnverifiableProof)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Hash key = Tests::makeHash(0xDD);
  tree.update(key, {0x11, 0x22}, /*version=*/1);

  //  Pick a root that doesn't correspond to any real state. The walk
  //  will read nodes that don't lead to `key`, and the resulting
  //  proof will not verify.
  Crypto::Hash bogus_root;
  bogus_root.data[0] = 0xFF;

  auto proof = proveAtRoot(tree, bogus_root, key);

  //  The walk might produce a proof (if it finds *a* path to some
  //  leaf) or fail entirely (if a node along the path isn't stored).
  //  Either way, if a proof is produced, it must not verify against
  //  the bogus root.
  if (proof.has_value())
  {
    EXPECT_FALSE(verifyProof(bogus_root, *proof));
  }
}