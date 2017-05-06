/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017, Regents of the University of California
 *
 * This file is part of NDN DeLorean, An Authentication System for Data Archives in
 * Named Data Networking.  See AUTHORS.md for complete list of NDN DeLorean authors
 * and contributors.
 *
 * NDN DeLorean is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * NDN DeLorean is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with NDN
 * DeLorean, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "merkle-tree.hpp"
#include "../tree-generator.hpp"
#include "db-fixture.hpp"

#include <boost/mpl/list.hpp>
#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestMerkleTree, DbFixture)

BOOST_AUTO_TEST_CASE(Basic)
{
  MerkleTree merkleTree(TreeGenerator::LOGGER_NAME, db);
  BOOST_CHECK_EQUAL(merkleTree.getNextLeafSeqNo(), 0);
  BOOST_CHECK(merkleTree.getRootHash() == nullptr);
}

template<NonNegativeInteger N, size_t L>
struct MerkleTreeTestParam
{
  const NonNegativeInteger leafNo = N;
  const size_t rootLevel = L;
};

typedef boost::mpl::list<MerkleTreeTestParam<5, 3>,
                         MerkleTreeTestParam<32, 5>,
                         MerkleTreeTestParam<33, 6>,
                         MerkleTreeTestParam<1024, 10>,
                         MerkleTreeTestParam<1025, 11>> AddLeafTestParams;

BOOST_AUTO_TEST_CASE_TEMPLATE(AddLeaf, T, AddLeafTestParams)
{
  T param;

  NonNegativeInteger leafNo = param.leafNo;
  size_t rootLevel = param.rootLevel;

  MerkleTree merkleTree(TreeGenerator::LOGGER_NAME, db);
  for (NonNegativeInteger i = 0; i < leafNo ; i++) {
    BOOST_REQUIRE(merkleTree.addLeaf(i, Node::getEmptyHash()));
  }

  auto hash1 = TreeGenerator::getHash(Node::Index(0, rootLevel), leafNo);
  auto hash2 = merkleTree.getRootHash();

  BOOST_REQUIRE(hash1 != nullptr);
  BOOST_REQUIRE(hash2 != nullptr);

  BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
}

class MerkleTreeLoadTestParam1
{
public:
  void
  insertData(Db& db)
  {
    // partial first sub-tree
    auto subtree1 = TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 5);
    db.insertSubTreeData(5, 0, *subtree1->encode(), false, 5);
  }

  const NonNegativeInteger seqNo = 0;
  const size_t level = 3;
  const NonNegativeInteger nextLeafSeqNo = 5;
};

class MerkleTreeLoadTestParam2
{
public:
  void
  insertData(Db& db)
  {
    // full first sub-tree
    auto subtree1 = TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32);
    auto subtree1Data = subtree1->encode();
    db.insertSubTreeData(5, 0, *subtree1Data);

    auto subtree2 = TreeGenerator::getSubTreeBinary(Node::Index(0, 10), 32);
    auto subtree2Data = subtree2->encode();
    db.insertSubTreeData(10, 0, *subtree2Data, false, 32);

    auto subtree3 = make_shared<SubTreeBinary>(TreeGenerator::LOGGER_NAME,
                                               Node::Index(32, 5),
                                               [&] (const Node::Index&) {},
                                               [&] (const Node::Index&,
                                                    const NonNegativeInteger&,
                                                    ndn::ConstBufferPtr) {});
    auto subtree3Data = subtree3->encode();

    db.insertSubTreeData(5, 32, *subtree3Data, false, 32);
  }

  const NonNegativeInteger seqNo = 0;
  const size_t level = 5;
  const NonNegativeInteger nextLeafSeqNo = 32;
};

class MerkleTreeLoadTestParam3
{
public:
  void
  insertData(Db& db)
  {
    auto subtree1 = TreeGenerator::getSubTreeBinary(Node::Index(0, 15), 1025);
    auto subtree1Data = subtree1->encode();
    db.insertSubTreeData(15, 0, *subtree1Data, false, 1025);

    auto subtree2 = TreeGenerator::getSubTreeBinary(Node::Index(1024, 10), 1025);
    auto subtree2Data = subtree2->encode();
    db.insertSubTreeData(10, 1024, *subtree2Data, false, 1025);

    auto subtree3 = TreeGenerator::getSubTreeBinary(Node::Index(1024, 5), 1025);
    auto subtree3Data = subtree3->encode();
    db.insertSubTreeData(5, 1024, *subtree3Data, false, 1025);
  }

  const NonNegativeInteger seqNo = 0;
  const size_t level = 11;
  const NonNegativeInteger nextLeafSeqNo = 1025;
};


typedef boost::mpl::list<MerkleTreeLoadTestParam1,
                         MerkleTreeLoadTestParam2,
                         MerkleTreeLoadTestParam3> DbLoadTestParams;

BOOST_AUTO_TEST_CASE_TEMPLATE(DbLoad, T, DbLoadTestParams)
{
  T param;

  param.insertData(db);

  MerkleTree merkleTree(TreeGenerator::LOGGER_NAME, db);

  auto hash1 = TreeGenerator::getHash(Node::Index(param.seqNo, param.level), param.nextLeafSeqNo);
  auto hash2 = merkleTree.getRootHash();

  BOOST_REQUIRE(hash1 != nullptr);
  BOOST_REQUIRE(hash2 != nullptr);

  BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
}

BOOST_AUTO_TEST_CASE(DbSave1)
{
  MerkleTree merkleTree(TreeGenerator::LOGGER_NAME, db);
  for (NonNegativeInteger i = 0; i < 5 ; i++) {
    BOOST_REQUIRE(merkleTree.addLeaf(i, Node::getEmptyHash()));
  }

  merkleTree.savePendingTree();
  auto data1 = db.getPendingSubTrees()[0];
  auto data2 = TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 5)->encode();

  BOOST_CHECK(data1->wireEncode() == data2->wireEncode());
}

BOOST_AUTO_TEST_CASE(DbSave2)
{
  MerkleTree merkleTree(TreeGenerator::LOGGER_NAME, db);
  for (NonNegativeInteger i = 0; i < 32 ; i++) {
    BOOST_REQUIRE(merkleTree.addLeaf(i, Node::getEmptyHash()));
  }

  merkleTree.savePendingTree();
  auto data1 = db.getPendingSubTrees()[0];
  auto data2 = TreeGenerator::getSubTreeBinary(Node::Index(0, 10), 32)->encode();

  auto data3 = db.getPendingSubTrees()[1];
  auto subtree = make_shared<SubTreeBinary>(TreeGenerator::LOGGER_NAME,
                                            Node::Index(32, 5),
                                            [&] (const Node::Index&) {},
                                            [&] (const Node::Index&,
                                                 const NonNegativeInteger&,
                                                 ndn::ConstBufferPtr) {});
  auto data4 = subtree->encode();

  BOOST_CHECK(data1->wireEncode() == data2->wireEncode());
  BOOST_CHECK(data3->wireEncode() == data4->wireEncode());

  auto dataA = TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32)->encode();
  auto dataB = db.getSubTreeData(5, 0);

  BOOST_CHECK(dataA->wireEncode() == dataB->wireEncode());
}

BOOST_AUTO_TEST_CASE(DbSave3)
{
  MerkleTree merkleTree(TreeGenerator::LOGGER_NAME, db);
  for (NonNegativeInteger i = 0; i < 1025 ; i++) {
    BOOST_REQUIRE(merkleTree.addLeaf(i, Node::getEmptyHash()));
  }

  merkleTree.savePendingTree();

  auto data1 = db.getPendingSubTrees()[0];
  auto data2 = TreeGenerator::getSubTreeBinary(Node::Index(0, 15), 1025)->encode();

  auto data3 = db.getPendingSubTrees()[1];
  auto data4 = TreeGenerator::getSubTreeBinary(Node::Index(1024, 10), 1025)->encode();

  auto data5 = db.getPendingSubTrees()[2];
  auto data6 = TreeGenerator::getSubTreeBinary(Node::Index(1024, 5), 1025)->encode();

  BOOST_CHECK(data1->wireEncode() == data2->wireEncode());
  BOOST_CHECK(data3->wireEncode() == data4->wireEncode());
  BOOST_CHECK(data5->wireEncode() == data6->wireEncode());

  for (NonNegativeInteger i = 0; i < 1024 ; i += 32) {
    auto dataA = TreeGenerator::getSubTreeBinary(Node::Index(i, 5), i + 32)->encode();
    auto dataB = db.getSubTreeData(5, i);

    BOOST_CHECK(dataA->wireEncode() == dataB->wireEncode());
  }

  auto dataA = TreeGenerator::getSubTreeBinary(Node::Index(0, 10), 1024)->encode();
  auto dataB = db.getSubTreeData(10, 0);

  BOOST_CHECK(dataA->wireEncode() == dataB->wireEncode());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
