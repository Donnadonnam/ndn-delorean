/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of NSL (NDN Signature Logger).
 * See AUTHORS.md for complete list of NSL authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of nsl authors and contributors.
 */

#include "sub-tree-binary.hpp"

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/util/digest.hpp>
#include "boost-test.hpp"

namespace nsl {
namespace tests {

class SubTreeBinaryTestFixture
{
public:
  NonNegativeInteger nextSeqNo;
  NonNegativeInteger seqNoCount;

  size_t nCompleteCalls;
  size_t nUpdateCalls;

  ndn::ConstBufferPtr eventualHash;
};

BOOST_FIXTURE_TEST_SUITE(TestSubTreeBinary, SubTreeBinaryTestFixture)

ndn::ConstBufferPtr
getTestHashRoot(const Node::Index& idx)
{
  if (idx.level == 0)
    return Node::getEmptyHash();

  auto hash1 = getTestHashRoot(Node::Index(idx.seqNo, idx.level - 1));
  auto hash2 = getTestHashRoot(Node::Index(idx.seqNo + (idx.range >> 1), idx.level - 1));

  ndn::util::Sha256 sha256;
  sha256 << idx.level << idx.seqNo;
  sha256.update(hash1->buf(), hash1->size());
  sha256.update(hash2->buf(), hash2->size());

  return sha256.computeDigest();
}

void
printHex(const uint8_t* buf, size_t size)
{
  using namespace CryptoPP;
  StringSource ss(buf, size, true, new HexEncoder(new FileSink(std::cerr), false));
  std::cerr << std::endl;
}

void
printByte(const uint8_t* buf, size_t size)
{
  std::stringstream ss;
  using namespace CryptoPP;
  StringSource is(buf, size, true, new HexEncoder(new FileSink(ss), false));

  std::string output = ss.str();
  for (size_t i = 0; i < output.size(); i++) {
    std::cerr << "0x" << output.at(i);
    std::cerr << output.at(++i) << ", ";
    if ((i + 1) % 32 == 0)
      std::cerr << std::endl;
  }
}


BOOST_AUTO_TEST_CASE(BasicTest1)
{
  nextSeqNo = 0;
  seqNoCount = 0;
  nCompleteCalls = 0;
  nUpdateCalls = 0;

  Name loggerName("/logger/name");

  Node::Index idx(0, 5);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index& index) {
                          BOOST_CHECK_EQUAL(this->seqNoCount, idx.range);
                          this->nCompleteCalls++;
                        },
                        [&] (const Node::Index&,
                             const NonNegativeInteger& seqNo,
                             ndn::ConstBufferPtr hash) {
                          BOOST_CHECK_EQUAL(this->nextSeqNo, seqNo);
                          this->nUpdateCalls++;
                          this->eventualHash = hash;
                        });

  BOOST_CHECK(subTree.getPeakIndex() == idx);
  BOOST_CHECK_EQUAL(subTree.getMinSeqNo(), 0);
  BOOST_CHECK_EQUAL(subTree.getMaxSeqNo(), 32);
  BOOST_CHECK_EQUAL(subTree.getLeafLevel(), 0);
  BOOST_CHECK_EQUAL(subTree.getNextLeafSeqNo(), 0);

  for (int i = 0; i < 32; i++) {
    seqNoCount++;
    nextSeqNo++;
    BOOST_CHECK_EQUAL(subTree.isFull(), false);
    auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
    BOOST_CHECK(subTree.addLeaf(node));
    BOOST_CHECK_EQUAL(subTree.getNextLeafSeqNo(), i + 1);
  }
  BOOST_CHECK_EQUAL(subTree.isFull(), true);

  BOOST_CHECK_EQUAL(nCompleteCalls, 1);
  BOOST_CHECK_EQUAL(nUpdateCalls, 32);

  auto actualHash = subTree.getRoot()->getHash();
  BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                eventualHash->begin(), eventualHash->end());

  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string rootHash("989551ef13ce660c1c5ccdda770f4769966a6faf83722c91dfeac597c6fa2782");
    StringSource ss(reinterpret_cast<const uint8_t*>(rootHash.c_str()), rootHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                  os.buf()->begin(), os.buf()->end());
  }

}

BOOST_AUTO_TEST_CASE(BasicTest2)
{
  nextSeqNo = 32;
  seqNoCount = 0;
  nCompleteCalls = 0;
  nUpdateCalls = 0;

  Name loggerName("/logger/name");

  Node::Index idx(32, 5);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index& index) {
                          BOOST_CHECK_EQUAL(this->seqNoCount, idx.range);
                          this->nCompleteCalls++;
                        },
                        [&] (const Node::Index&,
                             const NonNegativeInteger& seqNo,
                             ndn::ConstBufferPtr hash) {
                          BOOST_CHECK(this->nextSeqNo >= (1 << (idx.level - 1)));
                          BOOST_CHECK_EQUAL(this->nextSeqNo, seqNo);
                          this->nUpdateCalls++;
                          this->eventualHash = hash;
                        });

  BOOST_CHECK(subTree.getPeakIndex() == idx);
  BOOST_CHECK_EQUAL(subTree.getMinSeqNo(), 32);
  BOOST_CHECK_EQUAL(subTree.getMaxSeqNo(), 64);
  BOOST_CHECK_EQUAL(subTree.getLeafLevel(), 0);
  BOOST_CHECK_EQUAL(subTree.getNextLeafSeqNo(), 32);

  for (int i = 32; i < 64; i++) {
    seqNoCount++;
    nextSeqNo++;
    BOOST_CHECK_EQUAL(subTree.isFull(), false);
    auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
    BOOST_CHECK(subTree.addLeaf(node));
    BOOST_CHECK_EQUAL(subTree.getNextLeafSeqNo(), i + 1);
  }
  BOOST_CHECK_EQUAL(subTree.isFull(), true);

  BOOST_CHECK_EQUAL(nCompleteCalls, 1);
  BOOST_CHECK_EQUAL(nUpdateCalls, 32);

  auto actualHash = subTree.getRoot()->getHash();
  BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                eventualHash->begin(), eventualHash->end());

  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string rootHash("2657cd81c3acb8eb4489f0a2559d42532644ce737ae494f49f30452f47bcff53");
    StringSource ss(reinterpret_cast<const uint8_t*>(rootHash.c_str()), rootHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                  os.buf()->begin(), os.buf()->end());
  }
}

BOOST_AUTO_TEST_CASE(BasicTest3)
{
  nextSeqNo = 0;
  seqNoCount = 0;
  nCompleteCalls = 0;
  nUpdateCalls = 0;

  Name loggerName("/logger/name");

  Node::Index idx(0, 10);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index& index) {
                          BOOST_CHECK_EQUAL(this->seqNoCount, 32);
                          this->nCompleteCalls++;
                        },
                        [&] (const Node::Index&,
                             const NonNegativeInteger& seqNo,
                             ndn::ConstBufferPtr hash) {
                          BOOST_CHECK_EQUAL(this->nextSeqNo, seqNo);
                          this->nUpdateCalls++;
                          this->eventualHash = hash;
                        });

  BOOST_CHECK(subTree.getPeakIndex() == idx);
  BOOST_CHECK_EQUAL(subTree.getMinSeqNo(), 0);
  BOOST_CHECK_EQUAL(subTree.getMaxSeqNo(), 1024);
  BOOST_CHECK_EQUAL(subTree.getLeafLevel(), 5);
  BOOST_CHECK_EQUAL(subTree.getNextLeafSeqNo(), 0);

  for (int i = 0; i < 1024; i += 32) {
    seqNoCount++;
    nextSeqNo += 32;
    BOOST_CHECK_EQUAL(subTree.isFull(), false);
    auto node = make_shared<Node>(i, 5, i + 32, getTestHashRoot(Node::Index(i, 5)));
    BOOST_CHECK(subTree.addLeaf(node));
    BOOST_CHECK_EQUAL(subTree.getNextLeafSeqNo(), i + 32);
  }
  BOOST_CHECK_EQUAL(subTree.isFull(), true);

  BOOST_CHECK_EQUAL(nCompleteCalls, 1);
  BOOST_CHECK_EQUAL(nUpdateCalls, 32);

  auto actualHash = subTree.getRoot()->getHash();
  BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                eventualHash->begin(), eventualHash->end());

  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string rootHash("dc138a319c197bc4ede89902ed9b46e4e17d732b5ace9fa3b8a398db5edb1e36");
    StringSource ss(reinterpret_cast<const uint8_t*>(rootHash.c_str()), rootHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                  os.buf()->begin(), os.buf()->end());
  }
}

BOOST_AUTO_TEST_CASE(AddLeaf1)
{
  Name loggerName("/logger/name");

  Node::Index idx(0, 10);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  auto node_0_5 = make_shared<Node>(0, 5, 32, getTestHashRoot(Node::Index(0, 5)));
  auto node_32_5 = make_shared<Node>(32, 5, 64, getTestHashRoot(Node::Index(32, 5)));
  auto node_64_5 = make_shared<Node>(64, 5, 96, getTestHashRoot(Node::Index(64, 5)));

  Node::Index idx2(32, 5);
  SubTreeBinary subTree2(loggerName,
                         idx2,
                         [&] (const Node::Index&) {},
                         [&] (const Node::Index&,
                              const NonNegativeInteger&,
                              ndn::ConstBufferPtr) {});

  auto node_32_0 = make_shared<Node>(32, 0, 33, Node::getEmptyHash());
  auto node_33_0 = make_shared<Node>(33, 0, 34, Node::getEmptyHash());
  auto node_34_0 = make_shared<Node>(34, 0, 35, Node::getEmptyHash());
  BOOST_REQUIRE(subTree2.addLeaf(node_32_0));
  BOOST_REQUIRE(subTree2.getRoot() != nullptr);
  BOOST_REQUIRE(subTree2.getRoot()->getHash() != nullptr);
  auto node_32_5_33 = make_shared<Node>(32, 5, 33, subTree2.getRoot()->getHash());
  BOOST_REQUIRE(subTree2.addLeaf(node_33_0));
  auto node_32_5_34 = make_shared<Node>(32, 5, 34, subTree2.getRoot()->getHash());
  BOOST_REQUIRE(subTree2.addLeaf(node_34_0));
  auto node_32_5_35 = make_shared<Node>(32, 5, 35, subTree2.getRoot()->getHash());

  BOOST_CHECK_EQUAL(subTree.addLeaf(node_32_5), false);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_0_5), true);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_32_5_33), true);
  BOOST_CHECK_EQUAL(subTree.updateLeaf(34, node_32_5_34->getHash()), true);
  BOOST_CHECK_EQUAL(subTree.updateLeaf(35, node_32_5_35->getHash()), true);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_32_5), false);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_64_5), false);
  BOOST_CHECK_EQUAL(subTree.updateLeaf(64, node_32_5->getHash()), true);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_64_5), true);

  for (int i = 96; i < 1024; i += 32) {
    BOOST_CHECK_EQUAL(subTree.isFull(), false);
    auto node = make_shared<Node>(i, 5, i + 32, getTestHashRoot(Node::Index(i, 5)));
    BOOST_CHECK(subTree.addLeaf(node));
  }
  BOOST_CHECK_EQUAL(subTree.isFull(), true);

  auto actualHash = subTree.getRoot()->getHash();
  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string rootHash("dc138a319c197bc4ede89902ed9b46e4e17d732b5ace9fa3b8a398db5edb1e36");
    StringSource ss(reinterpret_cast<const uint8_t*>(rootHash.c_str()), rootHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                  os.buf()->begin(), os.buf()->end());
  }
}


uint8_t SUBTREE_DATA[] = {
  0x06, 0xfd, 0x04, 0x6f, // Data
    0x07, 0x40,  // Name /logger/name/5/0/complete/....
      0x08, 0x06, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x72,
      0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65,
      0x08, 0x01, 0x05,
      0x08, 0x01, 0x00,
      0x08, 0x08, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65,
      0x08, 0x20,
        0x98, 0x95, 0x51, 0xef, 0x13, 0xce, 0x66, 0x0c,
        0x1c, 0x5c, 0xcd, 0xda, 0x77, 0x0f, 0x47, 0x69,
        0x96, 0x6a, 0x6f, 0xaf, 0x83, 0x72, 0x2c, 0x91,
        0xdf, 0xea, 0xc5, 0x97, 0xc6, 0xfa, 0x27, 0x82,
    0x14, 0x00, // MetaInfo
    0x15, 0xfd, 0x04, 0x00, // Content
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    0x16, 0x03, 0x1b, 0x01, 0x00, // SigInfo
    0x17, 0x20, // SigValue
      0x2d, 0xda, 0xd1, 0xd3, 0x25, 0xd1, 0x7d, 0xf5, 0x64, 0xab, 0x58, 0x74, 0x3a, 0x01, 0xb9, 0x31,
      0x52, 0xcd, 0x55, 0xd2, 0xce, 0xea, 0xbc, 0x7c, 0x1a, 0x61, 0xe4, 0x7e, 0xff, 0x4a, 0x1f, 0xe7
};

BOOST_AUTO_TEST_CASE(Encoding1)
{
  Name loggerName("/logger/name");

  Node::Index idx(0, 5);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  for (int i = 0; i < 32; i++) {
    auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
    subTree.addLeaf(node);
  }

  shared_ptr<Data> data = subTree.encode();
  BOOST_REQUIRE(data != nullptr);

  BOOST_CHECK_EQUAL_COLLECTIONS(data->wireEncode().wire(),
                                data->wireEncode().wire() + data->wireEncode().size(),
                                SUBTREE_DATA,
                                SUBTREE_DATA + sizeof(SUBTREE_DATA));
}

BOOST_AUTO_TEST_CASE(Decoding1)
{
  Name loggerName("/logger/name");
  SubTreeBinary subtree(loggerName,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  Block block(SUBTREE_DATA, sizeof(SUBTREE_DATA));
  Data data(block);

  BOOST_REQUIRE_NO_THROW(subtree.decode(data));
}

uint8_t SUBTREE_DATA2[] = {
  0x06, 0xaa, // Data
    0x07, 0x39, // Name /logger/name/6/0/.../35
      0x08, 0x06, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x72,
      0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65,
      0x08, 0x01, 0x06,
      0x08, 0x01, 0x00,
      0x08, 0x01, 0x23,
      0x08, 0x20,
        0x44, 0xb2, 0x25, 0x95, 0x79, 0x99, 0x8c, 0xd7,
        0xd9, 0x56, 0xc5, 0x22, 0x32, 0x53, 0xd0, 0x7f,
        0xf0, 0x09, 0x12, 0xd2, 0x17, 0x54, 0x81, 0x79,
        0xfc, 0xad, 0x40, 0x2f, 0x86, 0x0e, 0xa2, 0xef,
    0x14, 0x04, // MetaInfo
      0x19, 0x02, 0xea, 0x60, // 60000 ms
    0x15, 0x40, // Content
      0x98, 0x95, 0x51, 0xef, 0x13, 0xce, 0x66, 0x0c, 0x1c, 0x5c, 0xcd, 0xda, 0x77, 0x0f, 0x47, 0x69,
      0x96, 0x6a, 0x6f, 0xaf, 0x83, 0x72, 0x2c, 0x91, 0xdf, 0xea, 0xc5, 0x97, 0xc6, 0xfa, 0x27, 0x82,
      0xf8, 0x30, 0x5d, 0x94, 0xfa, 0x23, 0xe2, 0x49, 0x08, 0x73, 0x5a, 0xc2, 0x22, 0x34, 0xa1, 0xfd,
      0xc4, 0x46, 0xec, 0x07, 0x7c, 0x6c, 0xa2, 0x7e, 0x51, 0x70, 0x68, 0xa9, 0xbb, 0xc6, 0x56, 0x89,
    0x16, 0x03, // SigInfo
      0x1b, 0x01, 0x00,
    0x17, 0x20, // SigValue
      0xad, 0x00, 0xce, 0x0b, 0x31, 0x06, 0x9d, 0xee, 0x90, 0x28, 0x03, 0xbe, 0x3f, 0xcc, 0x0a, 0xd6,
      0x1b, 0x3e, 0xf6, 0x26, 0x07, 0x63, 0x9b, 0xdf, 0xb9, 0x5e, 0x82, 0xd4, 0xb0, 0xce, 0xc0, 0x9f
};

BOOST_AUTO_TEST_CASE(Encoding2)
{
  Name loggerName("/logger/name");

  Node::Index idx(0, 10);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  auto node_0_5 = make_shared<Node>(0, 5, 32, getTestHashRoot(Node::Index(0, 5)));
  auto node_32_5 = make_shared<Node>(32, 5, 64, getTestHashRoot(Node::Index(32, 5)));
  auto node_64_5 = make_shared<Node>(64, 5, 96, getTestHashRoot(Node::Index(64, 5)));

  Node::Index idx2(32, 5);
  SubTreeBinary subTree2(loggerName,
                         idx2,
                         [&] (const Node::Index&) {},
                         [&] (const Node::Index&,
                              const NonNegativeInteger&,
                              ndn::ConstBufferPtr) {});

  auto node_32_0 = make_shared<Node>(32, 0, 33, Node::getEmptyHash());
  auto node_33_0 = make_shared<Node>(33, 0, 34, Node::getEmptyHash());
  auto node_34_0 = make_shared<Node>(34, 0, 35, Node::getEmptyHash());
  BOOST_REQUIRE(subTree2.addLeaf(node_32_0));
  BOOST_REQUIRE(subTree2.getRoot() != nullptr);
  BOOST_REQUIRE(subTree2.getRoot()->getHash() != nullptr);
  auto node_32_5_33 = make_shared<Node>(32, 5, 33, subTree2.getRoot()->getHash());
  BOOST_REQUIRE(subTree2.addLeaf(node_33_0));
  auto node_32_5_34 = make_shared<Node>(32, 5, 34, subTree2.getRoot()->getHash());
  BOOST_REQUIRE(subTree2.addLeaf(node_34_0));
  auto node_32_5_35 = make_shared<Node>(32, 5, 35, subTree2.getRoot()->getHash());

  BOOST_CHECK_EQUAL(subTree.addLeaf(node_32_5), false);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_0_5), true);
  BOOST_CHECK_EQUAL(subTree.addLeaf(node_32_5_33), true);
  BOOST_CHECK_EQUAL(subTree.updateLeaf(34, node_32_5_34->getHash()), true);
  BOOST_CHECK_EQUAL(subTree.updateLeaf(35, node_32_5_35->getHash()), true);

  shared_ptr<Data> data = subTree.encode();
  BOOST_REQUIRE(data != nullptr);

  BOOST_CHECK_EQUAL(data->getName().get(SubTreeBinary::OFFSET_COMPLETE).toNumber(), 35);
  BOOST_CHECK_EQUAL(data->getFreshnessPeriod(), time::milliseconds(60000));
  BOOST_CHECK_EQUAL(data->getContent().value_size(), 32 * 2);

  BOOST_CHECK_EQUAL_COLLECTIONS(data->wireEncode().wire(),
                                data->wireEncode().wire() + data->wireEncode().size(),
                                SUBTREE_DATA2,
                                SUBTREE_DATA2 + sizeof(SUBTREE_DATA2));
}

BOOST_AUTO_TEST_CASE(Decoding2)
{
  Name loggerName("/logger/name");
  SubTreeBinary subTree(loggerName,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  Block block(SUBTREE_DATA2, sizeof(SUBTREE_DATA2));
  Data data(block);

  BOOST_REQUIRE_NO_THROW(subTree.decode(data));

  auto node_32_5 = make_shared<Node>(32, 5, 64, getTestHashRoot(Node::Index(32, 5)));
  BOOST_CHECK_EQUAL(subTree.updateLeaf(64, node_32_5->getHash()), true);

  for (int i = 64; i < 1024; i += 32) {
    BOOST_CHECK_EQUAL(subTree.isFull(), false);
    auto node = make_shared<Node>(i, 5, i + 32, getTestHashRoot(Node::Index(i, 5)));
    BOOST_CHECK(subTree.addLeaf(node));
  }
  BOOST_CHECK_EQUAL(subTree.isFull(), true);

  auto actualHash = subTree.getRoot()->getHash();
  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string rootHash("dc138a319c197bc4ede89902ed9b46e4e17d732b5ace9fa3b8a398db5edb1e36");
    StringSource ss(reinterpret_cast<const uint8_t*>(rootHash.c_str()), rootHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                  os.buf()->begin(), os.buf()->end());
  }
}

uint8_t SUBTREE_DATA3[] = {
  0x06, 0x69,
    0x07, 0x39,
      0x08, 0x06, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x72,
      0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65,
      0x08, 0x01, 0x05,
      0x08, 0x01, 0x00,
      0x08, 0x01, 0x00,
      0x08, 0x20,
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    0x14, 0x03,
      0x19, 0x01, 0x00,
    0x15, 0x00,
    0x16, 0x03,
      0x1b, 0x01, 0x00,
    0x17, 0x20,
      0x42, 0x3d, 0x4b, 0xb2, 0xe8, 0x24, 0xd3, 0xf6, 0xb7, 0x20, 0x69, 0x8f, 0x70, 0xb3, 0x9f, 0xfb,
      0xdf, 0x71, 0x05, 0xdd, 0xcf, 0xdc, 0x4d, 0x08, 0xbb, 0x22, 0x2e, 0x89, 0x1a, 0x81, 0xef, 0xce
};

BOOST_AUTO_TEST_CASE(Encoding3)
{
  Name loggerName("/logger/name");

  Node::Index idx(0, 5);
  SubTreeBinary subTree(loggerName,
                        idx,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  shared_ptr<Data> data = subTree.encode();
  BOOST_REQUIRE(data != nullptr);

  BOOST_CHECK_EQUAL(data->getName().get(SubTreeBinary::OFFSET_COMPLETE).toNumber(), 0);
  BOOST_CHECK_EQUAL(data->getFreshnessPeriod(), time::milliseconds(0));
  BOOST_CHECK_EQUAL(data->getContent().value_size(), 0);

  BOOST_CHECK_EQUAL_COLLECTIONS(data->wireEncode().wire(),
                                data->wireEncode().wire() + data->wireEncode().size(),
                                SUBTREE_DATA3,
                                SUBTREE_DATA3 + sizeof(SUBTREE_DATA3));
}

BOOST_AUTO_TEST_CASE(Decoding3)
{
  Name loggerName("/logger/name");
  SubTreeBinary subTree(loggerName,
                        [&] (const Node::Index&) {},
                        [&] (const Node::Index&,
                             const NonNegativeInteger&,
                             ndn::ConstBufferPtr) {});

  Block block(SUBTREE_DATA3, sizeof(SUBTREE_DATA3));
  Data data(block);

  try {
    subTree.decode(data);
  }
  catch (std::runtime_error& e) {
    std::cerr << e.what() << std::endl;
  }

  BOOST_REQUIRE_NO_THROW(subTree.decode(data));
  BOOST_CHECK(subTree.getRoot() == nullptr);
  BOOST_CHECK(subTree.getPeakIndex() == Node::Index(0, 5));
  BOOST_CHECK_EQUAL(subTree.getLeafLevel(), 0);
  BOOST_CHECK_EQUAL(subTree.isFull(), false);

  for (int i = 0; i < 32; i ++) {
    BOOST_CHECK_EQUAL(subTree.isFull(), false);
    auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
    BOOST_CHECK(subTree.addLeaf(node));
  }
  BOOST_CHECK_EQUAL(subTree.isFull(), true);

  auto actualHash = subTree.getRoot()->getHash();
  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string rootHash("989551ef13ce660c1c5ccdda770f4769966a6faf83722c91dfeac597c6fa2782");
    StringSource ss(reinterpret_cast<const uint8_t*>(rootHash.c_str()), rootHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(actualHash->begin(), actualHash->end(),
                                  os.buf()->begin(), os.buf()->end());
  }
}

BOOST_AUTO_TEST_CASE(SubTreePeakIndexConvert)
{
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(0, 0)) == Node::Index(0, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(0, 1)) == Node::Index(0, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(0, 5), false) == Node::Index(0, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(0, 5)) == Node::Index(0, 10));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(1, 0)) == Node::Index(0, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(2, 1)) == Node::Index(0, 5));

  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(32, 0)) == Node::Index(32, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(32, 1)) == Node::Index(32, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(32, 5), false) == Node::Index(32, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(32, 5)) == Node::Index(0, 10));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(33, 0)) == Node::Index(32, 5));
  BOOST_CHECK(SubTreeBinary::toSubTreePeakIndex(Node::Index(34, 1)) == Node::Index(32, 5));
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
