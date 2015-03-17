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

#include "db.hpp"
#include "db-fixture.hpp"

#include <ndn-cxx/security/digest-sha256.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestDb, DbFixture)

BOOST_AUTO_TEST_CASE(Basic)
{
  ndn::DigestSha256 digest;
  ndn::ConstBufferPtr hash = make_shared<ndn::Buffer>(32);
  Data data1(Name("/logger/name/5/0/abcdabcdabcdabcdabcd/complete"));
  data1.setSignature(digest);
  data1.setSignatureValue(Block(tlv::SignatureValue, hash));
  Data data2(Name("/logger/name/5/32/abcdabcdabcdabcdabcd/complete"));
  data2.setSignature(digest);
  data2.setSignatureValue(Block(tlv::SignatureValue, hash));
  Data data3(Name("/logger/name/5/32/abcdabcdabcdabcdabcd/33"));
  data3.setSignature(digest);
  data3.setSignatureValue(Block(tlv::SignatureValue, hash));

  BOOST_CHECK_EQUAL(db.getPendingSubTrees().size(), 0);
  BOOST_CHECK(db.getSubTreeData(5, 0) == nullptr);
  db.insertSubTreeData(5, 0, data1);
  BOOST_REQUIRE(db.getSubTreeData(5, 0) != nullptr);
  BOOST_CHECK(db.getSubTreeData(5, 0)->wireEncode() == data1.wireEncode());
  BOOST_CHECK_EQUAL(db.getPendingSubTrees().size(), 0);

  BOOST_CHECK(db.getSubTreeData(5, 32) == nullptr);
  db.insertSubTreeData(5, 32, data3, false, 33);
  BOOST_REQUIRE(db.getSubTreeData(5, 32) != nullptr);
  BOOST_CHECK(db.getSubTreeData(5, 32)->wireEncode() == data3.wireEncode());
  BOOST_CHECK_EQUAL(db.getPendingSubTrees().size(), 1);

  db.insertSubTreeData(5, 32, data2);
  BOOST_REQUIRE(db.getSubTreeData(5, 32) != nullptr);
  BOOST_CHECK(db.getSubTreeData(5, 32)->wireEncode() == data2.wireEncode());
  BOOST_CHECK_EQUAL(db.getPendingSubTrees().size(), 0);
}

BOOST_AUTO_TEST_CASE(Basic2)
{
  ndn::DigestSha256 digest;
  ndn::ConstBufferPtr hash = make_shared<ndn::Buffer>(32);
  Data data1(Name("/logger/name/10/0/abcdabcdabcdabcdabcd/33"));
  data1.setSignature(digest);
  data1.setSignatureValue(Block(tlv::SignatureValue, hash));
  Data data2(Name("/logger/name/5/32/abcdabcdabcdabcdabcd/33"));
  data2.setSignature(digest);
  data2.setSignatureValue(Block(tlv::SignatureValue, hash));

  db.insertSubTreeData(5, 32, data2, false, 33);
  db.insertSubTreeData(10, 0, data1, false, 33);
  std::vector<shared_ptr<Data>> subtrees = db.getPendingSubTrees();

  BOOST_CHECK_EQUAL(subtrees.size(), 2);
  BOOST_CHECK(subtrees[0]->wireEncode() == data1.wireEncode());
  BOOST_CHECK(subtrees[1]->wireEncode() == data2.wireEncode());
}

const uint8_t Data1[] = {
0x06, 0xc5, // NDN Data
    0x07, 0x14, // Name
        0x08, 0x05,
            0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x08, 0x03,
            0x6e, 0x64, 0x6e,
        0x08, 0x06,
            0x70, 0x72, 0x65, 0x66, 0x69, 0x78,
    0x14, 0x04, // MetaInfo
        0x19, 0x02, // FreshnessPeriod
            0x27, 0x10,
    0x15, 0x08, // Content
        0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x21,
    0x16, 0x1b, // SignatureInfo
        0x1b, 0x01, // SignatureType
            0x01,
        0x1c, 0x16, // KeyLocator
            0x07, 0x14, // Name
                0x08, 0x04,
                    0x74, 0x65, 0x73, 0x74,
                0x08, 0x03,
                    0x6b, 0x65, 0x79,
                0x08, 0x07,
                    0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
    0x17, 0x80, // SignatureValue
        0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
        0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
        0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
        0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
        0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf,
        0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9,
        0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8,
        0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7,
        0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3,
        0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
};

BOOST_AUTO_TEST_CASE(Basic3)
{
  Name loggerName("/test/logger");
  Name dataName("/test/data");
  Block block(Data1, sizeof(Data1));
  Data data(block);

  BOOST_CHECK_EQUAL(db.getMaxLeafSeq(), 0);

  Leaf leaf(dataName, 1, 0, 0, loggerName);
  BOOST_CHECK(db.insertLeafData(leaf, data));
  BOOST_CHECK_EQUAL(db.getMaxLeafSeq(), 1);

  auto result = db.getLeaf(0);
  BOOST_CHECK_EQUAL(result.first->getDataName(), dataName);
  BOOST_CHECK_EQUAL(result.first->getTimestamp(), 1);
  BOOST_CHECK_EQUAL(result.first->getDataSeqNo(), 0);
  BOOST_CHECK_EQUAL(result.first->getSignerSeqNo(), 0);
  BOOST_REQUIRE(result.second != nullptr);
  BOOST_CHECK_EQUAL(result.second->getName(), data.getName());

  Leaf leaf2(dataName, 2, 1, 0, loggerName);
  BOOST_CHECK(db.insertLeafData(leaf2));
  BOOST_CHECK_EQUAL(db.getMaxLeafSeq(), 2);

  result = db.getLeaf(1);
  BOOST_REQUIRE(result.first != nullptr);
  BOOST_CHECK_EQUAL(result.first->getDataName(), dataName);
  BOOST_CHECK_EQUAL(result.first->getTimestamp(), 2);
  BOOST_CHECK_EQUAL(result.first->getDataSeqNo(), 1);
  BOOST_CHECK_EQUAL(result.first->getSignerSeqNo(), 0);
  BOOST_REQUIRE(result.second == nullptr);

  Leaf leaf3(dataName, 2, 5, 0, loggerName);
  BOOST_CHECK_EQUAL(db.insertLeafData(leaf), false);
  BOOST_CHECK_EQUAL(db.insertLeafData(leaf2), false);
  BOOST_CHECK_EQUAL(db.insertLeafData(leaf3), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
