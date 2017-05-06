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

#include "leaf.hpp"
#include "cryptopp.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace delorean {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestLeaf)

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

BOOST_AUTO_TEST_CASE(Basic)
{
  Name loggerName("/test/logger");
  Name dataName("/test/data");

  BOOST_CHECK_NO_THROW(Leaf(dataName, 0, 1, 1, loggerName));
  BOOST_CHECK_NO_THROW(Leaf(dataName, 0, 2, 1, loggerName));
  BOOST_CHECK_THROW(Leaf(dataName, 0, 2, 3, loggerName), Leaf::Error);

  Leaf leaf(dataName, 0, 2, 1, loggerName);

  BOOST_CHECK_EQUAL(leaf.getDataName(), dataName);
  BOOST_CHECK_EQUAL(leaf.getTimestamp(), 0);
  BOOST_CHECK_EQUAL(leaf.getDataSeqNo(), 2);
  BOOST_CHECK_EQUAL(leaf.getSignerSeqNo(), 1);

  BOOST_CHECK_THROW(leaf.setDataSeqNo(0), Leaf::Error);
  BOOST_CHECK_THROW(leaf.setSignerSeqNo(5), Leaf::Error);
}

uint8_t LEAF_BLOCK[] = {
  0x80, 0x17,
    0x07, 0x0c,
      0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
      0x08, 0x04, 0x64, 0x61, 0x74, 0x61,
    0x81, 0x01, 0x00,
    0x82, 0x01, 0x02,
    0x83, 0x01, 0x01
};

uint8_t LEAF_HASH[] = {
  0x79, 0xcb, 0x54, 0xa7, 0x47, 0xa8, 0xea, 0x98, 0x92, 0x39, 0xdb, 0xcf, 0xd0, 0x9a, 0xbb, 0xbd,
  0xe3, 0x10, 0x82, 0x3b, 0x4d, 0x46, 0xc4, 0xc1, 0x39, 0x76, 0xbd, 0x3d, 0x17, 0xcc, 0xa9, 0x2b
};

uint8_t LEAF_DATA[] = {
  0x06, 0x79,
    0x07, 0x33,
      0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
      0x08, 0x06, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x72,
      0x08, 0x01, 0x02,
      0x08, 0x20,
        0x79, 0xcb, 0x54, 0xa7, 0x47, 0xa8, 0xea, 0x98,
        0x92, 0x39, 0xdb, 0xcf, 0xd0, 0x9a, 0xbb, 0xbd,
        0xe3, 0x10, 0x82, 0x3b, 0x4d, 0x46, 0xc4, 0xc1,
        0x39, 0x76, 0xbd, 0x3d, 0x17, 0xcc, 0xa9, 0x2b,
    0x14, 0x00,
    0x15, 0x19,
      0x80, 0x17,
        0x07, 0x0c,
          0x08, 0x04, 0x74, 0x65, 0x73, 0x74,
          0x08, 0x04, 0x64, 0x61, 0x74, 0x61,
        0x81, 0x01, 0x00,
        0x82, 0x01, 0x02,
        0x83, 0x01, 0x01,
    0x16, 0x03,
      0x1b, 0x01, 0x00,
    0x17, 0x20,
      0x96, 0x49, 0xe0, 0x62, 0x23, 0x72, 0xd0, 0x90, 0x85, 0x9c, 0x28, 0xda, 0xc8, 0x50, 0x6f, 0x48,
      0x56, 0x62, 0x14, 0x8d, 0x75, 0x20, 0x91, 0xa9, 0x0a, 0x46, 0xd6, 0xf8, 0xfc, 0x5d, 0x8e, 0x8e
};

BOOST_AUTO_TEST_CASE(Encoding)
{
  Name loggerName("/test/logger");
  Name dataName("/test/data");

  Leaf leaf(dataName, 0, 2, 1, loggerName);
  const Block& block = leaf.wireEncode();

  BOOST_CHECK_EQUAL_COLLECTIONS(block.wire(), block.wire() + block.size(),
                                LEAF_BLOCK, LEAF_BLOCK + sizeof(LEAF_BLOCK));

  ndn::ConstBufferPtr hash = leaf.getHash();
  BOOST_CHECK_EQUAL_COLLECTIONS(hash->begin(), hash->end(),
                                LEAF_HASH, LEAF_HASH + sizeof(LEAF_HASH));

  auto data = leaf.encode();
  BOOST_CHECK_EQUAL_COLLECTIONS(data->wireEncode().wire(),
                                data->wireEncode().wire() + data->wireEncode().size(),
                                LEAF_DATA,
                                LEAF_DATA + sizeof(LEAF_DATA));
}

BOOST_AUTO_TEST_CASE(Decoding)
{
  Name loggerName("/test/logger");
  Name dataName("/test/data");


  Block block(LEAF_DATA, sizeof(LEAF_DATA));
  Data data(block);

  Leaf leaf;
  BOOST_REQUIRE_NO_THROW(leaf.decode(data));

  BOOST_CHECK_EQUAL(leaf.getDataName(), dataName);
  BOOST_CHECK_EQUAL(leaf.getTimestamp(), 0);
  BOOST_CHECK_EQUAL(leaf.getDataSeqNo(), 2);
  BOOST_CHECK_EQUAL(leaf.getSignerSeqNo(), 1);

  ndn::ConstBufferPtr hash = leaf.getHash();
  BOOST_CHECK_EQUAL_COLLECTIONS(hash->begin(), hash->end(),
                                LEAF_HASH, LEAF_HASH + sizeof(LEAF_HASH));
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace delorean
} // namespace ndn
