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

#include "node.hpp"
#include "cryptopp.hpp"

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include "boost-test.hpp"

namespace ndn {
namespace delorean {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestNode)

BOOST_AUTO_TEST_CASE(IndexTest1)
{
  Node::Index idx(0, 0);

  BOOST_CHECK_EQUAL(idx.seqNo, 0);
  BOOST_CHECK_EQUAL(idx.level, 0);
  BOOST_CHECK_EQUAL(idx.range, 1);

  Node::Index idx2(0, 1);
  BOOST_CHECK_EQUAL(idx2.seqNo, 0);
  BOOST_CHECK_EQUAL(idx2.level, 1);
  BOOST_CHECK_EQUAL(idx2.range, 2);

  Node::Index idx3(2, 1);
  BOOST_CHECK_EQUAL(idx3.seqNo, 2);
  BOOST_CHECK_EQUAL(idx3.level, 1);
  BOOST_CHECK_EQUAL(idx3.range, 2);

  Node::Index idx4(4, 2);
  BOOST_CHECK_EQUAL(idx4.seqNo, 4);
  BOOST_CHECK_EQUAL(idx4.level, 2);
  BOOST_CHECK_EQUAL(idx4.range, 4);

  BOOST_CHECK_THROW(Node::Index(1, 1), Node::Error);
  BOOST_CHECK_THROW(Node::Index(2, 2), Node::Error);
}

BOOST_AUTO_TEST_CASE(IndexTest2)
{
  Node::Index idx1(0, 0);
  Node::Index idx2(0, 1);
  Node::Index idx3(2, 0);
  Node::Index idx4(2, 1);

  BOOST_CHECK(idx1 < idx2);
  BOOST_CHECK(idx1 < idx3);
  BOOST_CHECK(idx1 < idx4);
  BOOST_CHECK(idx2 < idx3);
  BOOST_CHECK(idx2 < idx4);
  BOOST_CHECK(idx3 < idx4);

  BOOST_CHECK(idx1 == idx1);
  BOOST_CHECK_EQUAL(idx1 == idx2, false);
  BOOST_CHECK_EQUAL(idx1 == idx3, false);
  BOOST_CHECK_EQUAL(idx1 == idx4, false);
}

BOOST_AUTO_TEST_CASE(NodeTest1)
{
  std::string hash("ABCDEFGHIJKLMNOPabcdefghijklmno");
  auto buffer = make_shared<const ndn::Buffer>(hash.c_str(), hash.size());

  Node node(0, 0);
  BOOST_CHECK(node.getIndex() == Node::Index(0, 0));
  BOOST_CHECK(!node.isFull());
  BOOST_CHECK_EQUAL(node.getLeafSeqNo(), 0);
  BOOST_CHECK(node.getHash() == nullptr);

  node.setLeafSeqNo(1);
  BOOST_CHECK(node.isFull());
  BOOST_CHECK_EQUAL(node.getLeafSeqNo(), 1);

  Node node2(2, 1);
  BOOST_CHECK(!node2.isFull());
  BOOST_CHECK_EQUAL(node2.getLeafSeqNo(), 2);
  BOOST_CHECK(node2.getHash() == nullptr);

  Node node3(2, 1, 4);
  BOOST_CHECK(node3.isFull());
  BOOST_CHECK_EQUAL(node3.getLeafSeqNo(), 4);
  BOOST_CHECK(node3.getHash() == nullptr);

  Node node4(2, 1, 3, buffer);
  BOOST_CHECK(!node4.isFull());
  BOOST_CHECK_EQUAL(node4.getLeafSeqNo(), 3);
  BOOST_CHECK_EQUAL_COLLECTIONS(node4.getHash()->begin(), node4.getHash()->end(),
                                buffer->begin(), buffer->end());


  {
    using namespace CryptoPP;

    ndn::OBufferStream os;
    std::string emptyHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    StringSource ss(reinterpret_cast<const uint8_t*>(emptyHash.c_str()), emptyHash.size(),
                    true, new HexDecoder(new FileSink(os)));
    BOOST_CHECK_EQUAL_COLLECTIONS(Node::getEmptyHash()->begin(), Node::getEmptyHash()->end(),
                                  os.buf()->begin(), os.buf()->end());
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace delorean
} // namespace ndn
