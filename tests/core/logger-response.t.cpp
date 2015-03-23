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

#include "logger-response.hpp"
#include "cryptopp.hpp"

#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestLoggerResponse)

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
  LoggerResponse response1(5);
  BOOST_CHECK_EQUAL(response1.getCode(), 0);
  BOOST_CHECK_EQUAL(response1.getDataSeqNo(), 5);

  LoggerResponse response2(1, "error");
  BOOST_CHECK_EQUAL(response2.getCode(), 1);
  BOOST_CHECK_EQUAL(response2.getMsg(), "error");
}

uint8_t RESPONSE1[] = {
  0x90, 0x06,
    0x91, 0x01, 0x00,
    0x82, 0x01, 0x05
};

uint8_t RESPONSE2[] = {
  0x90, 0x0a,
    0x91, 0x01, 0x01,
    0x92, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72
};

BOOST_AUTO_TEST_CASE(Encoding)
{
  LoggerResponse response1(5);
  BOOST_CHECK_EQUAL_COLLECTIONS(response1.wireEncode().wire(),
                                response1.wireEncode().wire() + response1.wireEncode().size(),
                                RESPONSE1, RESPONSE1 + sizeof(RESPONSE1));

  LoggerResponse response2(1, "error");
  BOOST_CHECK_EQUAL_COLLECTIONS(response2.wireEncode().wire(),
                                response2.wireEncode().wire() + response2.wireEncode().size(),
                                RESPONSE2, RESPONSE2 + sizeof(RESPONSE2));
}

BOOST_AUTO_TEST_CASE(Decoding)
{
  LoggerResponse response1;
  Block block1(RESPONSE1, sizeof(RESPONSE1));
  BOOST_REQUIRE_NO_THROW(response1.wireDecode(block1));
  BOOST_CHECK_EQUAL(response1.getCode(), 0);
  BOOST_CHECK_EQUAL(response1.getDataSeqNo(), 5);

  LoggerResponse response2;
  Block block2(RESPONSE2, sizeof(RESPONSE2));
  BOOST_REQUIRE_NO_THROW(response2.wireDecode(block2));
  BOOST_CHECK_EQUAL(response2.getCode(), 1);
  BOOST_CHECK_EQUAL(response2.getMsg(), "error");
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
