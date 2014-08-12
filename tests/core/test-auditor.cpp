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
 * @author Peizhen Guo <patrick.guopz@gmail.com>
 */
#include <boost-test.hpp>
#include <iostream>

#include "auditor.hpp"
#include "merkle-tree.hpp"

namespace nsl {


boost::test_tools::predicate_result check_hash(ndn::ConstBufferPtr ptr1, ndn::ConstBufferPtr ptr2)
{
  bool result = true;
  for (int i = 0; i < ptr1->size(); i++)
    {
      if ((*ptr1)[i] != (*ptr2)[i])
        {
          result = false;
          break;
        }
    }
  return result;
}


BOOST_AUTO_TEST_SUITE(TestAuditor)


BOOST_AUTO_TEST_CASE(TestVerify)
{

  std::string str1 = "peizhen";
  std::string str2 = "guo";
  std::string str3 = "is";
  std::string str4 = "building";
  std::string str5 = "this";
  std::string str6 = "logging";
  std::string str7 = "system";
  ndn::Buffer buf1;
  ndn::Buffer buf2;
  ndn::Buffer buf3;
  ndn::Buffer buf4;
  ndn::Buffer buf5;
  ndn::Buffer buf6;
  ndn::Buffer buf7;
  for (int i=0; i < str1.size(); i++)
    buf1.push_back(uint8_t(str1[i]));
  for (int i=0; i < str2.size(); i++)
    buf2.push_back(uint8_t(str2[i]));
  for (int i=0; i < str3.size(); i++)
    buf3.push_back(uint8_t(str3[i]));
  for (int i=0; i < str4.size(); i++)
    buf4.push_back(uint8_t(str4[i]));
  for (int i=0; i < str5.size(); i++)
    buf5.push_back(uint8_t(str5[i]));
  for (int i=0; i < str6.size(); i++)
    buf6.push_back(uint8_t(str6[i]));
  for (int i=0; i < str7.size(); i++)
    buf7.push_back(uint8_t(str7[i]));
  ndn::ConstBufferPtr buf_p1 = boost::make_shared<ndn::Buffer>(buf1);
  ndn::ConstBufferPtr buf_p2 = boost::make_shared<ndn::Buffer>(buf2);
  ndn::ConstBufferPtr buf_p3 = boost::make_shared<ndn::Buffer>(buf3);
  ndn::ConstBufferPtr buf_p4 = boost::make_shared<ndn::Buffer>(buf4);
  ndn::ConstBufferPtr buf_p5 = boost::make_shared<ndn::Buffer>(buf5);
  ndn::ConstBufferPtr buf_p6 = boost::make_shared<ndn::Buffer>(buf6);
  ndn::ConstBufferPtr buf_p7 = boost::make_shared<ndn::Buffer>(buf7);

  // Test genProof function
  Auditor validator;
  MerkleTree merkle_tree;
  Index version1, version2;
  merkle_tree.addLeaf(buf_p1);
  merkle_tree.addLeaf(buf_p2);
  merkle_tree.addLeaf(buf_p3);
  merkle_tree.addLeaf(buf_p4);
  version1.number = 0; version1.level = merkle_tree.getLevel() - 1;
  const Index ver1 = version1;
  ndn::ConstBufferPtr rootHash1 = merkle_tree.getNode(ver1)->getHash();
  merkle_tree.addLeaf(buf_p5);
  merkle_tree.addLeaf(buf_p6);
  merkle_tree.addLeaf(buf_p7);
  version2.number = 0; version2.level = merkle_tree.getLevel() - 1;
  const Index ver2 = version2;
  ndn::ConstBufferPtr rootHash2 = merkle_tree.getNode(ver2)->getHash();

  std::vector<ConstNodePtr> evidence = merkle_tree.generateProof(3, 6);
  bool isConsistent = validator.verifyConsistency(3, 6, rootHash1, rootHash2, evidence);
  BOOST_CHECK(isConsistent== true);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace nsl
