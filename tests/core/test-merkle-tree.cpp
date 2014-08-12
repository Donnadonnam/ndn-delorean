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

#include "merkle-tree.hpp"

namespace nsl {

boost::test_tools::predicate_result check_buffer(ndn::ConstBufferPtr ptr1, ndn::ConstBufferPtr ptr2)
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

BOOST_AUTO_TEST_SUITE(TestTree)


BOOST_AUTO_TEST_CASE(TestBuild)
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

  //Test add/get function
  MerkleTree merkle_tree;
  merkle_tree.addLeaf(buf_p1);
  Index idx;
  idx.number = 0;
  idx.level = 0;
  ndn::ConstBufferPtr tmp_ptr = ((Leaf*)(merkle_tree.getNode(idx).get()))->getData();
  BOOST_CHECK(merkle_tree.getLeafNum() == 1 && merkle_tree.getLevel() == 1
              && merkle_tree.getLevel() == idx.level + 1);
  BOOST_CHECK(check_buffer(tmp_ptr, buf_p1));

  merkle_tree.addLeaf(buf_p2);
  idx.number += 1;
  BOOST_CHECK(check_buffer(((Leaf*)(merkle_tree.getNode(idx).get()))->getData(), buf_p2));
  idx.number = 0;
  idx.level = 1;
  BOOST_CHECK(((IntermediateNode*)(merkle_tree.getNode(idx).get()))->isFull() == true
              && merkle_tree.getLeafNum() == 2 && merkle_tree.getLevel() == 2
              && merkle_tree.getLevel() == idx.level + 1);


  merkle_tree.addLeaf(buf_p3);
  idx.number = 2; idx.level = 0;
  BOOST_CHECK(check_buffer(((Leaf*)(merkle_tree.getNode(idx).get()))->getData(), buf_p3));
  idx.level = 1;
  BOOST_CHECK(((IntermediateNode*)(merkle_tree.getNode(idx).get()))->isFull() == false);
  idx.number = 0;
  BOOST_CHECK(((IntermediateNode*)(merkle_tree.getNode(idx).get()))->isFull() == true);
  BOOST_CHECK(merkle_tree.getLeafNum() == 3 && merkle_tree.getLevel() == 3);


  merkle_tree.addLeaf(buf_p4);
  merkle_tree.addLeaf(buf_p5);
  merkle_tree.addLeaf(buf_p6);
  merkle_tree.addLeaf(buf_p7);
  BOOST_CHECK(merkle_tree.getLeafNum() == 7 && merkle_tree.getLevel() == 4);
  idx.level = 2;
  idx.number = 4;
  BOOST_CHECK(((IntermediateNode*)(merkle_tree.getNode(idx).get()))->isFull() == false);
  idx.level = 1;
  idx.number = 2;
  BOOST_CHECK(((IntermediateNode*)(merkle_tree.getNode(idx).get()))->isFull() == true);
}



BOOST_AUTO_TEST_CASE(TestGenerateProof)
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
  MerkleTree merkle_tree;
  merkle_tree.addLeaf(buf_p1);
  merkle_tree.addLeaf(buf_p2);
  merkle_tree.addLeaf(buf_p3);
  merkle_tree.addLeaf(buf_p4);
  merkle_tree.addLeaf(buf_p5);
  merkle_tree.addLeaf(buf_p6);
  merkle_tree.addLeaf(buf_p7);
  std::vector<ConstNodePtr> verifyPathPresent = merkle_tree.generateProof(2, 5);
  std::vector<ConstNodePtr> verifyPathPrevious = merkle_tree.generateProof(4, 6);
  Index idx;
  for (int i = 0; i < verifyPathPresent.size(); i++)
    {
      idx = (verifyPathPresent[i])->getIndex();
      std::cout << idx.number << "," << idx.level << std::endl;
    }
  std::cout << std::endl;
  for (int i = 0; i < verifyPathPrevious.size(); i++)
    {
      idx = (verifyPathPrevious[i])->getIndex();
      std::cout << idx.number << "," << idx.level << std::endl;
    }
}



BOOST_AUTO_TEST_SUITE_END()

} // namespace nsl
