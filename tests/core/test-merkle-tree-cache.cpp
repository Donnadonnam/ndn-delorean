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

#include "merkle-tree-cache.hpp"
#include "Auditor.hpp"


namespace nsl {

boost::test_tools::predicate_result check_buffer_cache(ndn::ConstBufferPtr ptr1,
                                                       ndn::ConstBufferPtr ptr2)
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

BOOST_AUTO_TEST_SUITE(TestCache)

BOOST_AUTO_TEST_CASE(TestFunction)
{
  // Test build
  ndn::Buffer buf[200];
  Index idx[200];
  for (uint8_t i = 0; i < 200; i++)
    {
      buf[i].push_back(i);
      idx[i].number = i;
      idx[i].level = 0;
    }
  MerkleTreeCache treeCache;
  for (int i = 0; i < 200; i++)
    {
      ndn::ConstBufferPtr p_buf = ndn::make_shared<ndn::Buffer>(buf[i]);
      Leaf newleaf(p_buf, idx[i].number, idx[i].level, 0);
      newleaf.computeHash();
      treeCache.addLeaf(newleaf);
      BOOST_CHECK(treeCache.getLeaves() == i + 1);
    }
  BOOST_CHECK(treeCache.getLevel() == 2 && treeCache.getLeaves() == 200);
  // std::cout<<treeCache.m_cachedTree.size()<<' '<<treeCache.m_leavesData.size()<<std::endl;

  // Test query
  ndn::ConstBufferPtr data_buf90 = ((Leaf*)(treeCache.queryNode(idx[90]).get()))->getData();
  BOOST_CHECK(int((*data_buf90)[0]) == 90);
  ndn::ConstBufferPtr data_buf10 = ((Leaf*)(treeCache.queryNode(idx[10]).get()))->getData();
  BOOST_CHECK(int((*data_buf10)[0]) == 10);

  ndn::ConstBufferPtr hash_buf1 = ((Leaf*)(treeCache.queryNode(idx[0]).get()))->getHash();
  ndn::ConstBufferPtr hash_buf2 = ((Leaf*)(treeCache.queryNode(idx[1]).get()))->getHash();
  ndn::ConstBufferPtr hash_buf3 = ((Leaf*)(treeCache.queryNode(idx[2]).get()))->getHash();
  ndn::ConstBufferPtr hash_buf4 = ((Leaf*)(treeCache.queryNode(idx[3]).get()))->getHash();
  Auditor audit;
  ndn::ConstBufferPtr hash_buf5 = audit.computeHash(hash_buf1, hash_buf2);
  ndn::ConstBufferPtr hash_buf6 = audit.computeHash(hash_buf3, hash_buf4);
  ndn::ConstBufferPtr hash_buf7 = audit.computeHash(hash_buf5, hash_buf6);
  Index idx1;
  idx1.number = 0; idx1.level = 2;
  ndn::ConstBufferPtr hash_buf8 = ((IntermediateNode*)(treeCache.queryNode(idx1).get()))->getHash();
  BOOST_CHECK(check_buffer_cache(hash_buf7, hash_buf8));
  idx1.number = 70; idx1.level = 1;
  ndn::ConstBufferPtr hash_buf70 = ((Leaf*)(treeCache.queryNode(idx[70]).get()))->getHash();
  ndn::ConstBufferPtr hash_buf71 = ((Leaf*)(treeCache.queryNode(idx[71]).get()))->getHash();
  ndn::ConstBufferPtr hash_buf72 = audit.computeHash(hash_buf70, hash_buf71);
  ndn::ConstBufferPtr hash_buf73 = ((IntermediateNode*)
                                    (treeCache.queryNode(idx1).get()))->getHash();
  BOOST_CHECK(check_buffer_cache(hash_buf72, hash_buf73));

  // Test Encoding Decoding
  idx1.number = 0; idx1.level = 12;
  SubTreePtr sub_ptr1 = treeCache.getSubTree(idx1);
  std::string tmp_str = sub_ptr1->encoding();
  SubTreePtr sub_ptr2 = treeCache.decoding(tmp_str);
  BOOST_CHECK(sub_ptr1->getRootIndex().number == sub_ptr2->getRootIndex().number &&
              sub_ptr1->getRootIndex().level == sub_ptr2->getRootIndex().level);
  BOOST_CHECK(sub_ptr1->getRemainPosition() == sub_ptr2->getRemainPosition());
  idx1.number = 0; idx1.level = 10;
  ndn::ConstBufferPtr origin_buf = sub_ptr1->getHash(idx1);
  ndn::ConstBufferPtr resume_buf = sub_ptr2->getHash(idx1);
  BOOST_CHECK(check_buffer_cache(origin_buf, resume_buf));


  // Test Sqlite3 (move m_database to public to test)
  /*
    idx1.number = 0; idx1.level = 12;
    treeCache.m_database.addSubTree(sub_ptr1);
    std::string str = treeCache.m_database.getSubTree(idx1);
    SubTreePtr sub_ptr_sql = treeCache.decoding(str);
    BOOST_CHECK(sub_ptr1->getRootIndex().number == sub_ptr_sql->getRootIndex().number &&
    sub_ptr1->getRootIndex().level == sub_ptr_sql->getRootIndex().level);
    BOOST_CHECK(sub_ptr1->getRemainPosition() == sub_ptr_sql->getRemainPosition());
    idx1.number = 0; idx1.level = 10;
    origin_buf = sub_ptr1->getHash(idx1);
    resume_buf = sub_ptr_sql->getHash(idx1);
    BOOST_CHECK(check_buffer_cache(origin_buf, resume_buf));
    idx1.number = 0; idx1.level = 12;
    BOOST_CHECK(treeCache.m_database.doesSubTreeExist(idx1) == true);
    idx1.number = 300; idx1.level = 2;
    BOOST_CHECK(treeCache.m_database.doesSubTreeExist(idx1) == false);

    uint64_t sequence = 90;
    treeCache.m_database.addLeafInfo(sequence, data_buf90);
    ndn::ConstBufferPtr data_buf_sql = treeCache.m_database.getLeafInfo(sequence);
    BOOST_CHECK(int((*data_buf_sql)[0]) == 90);
    BOOST_CHECK(treeCache.m_database.doesLeafInfoExist(400) == false);
    // insert update
    treeCache.m_database.addLeafInfo(sequence, data_buf10);
    data_buf_sql = treeCache.m_database.getLeafInfo(sequence);
    BOOST_CHECK(int((*data_buf_sql)[0]) == 10);
  */
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace nsl
