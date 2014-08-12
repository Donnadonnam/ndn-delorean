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
#include <stdint.h>
#include <iostream>
#include <boost-test.hpp>

#include "leaf.hpp"
#include "intermediate-node.hpp"

namespace nsl {


BOOST_AUTO_TEST_SUITE(NodeTest)


BOOST_AUTO_TEST_CASE(LeafTest)
{
  //Test the constructor & getFunc
  Index idx;
  idx.number = 1;
  idx.level = 0;
  ndn::Buffer buffer;
  for (int i = 0; i < 10; i++)
    {
      buffer.push_back(i + 65); // from A to J
    }
  ndn::ConstBufferPtr p_buf = boost::make_shared<const ndn::Buffer>(buffer);
  Leaf leaf_node(p_buf, idx.number, idx.level, 0);
  BOOST_CHECK(leaf_node.getIndex().number == 1);
  BOOST_CHECK(leaf_node.getIndex().level == 0);
  ndn::ConstBufferPtr data = leaf_node.getData();
  for (int i = 0; i < data->size(); i++)
    {
      std::cout<<(*data)[i]<<' ';
    }
  std::cout<<"Data Finished"<<std::endl;
  //Test hash computation
  leaf_node.computeHash();
  ndn::ConstBufferPtr hash = leaf_node.getHash();
  for (int i = 0; i < hash->size(); i++)
    {
      std::cout<<int((*hash)[i])<<' ';
    }
  std::cout<<"Hash Finished"<<std::endl;
}

BOOST_AUTO_TEST_CASE(IntermediateNodeTest)
{
  //Test update full condition
  IntermediateNode inter_node(2,1,0);
  inter_node.setIsFull(4);
  BOOST_CHECK(inter_node.isFull() == true);
  inter_node.setIsFull(2);
  BOOST_CHECK(inter_node.isFull() == false);
}

BOOST_AUTO_TEST_SUITE_END()



} // namespace nsl
