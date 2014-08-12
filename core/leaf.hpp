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
#ifndef NLS_CORE_LEAF_HPP
#define NLS_CORE_LEAF_HPP

#include <vector>
#include <ndn-cxx/util/crypto.hpp>
#include "node.hpp"

namespace nsl {

class Leaf : public Node
{
public:

  Leaf()
    : Node()
  {
  }


  Leaf(ndn::ConstBufferPtr data, uint64_t sequenceNumber, uint64_t level, time_t timestamp)
    : Node(sequenceNumber, level, timestamp), m_data(data)
  {
  }


  Leaf(const Leaf& new_leaf)
    : Node(new_leaf.getIndex().number, new_leaf.getIndex().level, new_leaf.getTimestamp())
  {
    m_data = new_leaf.getData();
    this->setHash(new_leaf.getHash());
  }


  ~Leaf()
  {
  }

  ndn::ConstBufferPtr
  getData() const;


  void
  computeHash();

private:
  ndn::ConstBufferPtr m_data;
};

} // namespace nsl

#endif // NLS_CORE_LEAF_HPP
