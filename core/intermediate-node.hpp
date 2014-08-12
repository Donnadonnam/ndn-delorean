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
#ifndef NLS_CORE_INTERMEDIATE_NODE_HPP
#define NLS_CORE_INTERMEDIATE_NODE_HPP

#include <stddef.h>
#include <math.h>
#include <ndn-cxx/util/crypto.hpp>
#include "node.hpp"


namespace nsl {


class IntermediateNode : public Node
{
public:

  IntermediateNode()
    : Node()
  {
  }

  IntermediateNode(uint64_t sequenceNumber, uint64_t level, time_t timestamp)
    : Node(sequenceNumber, level, timestamp), m_isFull(false)
  {
  }

  IntermediateNode(const IntermediateNode& new_node)
    :Node(new_node.getIndex().number, new_node.getIndex().level, 0)
  {
    m_isFull = new_node.isFull();
    this->setHash(new_node.getHash());
  }

  ~IntermediateNode()
  {
  }

  bool
  setIsFull(uint64_t totalLeafNum);

  bool
  isFull() const;

  void
  computeHash(ndn::ConstBufferPtr hash_l, ndn::ConstBufferPtr hash_r);

  void
  computeHashOneSide(ndn::ConstBufferPtr hash_l);

private:
  bool m_isFull;
};

} // namespace nsl

#endif // NLS_CORE_INTERMEDIATE_NODE_HPP
