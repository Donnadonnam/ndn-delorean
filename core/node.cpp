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
#include "node.hpp"

namespace nsl {

Node::Node(uint64_t sequenceNumber, uint64_t level, time_t timestamp)
{
  m_index.number = sequenceNumber;
  m_index.level = level;
  m_timeStamp = timestamp;
}


const Index&
Node::getIndex() const
{
  return m_index;
}



time_t
Node::getTimestamp() const
{
  return m_timeStamp;
}



void
Node::setHash(ndn::ConstBufferPtr digest)
{
  m_hash = digest;
}



ndn::ConstBufferPtr
Node::getHash() const
{
  return m_hash;
}

} // namespace nsl