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

#include <ndn-cxx/util/digest.hpp>
#include <boost/lexical_cast.hpp>

namespace nsl {

ndn::ConstBufferPtr Node::EMPTY_HASH;

Node::Index::Index(const NonNegativeInteger& nodeSeq, size_t nodeLevel)
  : seqNo(nodeSeq)
  , level(nodeLevel)
  , range(1 << nodeLevel)
{
  if (seqNo % range != 0)
    throw Error("Index: index level and seqNo do not match: (" +
                boost::lexical_cast<std::string>(seqNo) + ", " +
                boost::lexical_cast<std::string>(level) + ")");
}

bool
Node::Index::operator<(const Index& other) const
{
  if (seqNo < other.seqNo) {
    return true;
  }
  else if (seqNo == other.seqNo) {
    return level < other.level;
  }
  else {
    return false;
  }
}

bool
Node::Index::operator==(const Index& other) const
{
  return equals(other);
}

bool
Node::Index::operator!=(const Index& other) const
{
  return !equals(other);
}

bool
Node::Index::equals(const Index& other) const
{
  if (seqNo == other.seqNo && level == other.level) {
    return true;
  }
  else {
    return false;
  }
}

Node::Node(const NonNegativeInteger& nodeSeqNo,
           size_t nodeLevel,
           const NonNegativeInteger& leafSeqNo,
           ndn::ConstBufferPtr hash)
  : m_index(nodeSeqNo, nodeLevel)
  , m_hash(hash)
{
  if (leafSeqNo == 0 && m_index.seqNo > leafSeqNo)
    m_leafSeqNo = m_index.seqNo;
  else
    setLeafSeqNo(leafSeqNo);
}

void
Node::setLeafSeqNo(const NonNegativeInteger& leafSeqNo)
{
  if (leafSeqNo > m_index.seqNo + m_index.range || leafSeqNo < m_index.seqNo)
    throw Error("Node: leaf seqNo is out of range");

  m_leafSeqNo = leafSeqNo;
}

void
Node::setHash(ndn::ConstBufferPtr hash)
{
  m_hash = hash;
}

bool
Node::isFull() const
{
  return m_index.seqNo + m_index.range == m_leafSeqNo;
}

ndn::ConstBufferPtr
Node::getEmptyHash()
{
  if (EMPTY_HASH == nullptr) {
    ndn::util::Sha256 sha256;
    EMPTY_HASH = sha256.computeDigest();
  }

  return EMPTY_HASH;
}

} // namespace nsl
