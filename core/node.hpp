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

#ifndef NSL_CORE_NODE_HPP
#define NSL_CORE_NODE_HPP

#include "common.hpp"
#include "util/non-negative-integer.hpp"
#include <ndn-cxx/encoding/buffer.hpp>

namespace nsl {

class Node
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  class Index
  {
  public:
    explicit
    Index(const NonNegativeInteger& seqNo = 0, size_t level = 0);

    /**
     * @brief compare two indices
     *
     * A index is larger than the other if its seqNo is larger than the other,
     * or their seqNos are equal but its level is lower.
     */
    bool
    operator<(const Index& other) const;

    bool
    operator==(const Index& other) const;

    bool
    operator!=(const Index& other) const;

    bool
    equals(const Index& other) const;

  public:
    NonNegativeInteger seqNo;
    size_t level;
    NonNegativeInteger range;
  };

public:
  Node(const NonNegativeInteger& seqNo,
       size_t level,
       const NonNegativeInteger& leafSeqNo = 0,
       ndn::ConstBufferPtr hash = nullptr);

  const Index&
  getIndex() const
  {
    return m_index;
  }

  void
  setLeafSeqNo(const NonNegativeInteger& leafSeqNo);

  const NonNegativeInteger&
  getLeafSeqNo() const
  {
    return m_leafSeqNo;
  }

  void
  setHash(ndn::ConstBufferPtr hash);

  ndn::ConstBufferPtr
  getHash() const
  {
    return m_hash;
  }

  bool
  isFull() const;

  static ndn::ConstBufferPtr
  getEmptyHash();

protected:
  Index m_index;
  NonNegativeInteger m_leafSeqNo;
  ndn::ConstBufferPtr m_hash;

private:
  static ndn::ConstBufferPtr EMPTY_HASH;
};

typedef shared_ptr<Node> NodePtr;
typedef shared_ptr<const Node> ConstNodePtr;

} // namespace nsl

#endif // NSL_CORE_NODE_HPP
