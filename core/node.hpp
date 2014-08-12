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

#ifndef NLS_CORE_NODE_HPP
#define NLS_CORE_NODE_HPP
#include <stddef.h>
#include <time.h>

#include <ndn-cxx/util/crypto.hpp>

namespace nsl {

class Index
{
public:
  Index()
  {
  }

  Index(const Index& idx)
    : number(idx.number),
      level(idx.level)
  {
  }

  bool operator<(const Index& other) const
  {
    if (number < other.number)
      {
        return true;
      }
    else if (number == other.number)
      {
        return level < other.level;
      }
    else
      {
        return false;
      }

  }

public:
  uint64_t number;
  uint64_t level;
};


class Node
{
public:

  Node()
  {
  }


  Node(uint64_t sequenceNumber, uint64_t level, time_t timestamp);


  ~Node()
  {
  }


  const Index&
  getIndex() const;


  time_t
  getTimestamp() const;


  void
  setHash(ndn::ConstBufferPtr digest);


  ndn::ConstBufferPtr
  getHash() const;

private:
  ndn::ConstBufferPtr m_hash;
  Index m_index;   // Node index.number starts from 0 (the index of current root)
  time_t m_timeStamp;
};

} // namespace nsl

#endif // NLS_CORE_NODE_HPP
