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
#ifndef NLS_CORE_SUB_TREE_CACHE_HPP
#define NLS_CORE_SUB_TREE_CACHE_HPP

#include <ndn-cxx/encoding/buffer.hpp>
#include <stdint.h>
#include <string.h>

#include "node.hpp"

namespace nsl {

typedef ndn::function<void(uint8_t, ndn::ConstBufferPtr)> CallBack;

class SubTree
{
public:
  SubTree()
  {
  }

  SubTree(Index rootIndex, CallBack callBackFunction)
    : m_root(rootIndex),
      m_remainPosition(64),
      m_callBackUpdate(callBackFunction)
  {
    for (int i = 0; i < 127; i++)
      {
        m_nodeHashes.push_back(ndn::BufferPtr(new ndn::Buffer));
      }
  }

  ~SubTree()
  {
  }

  void
  addNode(ndn::ConstBufferPtr hash_ptr);

  Index
  getRootIndex();

  uint8_t
  getRemainPosition();

  Index
  getParentRootIndex();

  ndn::ConstBufferPtr
  getHash(Index nodeIndex);

  // change when subtree's root hash below it changes
  void
  updateLeafHash(Index subRootIndex, ndn::ConstBufferPtr hash);


  // decode is implemented in MerkleTreeCache class
  std::string
  encoding();

  void
  resumeFromString(uint8_t remain, std::vector<ndn::BufferPtr> hashes);

private:

  void
  updateHash();


private:

  //Based on the following sequence number
  //         0
  //    1          2
  //  3   4     5     6
  // 7 8 9 10 11 12 13 14
  std::vector<ndn::BufferPtr> m_nodeHashes;
  Index m_root;
  uint8_t m_remainPosition;
  CallBack m_callBackUpdate;
};


} // namespace nsl

#endif // NLS_CORE_SUB_TREE_CACHE_HPP
