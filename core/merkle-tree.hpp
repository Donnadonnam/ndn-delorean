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
#ifndef NLS_CORE_MERKLE_TREE_HPP
#define NLS_CORE_MERKLE_TREE_HPP

#include <map>
#include <vector>

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "leaf.hpp"
#include "intermediate-node.hpp"
#include "merkle-tree-cache.hpp"

namespace nsl {

class MerkleTree
{
public:
  MerkleTree();

  ~MerkleTree()
  {
  }

  ConstNodePtr
  getNode(const Index& index);

  uint64_t
  getLeafNum() const;

  uint64_t
  getLevel() const;


  //return root hash value
  uint64_t
  addLeaf(ndn::ConstBufferPtr info);


  std::vector<ConstNodePtr>
  generateProof(uint64_t version1, uint64_t version2); // version equals to leaf's index number


private:
  MerkleTreeCache m_cache;
  uint64_t m_nLevels;
  uint64_t m_nLeaves;

};


} // namespace nsl

#endif // NLS_CORE_MERKLE_TREE_HPP
