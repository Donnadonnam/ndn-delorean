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
#ifndef NLS_CORE_MERKLE_TREE_CACHE_HPP
#define NLS_CORE_MERKLE_TREE_CACHE_HPP

#include <map>
#include <vector>

#include "sub-tree.hpp"
#include "leaf.hpp"
#include "intermediate-node.hpp"
#include "merkle-tree-sqlite3.hpp"


namespace nsl {


typedef ndn::shared_ptr<const SubTree> ConstSubTreePtr;
typedef ndn::shared_ptr<SubTree> SubTreePtr;
typedef ndn::shared_ptr<const Node> ConstNodePtr;
typedef ndn::shared_ptr<Node> NodePtr;

class MerkleTreeCache
{
public:

  MerkleTreeCache()
    :m_nLevels(0),
     m_nLeaves(0)
  {
  }

  ~MerkleTreeCache()
  {
  }

  uint8_t
  getLevel()
  {
    return m_nLevels;
  }

  uint64_t
  getLeaves()
  {
    return m_nLeaves;
  }

  SubTreePtr
  getSubTree(Index rootIndex)
  {
    if (m_cachedTree.count(rootIndex) > 0)
      {
        //std::cout<<"I'm here!"<<int(m_cachedTree[rootIndex]->getRemainPosition())<<std::endl;
        return m_cachedTree[rootIndex];
      }
    else
      {
        std::string treeString = m_database.getSubTree(rootIndex);
        SubTreePtr newtree = decoding(treeString);
        return newtree;
      }
  }

  // Do the update when a subtree is full
  // Iteratively: find parent --> check full --> ... --> if not full -->
  // create subtree --> create subsubtree --> ... --> until down to the leaf
  // invoke a subtree.updateHash(), and decide whether to add new subtrees according to the callback
  // remainPosition value.
  void
  update(Index subRootIndex, uint8_t subRemainNum, ndn::ConstBufferPtr subRootHash);

  void
  addLeaf(Leaf newLeaf);

  NodePtr
  queryNode(Index nodeIndex);

  bool
  doesNodeExist(Index nodeIndex);

  void
  loadSubTreeFromDatabase(Index rootIndex);

  void
  loadLeafFromDatabase(uint64_t sequence);



  SubTreePtr
  decoding(std::string subTreeInfo);

  // remove the comment to test sqlite3 function
  // MerkleTreeSqlite3 m_database;

  // To show the exact size of the cache
  // std::map<Index, SubTreePtr> m_cachedTree;
  // std::map<uint64_t, ndn::ConstBufferPtr> m_leavesData;


private:

  // find which subTree the node belongs to (not include root node)
  Index
  findSubTree(Index nodeIndex);

  // find a subTree's parent root index
  Index
  getParentRootIndex(Index thisRootIndex);


  // To be finished
  uint8_t
  doesCacheFull()
  {
    if (m_cachedTree.size() >= 3 && m_leavesData.size() >= 64)
      {
        return 3;
      }
    else if (m_cachedTree.size() >= 3 && m_leavesData.size() < 64)
      {
        return 2;
      }
    else if (m_cachedTree.size() < 3 && m_leavesData.size() >= 64)
      {
        return 1;
      }
    else
      {
        return 0;
      }
  }

  // choose a cache item to remove,
  // exactly remove items from cache only when: 1)have full subtrees 2)cache is full
  void
  removeSubTree();

  void
  removeLeaf();

private:
  // partly in cache, completely in db
  std::map<Index, SubTreePtr> m_cachedTree;
  std::map<uint64_t, ndn::ConstBufferPtr> m_leavesData; //starts from 0(same as leaf)

  // completely in memory, add & delete with time
  std::map<Index, int> m_timeFromLastUse;
  uint8_t m_nLevels; // levels counted based on subtree unit
  uint64_t m_nLeaves; // sequence number + 1

  // sqlite3 database
  MerkleTreeSqlite3 m_database;
};

} // namespace nsl

#endif // NLS_CORE_MERKLE_TREE_CACHE_HPP
