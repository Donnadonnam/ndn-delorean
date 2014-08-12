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

#include "merkle-tree-cache.hpp"



namespace nsl {

typedef std::map<Index, int>::iterator tree_iter;
typedef std::map<uint64_t, ndn::ConstBufferPtr>::iterator leaf_iter;

Index
MerkleTreeCache::findSubTree(Index nodeIndex)
{
  if(nodeIndex.level % 6 == 0 && nodeIndex.level != 0)
    {
      return nodeIndex;
    }
  else
    {
      uint8_t step = (uint64_t(nodeIndex.level / 6) + 1) * 6 - nodeIndex.level;
      for (int i = 0; i < step; i++)
        {
          nodeIndex.number -= nodeIndex.number % int(pow(2, nodeIndex.level + 1));
          nodeIndex.level += 1;
        }
      return nodeIndex;
    }
}

Index
MerkleTreeCache::getParentRootIndex(Index thisRootIndex)
{
  Index parentIndex;
  parentIndex.number = thisRootIndex.number;
  parentIndex.level = thisRootIndex.level;
  for (int i = 0; i < 6; i++)
    {
      parentIndex.number -= parentIndex.number%int(pow(2, parentIndex.level + 1));
      parentIndex.level += 1;
    }
  return parentIndex;
}


void
MerkleTreeCache::removeSubTree()
{
  if (doesCacheFull() > 1)
    {
      // find out the least recent used subtree
      tree_iter _i = m_timeFromLastUse.begin();
      int idle_time_max = -1;
      Index rm_index_max = _i->first;
      int idle_time_min = _i->second;
      Index rm_index_min = _i->first;
      for (_i = m_timeFromLastUse.begin(); _i != m_timeFromLastUse.end(); _i++)
        {
          if (_i->second > idle_time_max && m_cachedTree[_i->first]->getRemainPosition() == 0)
            {
              idle_time_max = _i->second;
              rm_index_max = _i->first;
            }
          if (_i->second < idle_time_min)
            {
              idle_time_min = _i->second;
              rm_index_min = _i->first;
            }
        }

      // refresh the timer
      for (_i = m_timeFromLastUse.begin(); _i != m_timeFromLastUse.end(); _i++)
        {
          _i->second -= idle_time_min;
        }
      // update to database and remove subtree from cache and timer,only when there is full subtree
      if (m_cachedTree[rm_index_max]->getRemainPosition() == 0 && idle_time_max >= 0)
        {
          m_database.addSubTree(m_cachedTree[rm_index_max]);
          m_cachedTree.erase(rm_index_max);
          m_timeFromLastUse.erase(rm_index_max);
        }
    }
}

void
MerkleTreeCache::removeLeaf()
{
  if (doesCacheFull() % 2 != 0)
    {
      // randomly pick a old leaf to remove
      leaf_iter _i = m_leavesData.begin();
      while (_i->first == m_nLeaves - 1)
        {
          _i++;
        }
      m_database.addLeafInfo(_i->first, _i->second);
      m_leavesData.erase(_i->first);
    }
}





// Do not have to deal with NOT-IN-MEMORY issue because not full tree will not in database
void
MerkleTreeCache::addLeaf(Leaf newLeaf)
{
  ndn::ConstBufferPtr data = newLeaf.getData();
  removeLeaf(); // test whether is full, if so, delete an old item
  m_leavesData[newLeaf.getIndex().number] = data;
  Index leafIndex = newLeaf.getIndex();
  ndn::ConstBufferPtr hash = newLeaf.getHash();

  Index subTreeRoot = findSubTree(leafIndex);
  if (m_nLeaves > 0)
    {
      // Not full so that always in memory
      m_cachedTree[subTreeRoot]->addNode(hash);
      m_nLeaves += 1;
    }
  else
    {
      SubTreePtr newTree(new SubTree(subTreeRoot,
                                     ndn::bind(&MerkleTreeCache::update, this,
                                               subTreeRoot, _1, _2)));
      newTree->addNode(hash);
      removeSubTree();
      m_cachedTree[subTreeRoot] = newTree;
      m_nLeaves = 1;
      m_nLevels = 1;
    }

  for (tree_iter _i = m_timeFromLastUse.begin(); _i != m_timeFromLastUse.end(); _i++)
    {
      _i->second += 1;
    }
  m_timeFromLastUse[subTreeRoot] = 0; // if not exist, automatically create one and set to 0
}


// Deal with loading from database
// database update
// consider add to database when a subtree is full
void
MerkleTreeCache::update(Index subRootIndex, uint8_t subRemainNum, ndn::ConstBufferPtr subRootHash)
{
  if ((subRootIndex.level / 6) < m_nLevels)
    {
      Index parentRoot = getParentRootIndex(subRootIndex);

      // bring in memory if parentRoot not in
      if (m_cachedTree.count(parentRoot) <= 0)
        {
          loadSubTreeFromDatabase(parentRoot);
        }
      m_cachedTree[parentRoot]->updateLeafHash(subRootIndex, subRootHash);
      m_timeFromLastUse[parentRoot] = 0;
    }

  if (subRemainNum == 0) // add the current full subtree into the database
    {
      Index parentRoot = getParentRootIndex(subRootIndex);
      if ((subRootIndex.level / 6) >= m_nLevels) // if it is the top subtree
        {
          SubTreePtr newTree(new SubTree(parentRoot,
                                         ndn::bind(&MerkleTreeCache::update, this,
                                                   parentRoot, _1, _2)));
          removeSubTree();
          m_cachedTree[parentRoot] = newTree;
          m_nLevels += 1;
          m_timeFromLastUse[parentRoot] = 0;
          m_cachedTree[parentRoot]->updateLeafHash(subRootIndex, subRootHash);
        }
      Index newRoot;
      newRoot.level = subRootIndex.level;
      newRoot.number = subRootIndex.number + int(pow(2, subRootIndex.level));
      // whether the updated subtree is already full,
      // but its child subtree is not full.
      // To avoid create multiple sibling new subtree
      if (m_cachedTree.count(newRoot) == 0)
        {
          SubTreePtr newTree(new SubTree(newRoot,
                                         ndn::bind(&MerkleTreeCache::update, this,
                                                   newRoot, _1, _2)));
          removeSubTree();
          m_cachedTree[newRoot] = newTree;
          m_timeFromLastUse[newRoot] = 0;
        }
    }
}


NodePtr
MerkleTreeCache::queryNode(Index nodeIndex)
{
  // update timer
  for (tree_iter _i = m_timeFromLastUse.begin(); _i != m_timeFromLastUse.end(); _i++)
    {
      _i->second += 1;
    }

  Index rootIndex = findSubTree(nodeIndex);
  ndn::ConstBufferPtr hash;
  if (m_cachedTree.count(rootIndex) == 0)
    {
      loadSubTreeFromDatabase(rootIndex);
    }
  hash = m_cachedTree[rootIndex]->getHash(nodeIndex);

  if (nodeIndex.level == 0)
    {
      if (m_leavesData.count(nodeIndex.number) == 0)
        {
          loadLeafFromDatabase(nodeIndex.number);
        }
      NodePtr node_ptr(new Leaf(m_leavesData[nodeIndex.number],
                                nodeIndex.number, nodeIndex.level, 0));
      node_ptr->setHash(hash);
      return node_ptr;
    }
  else
    {
      NodePtr node_ptr(new IntermediateNode(nodeIndex.number, nodeIndex.level, 0));
      node_ptr->setHash(hash);
      ((IntermediateNode*)node_ptr.get())->setIsFull(m_nLeaves);
      return node_ptr;
    }
}


bool
MerkleTreeCache::doesNodeExist(Index nodeIndex)
{
  Index rootIndex = findSubTree(nodeIndex);
  if (m_cachedTree.count(rootIndex) > 0)
    {
      return true;
    }
  else
    {
      bool result = m_database.doesSubTreeExist(rootIndex);
      return result;
    }
}



SubTreePtr
MerkleTreeCache::decoding(std::string subTreeInfo)
{
  uint64_t seq = 0;
  unsigned char tmp = 0;
  for (int i = 7; i >= 0; i--)
    {
      tmp = subTreeInfo[i];
      seq += tmp;
      seq = seq << 8;
    }
  seq = seq >> 8;
  uint64_t lev = 0;
  for (int i = 15; i >= 8; i--)
    {
      tmp = subTreeInfo[i];
      lev += tmp;
      lev = lev << 8;
    }
  lev = lev >> 8;
  Index rootIndex;
  rootIndex.number = seq;
  rootIndex.level = lev;
  SubTreePtr newTree(new SubTree(rootIndex,
                                 ndn::bind(&MerkleTreeCache::update, this,
                                           rootIndex, _1, _2)));
  uint8_t remain = subTreeInfo[16]; // not useful
  if (remain == 0)
    {
      std::vector<ndn::BufferPtr> hashes;
      for (int i = 0; i < 127; i++)
        {
          ndn::Buffer buf;
          for(int j = 17 + 32 * i; j < 49 + 32 * i; j++)
            {
              buf.push_back(subTreeInfo[j]);
            }
          ndn::BufferPtr thisBuf = ndn::make_shared<ndn::Buffer>(buf);
          hashes.push_back(thisBuf);
        }
      newTree->resumeFromString(remain, hashes);
      return newTree;
    }
  else
    {
      std::vector<ndn::BufferPtr> hashes;
      uint8_t lastNo = 126 - remain;
      for (int i = 63; i <= lastNo; i++)
        {
          ndn::Buffer buf;
          for(int j = 17 + 32 * i; j < 49 + 32 * i; j++)
            {
              buf.push_back(subTreeInfo[j]);
            }
          ndn::BufferPtr thisBuf = ndn::make_shared<ndn::Buffer>(buf);
          hashes.push_back(thisBuf);
        }
      newTree->resumeFromString(remain, hashes);
      return newTree;
    }
}


void
MerkleTreeCache::loadSubTreeFromDatabase(Index rootIndex)
{
  // Detect the cache limitation
  removeSubTree();
  std::string tmp_str = m_database.getSubTree(rootIndex);
  SubTreePtr newtree = decoding(tmp_str);
  m_cachedTree[rootIndex] = newtree;
  m_timeFromLastUse[rootIndex] = 0;
}

void
MerkleTreeCache::loadLeafFromDatabase(uint64_t sequence)
{
  // Detect the cache limitation
  removeLeaf();
  ndn::ConstBufferPtr newleaf = m_database.getLeafInfo(sequence);
  m_leavesData[sequence] = newleaf;
}


} // namespace nsl
