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
#include "merkle-tree.hpp"

namespace nsl {

MerkleTree::MerkleTree()
{
  m_nLevels = 0;
  m_nLeaves = 0;
}


ConstNodePtr
MerkleTree::getNode(const Index& index)
{
  ConstNodePtr p_leav;
  if (m_cache.doesNodeExist(index))
    {
      p_leav = m_cache.queryNode(index);
      return p_leav;
    }
  else
    return p_leav;
}


uint64_t
MerkleTree::getLeafNum() const
{
  return m_nLeaves;
}


uint64_t
MerkleTree::getLevel() const
{
  return m_nLevels;
}



uint64_t
MerkleTree::addLeaf(ndn::ConstBufferPtr info)
{
  Leaf new_leaf(info, m_nLeaves, 0, 0);
  new_leaf.computeHash(); // computeHash() has been written.
  m_nLeaves++;
  if (m_nLeaves > int(pow(2, int(m_nLevels) - 1)))
    {
      m_nLevels++;
    }
  m_cache.addLeaf(new_leaf);
  return m_nLeaves - 1;
}


std::vector<ConstNodePtr>
MerkleTree::generateProof(uint64_t version1, uint64_t version2)
{
  std::vector<ConstNodePtr> proof;
  if (version1 >= version2)
    {
      return proof;
    }

  //add a memberproof from version2
  Index this_idx;
  this_idx.number = version2;
  this_idx.level = 0;
  ConstNodePtr p_leav;
  p_leav = m_cache.queryNode(this_idx);
  proof.push_back(p_leav);
  if ((this_idx.number % 2) != 0)
    {
      this_idx.number -= 1;
      p_leav = m_cache.queryNode(this_idx);
      proof.push_back(p_leav);
    }
  this_idx.level += 1;
  this_idx.number -= this_idx.number % 2;
  for (int i = 1; i < m_nLevels - 1 ; i++)
    {
      if (this_idx.number % int(pow(2, i + 1)) != 0)
        {
          this_idx.number -= int(pow(2, i));
          p_leav = m_cache.queryNode(this_idx);
          proof.push_back(p_leav);
        }
      this_idx.level += 1;
      this_idx.number -= this_idx.number % int(pow(2, i + 1));
    }

  //add another path from version1
  this_idx.number = version1;
  this_idx.level = 0;
  p_leav = m_cache.queryNode(this_idx);
  proof.push_back(p_leav);
  if ((this_idx.number % 2) != 0)
    {
      this_idx.number -= 1;
      p_leav = m_cache.queryNode(this_idx);
      proof.push_back(p_leav);
    }
  this_idx.level += 1;
  this_idx.number -= this_idx.number % 2;
  for (int i = 1; i < m_nLevels - 1 ; i++)
    {
      if (this_idx.number % int(pow(2, i + 1)) != 0)
        {
          this_idx.number -= int(pow(2, i));
          p_leav = m_cache.queryNode(this_idx);
          proof.push_back(p_leav);
        }
      this_idx.level += 1;
      this_idx.number -= this_idx.number % int(pow(2, i + 1));
    }

  return proof;
}

} // namespace nsl
