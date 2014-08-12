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

#include "sub-tree.hpp"
#include "Auditor.hpp"
#include <math.h>


namespace nsl {

void
SubTree::addNode(ndn::ConstBufferPtr hash_ptr)
{
  if(m_remainPosition > 0)
    {
      uint8_t seqNo = 127 - m_remainPosition;
      m_nodeHashes[seqNo] = ndn::make_shared<ndn::Buffer>(*hash_ptr);
      m_remainPosition -= 1;
      updateHash();
    }
}

void
SubTree::updateHash()
{
  uint8_t i_ = 6;
  uint8_t lastNo = 126 - m_remainPosition;
  for (; i_ > 0; i_--)
    {
      for (int i = int(pow(2, i_)) - 1; i <= lastNo; i+= 2)
        {
          if ((i + 1) <= lastNo)
            {
              uint8_t up_idx = (i-1) / 2;
              Auditor hasher;
              ndn::ConstBufferPtr buf = hasher.computeHash(m_nodeHashes[i],
                                                           m_nodeHashes[i + 1]);
              m_nodeHashes[up_idx] = ndn::make_shared<ndn::Buffer>(*buf);
            }
          else
            {
              uint8_t up_idx = (i-1) / 2;
              Auditor hasher;
              ndn::ConstBufferPtr buf = hasher.computeHashOneSide(m_nodeHashes[i]);
              m_nodeHashes[up_idx] = ndn::make_shared<ndn::Buffer>(*buf);
            }
        }
      lastNo = (lastNo - 1) / 2;
    }
  m_callBackUpdate(m_remainPosition, m_nodeHashes[0]);
}




void
SubTree::updateLeafHash(Index subRootIndex, ndn::ConstBufferPtr hash)
{
  uint8_t lastNo = 126 - m_remainPosition;
  uint64_t sequenceNo = subRootIndex.number;
  uint64_t level = subRootIndex.level;
  uint8_t indexBase = int(pow(2, m_root.level - level) - 1);
  uint8_t indexOffset = (sequenceNo - m_root.number) / int(pow(2, level));
  m_nodeHashes[indexBase + indexOffset] = ndn::make_shared<ndn::Buffer>(*hash);
  if (lastNo < indexBase + indexOffset) // update value ? add new value
    {
      m_remainPosition -= 1;
    }
  updateHash();
}

ndn::ConstBufferPtr
SubTree::getHash(Index nodeIndex)
{
  uint64_t sequenceNo = nodeIndex.number;
  uint64_t level = nodeIndex.level;
  uint8_t indexBase = int(pow(2, m_root.level - level) - 1);
  uint8_t indexOffset = (sequenceNo - m_root.number) / int(pow(2, level));
  return m_nodeHashes[indexBase + indexOffset];
}




Index
SubTree::getRootIndex()
{
  return m_root;
}

uint8_t
SubTree::getRemainPosition()
{
  return m_remainPosition;
}

Index
SubTree::getParentRootIndex()
{
  Index parentIndex;
  parentIndex.number = m_root.number;
  parentIndex.level = m_root.level;
  for (int i = 0; i < 6; i++)
    {
      parentIndex.number -= parentIndex.number%int(pow(2, parentIndex.level + 1));
      parentIndex.level += 1;
    }
  return parentIndex;
}



std::string
SubTree::encoding()
{
  std::string subTreeInfo = "";
  uint64_t seq = m_root.number;
  uint64_t lev = m_root.level;
  unsigned char div_seq[8];
  unsigned char div_lev[8];
  for (int i = 0; i < 8; i++)
    {
      div_seq[i] = (seq >> (8*i)) & 0xFF;
      div_lev[i] = (lev >> (8*i)) & 0xFF;
    }
  for (int i = 0; i < 8; i++)
    {
      subTreeInfo += div_seq[i];
    }
  for (int i = 0; i < 8; i++)
    {
      subTreeInfo += div_lev[i];
    }
  subTreeInfo += m_remainPosition;
  for (int i = 0; i < 127; i++)
    {
      for (int j = 0; j < m_nodeHashes[i]->size(); j++)
        {
          subTreeInfo += (*m_nodeHashes[i])[j];
        }
      uint8_t flag = 0;
      for (int j = m_nodeHashes[i]->size(); j < 32; j++)
        {
          subTreeInfo += flag;
        }
    }
  return subTreeInfo;
}

void
SubTree::resumeFromString(uint8_t remain, std::vector<ndn::BufferPtr> hashes)
{
  m_remainPosition = remain;
  if (remain == 0)
    {
      for (int i = 0; i < hashes.size(); i++)
        {
          m_nodeHashes[i] = hashes[i];
        }
    }
  else
    {
      for (int i = 0; i < hashes.size(); i++)
        {
          m_nodeHashes[63 + i] = hashes[i];
        }
      uint8_t i_ = 6;
      uint8_t lastNo = 126 - m_remainPosition;
      for (; i_ > 0; i_--)
        {
          for (int i = int(pow(2, i_)) - 1; i <= lastNo; i+= 2)
            {
              if ((i + 1) <= lastNo)
                {
                  uint8_t up_idx = (i-1) / 2;
                  Auditor hasher;
                  ndn::ConstBufferPtr buf = hasher.computeHash(m_nodeHashes[i],
                                                               m_nodeHashes[i + 1]);
                  m_nodeHashes[up_idx] = ndn::make_shared<ndn::Buffer>(*buf);
                }
              else
                {
                  uint8_t up_idx = (i-1) / 2;
                  Auditor hasher;
                  ndn::ConstBufferPtr buf = hasher.computeHashOneSide(m_nodeHashes[i]);
                  m_nodeHashes[up_idx] = ndn::make_shared<ndn::Buffer>(*buf);
                }
            }
          lastNo = (lastNo - 1) / 2;
        }
    }
}


} // namespace nsl
