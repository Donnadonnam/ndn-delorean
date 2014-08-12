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
#include "intermediate-node.hpp"

namespace nsl {

bool
IntermediateNode::isFull() const
{
  return m_isFull;
}



bool
IntermediateNode::setIsFull(uint64_t number)
{
  Index info = this->getIndex();
  uint64_t num = info.number;
  uint64_t lev = info.level;
  if (double(num) + pow(2, lev) <= number)
    {
      m_isFull = true;
      return m_isFull;
    }
  else
    {
      m_isFull = false;
      return m_isFull;
    }

}



void
IntermediateNode::computeHash(ndn::ConstBufferPtr hash_l, ndn::ConstBufferPtr hash_r)
{
  ndn::Buffer tmp_buf = *hash_l;
  for (int i = 0; i < hash_r->size(); i++)
    {
      tmp_buf.push_back((*hash_r)[i]);
    }
  ndn::ConstBufferPtr digest = ndn::crypto::sha256(tmp_buf.buf(), tmp_buf.size());
  this->setHash(digest);
}

void IntermediateNode::computeHashOneSide(ndn::ConstBufferPtr hash_l)
{
  ndn::ConstBufferPtr digest = ndn::crypto::sha256(hash_l->buf(), hash_l->size());
  this->setHash(digest);
}

} // namespace nsl
