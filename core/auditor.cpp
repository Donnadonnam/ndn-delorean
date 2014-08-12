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
#include "auditor.hpp"

namespace nsl {

ndn::ConstBufferPtr
Auditor::computeHash(ndn::ConstBufferPtr hash_l, ndn::ConstBufferPtr hash_r)
{
  ndn::Buffer tmp_buf = *hash_l;
  for (int i = 0; i < hash_r->size(); i++)
    {
      tmp_buf.push_back((*hash_r)[i]);
    }
  ndn::ConstBufferPtr digest = ndn::crypto::sha256(tmp_buf.buf(), tmp_buf.size());
  return digest;
}





ndn::ConstBufferPtr
Auditor::computeHashOneSide(ndn::ConstBufferPtr hash_l)
{
  ndn::ConstBufferPtr digest = ndn::crypto::sha256(hash_l->buf(), hash_l->size());
  return digest;
}






bool
Auditor::verifyConsistency(uint64_t version1, uint64_t version2, ndn::ConstBufferPtr hash1,
                           ndn::ConstBufferPtr hash2, std::vector<ConstNodePtr> proof)
{
  // find version2's level
  uint64_t levelVer2 = 1;
  uint64_t ver2 = version2;
  while(ver2 >= 1)
    {
      ver2 = ver2 / 2;
      levelVer2 += 1;
    }

  // compare version2's hash
  ndn::ConstBufferPtr hash_l;
  ndn::ConstBufferPtr hash_r;
  ndn::ConstBufferPtr tmp_hash;
  Index tmp_idx = proof[0]->getIndex();
  int isRight = tmp_idx.number % int(pow(2, tmp_idx.level + 1));
  if (isRight != 0)
    hash_r = proof[0]->getHash();
  else
    hash_l = proof[0]->getHash();
  uint64_t i_ = 1;
  for (; tmp_idx.level < levelVer2 - 1; )
    {
      if (isRight != 0)
        {
          hash_l = proof[i_]->getHash();
          tmp_hash = computeHash(hash_l, hash_r);
          i_++;
        }
      else
        {
          tmp_hash = computeHashOneSide(hash_l);
        }
      tmp_idx.level += 1;
      tmp_idx.number -= tmp_idx.number % int(pow(2, tmp_idx.level));
      isRight = tmp_idx.number % int(pow(2, tmp_idx.level + 1));
      if (isRight != 0)
        {
          hash_r = tmp_hash;
        }
      else
        {
          hash_l = tmp_hash;
        }
    }
  bool hash2_consis = true;
  if (isRight != 0)
    {
      for (int i = 0; i < hash_r->size() ; i++)
        {
          if ((*hash2)[i] != (*hash_r)[i])
            {
              hash2_consis = false;
              break;
            }
        }
    }
  else
    {
      for (int i = 0; i < hash_l->size() ; i++)
        {
          if ((*hash2)[i] != (*hash_l)[i])
            {
              hash2_consis = false;
              break;
            }
        }
    }




  // compare hash1
  tmp_idx = proof[i_]->getIndex();
  isRight = tmp_idx.number % int(pow(2, tmp_idx.level + 1));
  if (isRight != 0)
    hash_r = proof[i_]->getHash();
  else
    hash_l = proof[i_]->getHash();
  i_++;
  for (; i_ < proof.size(); )
    {
      if (isRight != 0)
        {
          hash_l = proof[i_]->getHash();
          tmp_hash = computeHash(hash_l, hash_r);
          i_++;
        }
      else
        {
          tmp_hash = computeHashOneSide(hash_l);
        }
      tmp_idx.level += 1;
      tmp_idx.number -= tmp_idx.number % int(pow(2, tmp_idx.level));
      isRight = tmp_idx.number % int(pow(2, tmp_idx.level + 1));
      if (isRight != 0)
        {
          hash_r = tmp_hash;
        }
      else
        {
          hash_l = tmp_hash;
        }
    }

  bool hash1_consis = true;
  if (isRight != 0)
    {
      for (int i = 0; i < hash_r->size() ; i++)
        {
          if ((*hash1)[i] != (*hash_r)[i])
            {
              hash1_consis = false;
              break;
            }
        }
    }
  else
    {
      for (int i = 0; i < hash_l->size() ; i++)
        {
          if ((*hash1)[i] != (*hash_l)[i])
            {
              hash1_consis = false;
              break;
            }
        }
    }

  return hash1_consis && hash2_consis;

}


} // namespace nsl
