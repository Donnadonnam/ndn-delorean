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
#ifndef NLS_CORE_AUDITOR_HPP
#define NLS_CORE_AUDITOR_HPP

#include <string>
#include <vector>

#include <math.h>
#include <stdint.h>

#include <ndn-cxx/util/crypto.hpp>

#include "node.hpp"

namespace nsl {

typedef ndn::shared_ptr<const Node> ConstNodePtr;
typedef ndn::shared_ptr<Node> NodePtr;

class Auditor
{
public:
  Auditor()
  {
  }


  ~Auditor()
  {
  }


  bool
  verifyConsistency(uint64_t version1, uint64_t version2, ndn::ConstBufferPtr hash1,
                    ndn::ConstBufferPtr hash2, std::vector<ConstNodePtr> proof);


  std::vector<Node*>
  queryByTime(time_t);

  ndn::ConstBufferPtr
  computeHash(ndn::ConstBufferPtr hash_l, ndn::ConstBufferPtr hash_r);


  ndn::ConstBufferPtr
  computeHashOneSide(ndn::ConstBufferPtr hash_l);


private:

};

} // namespace nsl

#endif // NLS_CORE_AUDITOR_HPP
