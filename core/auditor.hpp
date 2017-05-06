/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017, Regents of the University of California
 *
 * This file is part of NDN DeLorean, An Authentication System for Data Archives in
 * Named Data Networking.  See AUTHORS.md for complete list of NDN DeLorean authors
 * and contributors.
 *
 * NDN DeLorean is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * NDN DeLorean is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with NDN
 * DeLorean, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NDN_DELOREAN_CORE_AUDITOR_HPP
#define NDN_DELOREAN_CORE_AUDITOR_HPP

#include "common.hpp"
#include "node.hpp"
#include "sub-tree-binary.hpp"
#include "util/non-negative-integer.hpp"
#include <ndn-cxx/encoding/buffer.hpp>
#include <vector>

namespace ndn {
namespace delorean {

class Auditor
{
public:
  static bool
  doesExist(const NonNegativeInteger& seqNo,
            ndn::ConstBufferPtr hash,
            const NonNegativeInteger& rootNextSeqNo,
            ndn::ConstBufferPtr rootHash,
            const std::vector<shared_ptr<Data>>& proofs,
            const Name& loggerName);

  static bool
  isConsistent(const NonNegativeInteger& seqNo,
               ndn::ConstBufferPtr hash,
               const NonNegativeInteger& rootNextSeqNo,
               ndn::ConstBufferPtr rootHash,
               const std::vector<shared_ptr<Data>>& proofs,
               const Name& loggerName);

NDN_DELOREAN_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static bool
  loadProof(std::map<Node::Index, ConstSubTreeBinaryPtr>& trees,
            const std::vector<shared_ptr<Data>>& proofs,
            const Name& loggerName);
};

} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_CORE_AUDITOR_HPP
