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

#ifndef NDN_DELOREAN_TESTS_TREE_GENERATOR_HPP
#define NDN_DELOREAN_TESTS_TREE_GENERATOR_HPP

#include "sub-tree-binary.hpp"

namespace ndn {
namespace delorean {
namespace tests {

class TreeGenerator
{
public:
  static ndn::ConstBufferPtr
  getHash(const Node::Index& idx,
          const NonNegativeInteger& nextLeafSeqNo,
          bool useEmpty = true);

  static shared_ptr<SubTreeBinary>
  getSubTreeBinary(const Node::Index& index,
                   const NonNegativeInteger& nextLeafSeqNo,
                   bool useEmpty = true);

  static ndn::ConstBufferPtr
  getLeafHash();

public:
  static const Name LOGGER_NAME;

private:
  static ndn::ConstBufferPtr LEAF_HASH;
};

} // namespace tests
} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_TESTS_TREE_GENERATOR_HPP
