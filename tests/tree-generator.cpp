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

#include "tree-generator.hpp"
#include <ndn-cxx/util/digest.hpp>

namespace nsl {
namespace tests {

const Name TreeGenerator::LOGGER_NAME("/logger/name");
ndn::ConstBufferPtr TreeGenerator::LEAF_HASH;

ndn::ConstBufferPtr
TreeGenerator::getHash(const Node::Index& idx,
                       const NonNegativeInteger& nextLeafSeqNo,
                       bool useEmpty)
{
  if (idx.level == 0) {
    if (useEmpty)
      return Node::getEmptyHash();

    return Node::getEmptyHash();
  }

  NonNegativeInteger leftChildSeqNo = idx.seqNo;
  NonNegativeInteger rightChildSeqNo = idx.seqNo + (idx.range >> 1);

  if (idx.seqNo == 0 && nextLeafSeqNo <= rightChildSeqNo) {
    BOOST_ASSERT(false);
  }

  ndn::util::Sha256 sha256;
  sha256 << idx.level << idx.seqNo;

  auto hash1 = getHash(Node::Index(leftChildSeqNo, idx.level - 1),
                       nextLeafSeqNo,
                       useEmpty);
  sha256.update(hash1->buf(), hash1->size());

  if (nextLeafSeqNo > rightChildSeqNo) {
    auto hash2 = getHash(Node::Index(rightChildSeqNo, idx.level - 1),
                         nextLeafSeqNo,
                         useEmpty);
    sha256.update(hash2->buf(), hash2->size());
  }
  else {
    auto hash2 = Node::getEmptyHash();
    sha256.update(hash2->buf(), hash2->size());
  }
  return sha256.computeDigest();
}

shared_ptr<SubTreeBinary>
TreeGenerator::getSubTreeBinary(const Node::Index& index,
                                const NonNegativeInteger& nextLeafSeqNo,
                                bool useEmpty)
{
  auto subtree = make_shared<SubTreeBinary>(LOGGER_NAME, index,
                                            [&] (const Node::Index&) {},
                                            [&] (const Node::Index&,
                                                 const NonNegativeInteger&,
                                                 ndn::ConstBufferPtr) {});

  size_t leafLevel = index.level + 1 - SubTreeBinary::SUB_TREE_DEPTH;
  NonNegativeInteger step = 1 << leafLevel;

  for (NonNegativeInteger i = index.seqNo; i < nextLeafSeqNo - step; i += step) {
    auto node = make_shared<Node>(i, leafLevel, i + step,
                                  getHash(Node::Index(i, leafLevel),
                                          i + step,
                                          useEmpty));
    subtree->addLeaf(node);
  }

  NonNegativeInteger childSeqNo = ((nextLeafSeqNo - 1) >> leafLevel) << leafLevel;
  auto node = make_shared<Node>(childSeqNo, leafLevel, nextLeafSeqNo,
                                getHash(Node::Index(childSeqNo, leafLevel),
                                        nextLeafSeqNo,
                                        useEmpty));
  subtree->addLeaf(node);

  return subtree;
}

ndn::ConstBufferPtr
TreeGenerator::getLeafHash()
{
  if (LEAF_HASH == nullptr) {
    ndn::util::Sha256 sha256;
    sha256 << 1;
    LEAF_HASH = sha256.computeDigest();
  }

  return LEAF_HASH;
}

} // namespace tests
} // namespace nsl
