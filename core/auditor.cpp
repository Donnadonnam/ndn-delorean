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
 * See AUTHORS.md for complete list of nsl authors and contributors.
 */

#include "auditor.hpp"

#include <ndn-cxx/util/digest.hpp>

namespace nsl {

bool
Auditor::doesExist(const NonNegativeInteger& seqNo,
                   ndn::ConstBufferPtr hash,
                   const NonNegativeInteger& rootNextSeqNo,
                   ndn::ConstBufferPtr rootHash,
                   const std::vector<shared_ptr<Data>>& proofs,
                   const Name& loggerName)
{
  BOOST_ASSERT(rootHash != nullptr);
  BOOST_ASSERT(hash != nullptr);

  std::map<Node::Index, ConstSubTreeBinaryPtr> trees;

  if (!loadProof(trees, proofs, loggerName))
    return false;

  // std::cerr << "Loaded" << std::endl;

  size_t rootLevel = 0;
  NonNegativeInteger tmpSeqNo = rootNextSeqNo - 1;
  while (tmpSeqNo != 0) {
    rootLevel++;
    tmpSeqNo = tmpSeqNo >> 1;
  }

  if (rootLevel == 0) { // only one node
    // std::cerr << "one level" << std::endl;
    if (seqNo != 0)
      return false;

    auto it = trees.find(Node::Index(0, SubTreeBinary::SUB_TREE_DEPTH - 1));
    if (it != trees.end()) {
      // std::cerr << "find subtree" << std::endl;
      auto node = it->second->getNode(Node::Index(0, 0));
      if (node != nullptr && *node->getHash() == *hash && *hash == *rootHash)
        return true;
      else
        return false;
    }
    else
      return false;
  }


  NonNegativeInteger childSeqMask = 1;
  NonNegativeInteger childSeqNo = seqNo;
  size_t childLevel = 0;
  ndn::ConstBufferPtr childHash = hash;

  NonNegativeInteger parentSeqMask = (~0) << 1;
  NonNegativeInteger parentSeqNo = childSeqNo & parentSeqMask;
  size_t parentLevel = 1;

  Node::Index treePeakIndex(0, 0);
  ConstSubTreeBinaryPtr subTree;

  do { // get parent hash
    Node::Index tmpIndex =
      SubTreeBinary::toSubTreePeakIndex(Node::Index(childSeqNo, childLevel));

    // std::cerr << "peak: " << tmpIndex.level << ", " << tmpIndex.seqNo << std::endl;
    if (tmpIndex != treePeakIndex) {
      treePeakIndex = tmpIndex;
      auto it = trees.find(treePeakIndex);
      if (it != trees.end() && it->second != nullptr) {
        subTree = it->second;
      }
      else
        return false;
    }

    // std::cerr << "Hey" << std::endl;
    // right child or left child
    ndn::util::Sha256 sha256;
    if (childSeqMask & seqNo) { // right child
      // std::cerr << "right" << std::endl;
      // std::cerr << parentSeqNo << ", " << childLevel << std::endl;
      auto leftChild = subTree->getNode(Node::Index(parentSeqNo, childLevel));
      if (leftChild == nullptr && leftChild->getHash() == nullptr)
        return false;

      // std::cerr << "found node" << std::endl;
      sha256 << parentLevel << parentSeqNo;
      sha256.update(leftChild->getHash()->buf(), leftChild->getHash()->size());
      sha256.update(childHash->buf(), childHash->size());
    }
    else { // left child
      // std::cerr << "left" << std::endl;
      ndn::ConstBufferPtr rightChildHash = Node::getEmptyHash();
      if (rootNextSeqNo > childSeqNo + (1 << childLevel)) {
        // std::cerr << childSeqNo + (1 << childLevel) << ", " << childLevel << std::endl;
        auto rightChild = subTree->getNode(Node::Index(childSeqNo + (1 << childLevel), childLevel));
        if (rightChild == nullptr || rightChild->getHash() == nullptr)
          return false;
        rightChildHash = rightChild->getHash();
        // std::cerr << "left done" << std::endl;
      }

      sha256 << parentLevel << parentSeqNo;
      sha256.update(childHash->buf(), childHash->size());
      sha256.update(rightChildHash->buf(), rightChildHash->size());
    }

    childSeqMask = childSeqMask << 1;
    childSeqNo = parentSeqNo;
    childLevel = parentLevel;
    childHash = sha256.computeDigest();

    parentSeqMask = parentSeqMask << 1;
    parentSeqNo = childSeqNo & parentSeqMask;
    parentLevel++;

  } while (childLevel < rootLevel);

  // std::cerr << "done" << std::endl;

  return (*childHash == *rootHash);
}

bool
Auditor::isConsistent(const NonNegativeInteger& oldRootNextSeqNo,
                      ndn::ConstBufferPtr oldRootHash,
                      const NonNegativeInteger& newRootNextSeqNo,
                      ndn::ConstBufferPtr newRootHash,
                      const std::vector<shared_ptr<Data>>& proofs,
                      const Name& loggerName)
{
  BOOST_ASSERT(oldRootHash != nullptr);
  BOOST_ASSERT(newRootHash != nullptr);

  if (oldRootNextSeqNo > newRootNextSeqNo)
    return false;

  std::map<Node::Index, ConstSubTreeBinaryPtr> trees;
  if (!loadProof(trees, proofs, loggerName))
    return false;

  // std::cerr << "1" << std::endl;

  // get boundary leaf:
  NonNegativeInteger leafSeqNo = oldRootNextSeqNo - 1;
  NonNegativeInteger treeSeqNo = leafSeqNo & ((~0) << (SubTreeBinary::SUB_TREE_DEPTH - 1));
  auto it = trees.find(Node::Index(treeSeqNo, SubTreeBinary::SUB_TREE_DEPTH - 1));
  if (it == trees.end())
    return false;

  auto leaf = it->second->getNode(Node::Index(leafSeqNo, 0));
  if (leaf == nullptr || leaf->getHash() == nullptr)
    return false;

  if (!doesExist(leafSeqNo, leaf->getHash(), oldRootNextSeqNo, oldRootHash,
                 proofs, loggerName))
    return false;

  // std::cerr << "2" << std::endl;

  if (oldRootNextSeqNo == newRootNextSeqNo) {
    if (*oldRootHash == *newRootHash)
      return true;
    else
      return false;
  }

  // std::cerr << "3" << std::endl;

  if (!doesExist(leafSeqNo, leaf->getHash(), newRootNextSeqNo, newRootHash,
                 proofs, loggerName))
    return false;

  // std::cerr << "4" << std::endl;

  return true;
}

bool
Auditor::loadProof(std::map<Node::Index, ConstSubTreeBinaryPtr>& trees,
                   const std::vector<shared_ptr<Data>>& proofs,
                   const Name& loggerName)
{
  try {
    for (auto proof : proofs) {
      // std::cerr << proof->getName() << std::endl;
      auto subtree =
        make_shared<SubTreeBinary>(loggerName,
                                   [] (const Node::Index& idx) {},
                                   [] (const Node::Index&,
                                       const NonNegativeInteger& seqNo,
                                       ndn::ConstBufferPtr hash) {});
      subtree->decode(*proof);

      // std::cerr << subtree->getPeakIndex().level << ", " << subtree->getPeakIndex().seqNo << std::endl;
      if (trees.find(subtree->getPeakIndex()) == trees.end())
        trees[subtree->getPeakIndex()] = subtree;
      else
        return false;
    }
  }
  catch (SubTreeBinary::Error& e) {
    // std::cerr << e.what() << std::endl;
    return false;
  }
  catch (Node::Error& e) {
    // std::cerr << e.what() << std::endl;
    return false;
  }
  catch (tlv::Error&) {
    return false;
  }

  return true;
}

} // namespace nsl
