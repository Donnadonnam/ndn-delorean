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

#include "merkle-tree.hpp"

namespace nsl {

MerkleTree::MerkleTree(Db& db)
  : m_db(db)
  , m_nextLeafSeqNo(0)
{
}

MerkleTree::MerkleTree(const Name& loggerName, Db& db)
  : m_loggerName(loggerName)
  , m_db(db)
  , m_nextLeafSeqNo(0)
{
  loadPendingSubTrees();
}

MerkleTree::~MerkleTree()
{
  savePendingTree();
}

void
MerkleTree::setLoggerName(const Name& loggerName)
{
  m_loggerName = loggerName;
}

bool
MerkleTree::addLeaf(const NonNegativeInteger& seqNo, ndn::ConstBufferPtr hash)
{
  auto baseTree = m_pendingTrees[SubTreeBinary::SUB_TREE_DEPTH - 1];
  BOOST_ASSERT(baseTree != nullptr);

  NodePtr leaf = make_shared<Node>(seqNo, 0, seqNo + 1, hash);
  return baseTree->addLeaf(leaf);
}

void
MerkleTree::savePendingTree()
{
  size_t level = m_rootSubTree->getPeakIndex().level;
  size_t step = SubTreeBinary::SUB_TREE_DEPTH - 1;

  for (size_t i = level; i > 0; i -= step) {
    auto pendingTree = m_pendingTrees[i];
    BOOST_ASSERT(pendingTree != nullptr);

    auto data = pendingTree->encode();
    if (data != nullptr) {
      m_db.insertSubTreeData(pendingTree->getPeakIndex().level, pendingTree->getPeakIndex().seqNo,
                             *data, false, pendingTree->getNextLeafSeqNo());
    }
  }
}

shared_ptr<Data>
MerkleTree::getPendingSubTreeData(size_t level)
{
  auto it = m_pendingTrees.find(level);
  if (it != m_pendingTrees.end())
    return it->second->encode();
  else
    return nullptr;
}

// private:
void
MerkleTree::loadPendingSubTrees()
{
  std::vector<shared_ptr<Data>> subtreeDatas = m_db.getPendingSubTrees();

  shared_ptr<SubTreeBinary> subtree;
  if (subtreeDatas.empty()) {
    subtree = make_shared<SubTreeBinary>(m_loggerName,
      Node::Index(0, SubTreeBinary::SUB_TREE_DEPTH - 1),
      [this] (const Node::Index& idx) {
        // std::cerr << "complete: " << idx.level << ", " << idx.seqNo << std::endl;
        this->getNewRoot(idx);
      },
      [this] (const Node::Index& idx,
              const NonNegativeInteger& seqNo,
              ndn::ConstBufferPtr hash) {
        // std::cerr << "update: " << idx.level << ", " << idx.seqNo << std::endl;
        // std::cerr << "seqNo: " << seqNo << std::endl;
        this->m_nextLeafSeqNo = seqNo;
        this->m_hash = hash;
      });
    m_pendingTrees[SubTreeBinary::SUB_TREE_DEPTH - 1] = subtree;
    m_rootSubTree = subtree;
    return;
  }

  subtree = make_shared<SubTreeBinary>(m_loggerName,
    [this] (const Node::Index& idx) { this->getNewRoot(idx); },
    [this] (const Node::Index& idx,
            const NonNegativeInteger& seqNo,
            ndn::ConstBufferPtr hash) {
      this->m_nextLeafSeqNo = seqNo;
      this->m_hash = hash;
    });

  subtree->decode(*subtreeDatas[0]);
  m_pendingTrees[subtree->getPeakIndex().level] = subtree;
  m_rootSubTree = subtree;

  shared_ptr<SubTreeBinary> parentTree = subtree;
  for (size_t i = 1; i < subtreeDatas.size(); i++) {
    subtree = make_shared<SubTreeBinary>(m_loggerName,
      [this] (const Node::Index& idx) {
        this->getNewSibling(idx);
      },
      [parentTree] (const Node::Index&,
           const NonNegativeInteger& seqNo,
           ndn::ConstBufferPtr hash) {
        parentTree->updateLeaf(seqNo, hash);
      });

    subtree->decode(*subtreeDatas[i]);
    if (parentTree->getPeakIndex().level + 1 - SubTreeBinary::SUB_TREE_DEPTH !=
        subtree->getPeakIndex().level)
      throw Error("loadPendingSubTrees: inconsistent pending subtree level");

    if (parentTree->getNextLeafSeqNo() != subtree->getNextLeafSeqNo())
      throw Error("loadPendingSubTrees: inconsistent pending subtree next leaf seqNo");

    m_pendingTrees[subtree->getPeakIndex().level] = subtree;
    parentTree = subtree;
  }
}

void
MerkleTree::getNewRoot(const Node::Index& idx)
{
  // save the old root tree into db
  auto oldRoot = m_pendingTrees[idx.level];
  BOOST_ASSERT(oldRoot != nullptr);
  m_db.insertSubTreeData(idx.level, idx.seqNo, *oldRoot->encode());

  // create a new root tree
  Node::Index newRootIdx(0, idx.level + SubTreeBinary::SUB_TREE_DEPTH - 1);
  auto newRoot = make_shared<SubTreeBinary>(m_loggerName, newRootIdx,
    [this] (const Node::Index& idx) {
      // std::cerr << "complete: " << idx.level << ", " << idx.seqNo << std::endl;
      this->getNewRoot(idx);
    },
    [this] (const Node::Index& index,
         const NonNegativeInteger& seqNo,
         ndn::ConstBufferPtr hash) {
      // std::cerr << "update: " << index.level << ", " << index.seqNo << std::endl;
      // std::cerr << "seqNo: " << seqNo << std::endl;
      this->m_nextLeafSeqNo = seqNo;
      this->m_hash = hash;
    });

  m_pendingTrees[newRoot->getPeakIndex().level] = newRoot;
  m_rootSubTree = newRoot;

  bool result = newRoot->updateLeaf(idx.seqNo + idx.range, oldRoot->getRoot()->getHash());
  BOOST_ASSERT(result);

  // create a sibling
  getNewSibling(idx);
}

void
MerkleTree::getNewSibling(const Node::Index& idx)
{
  // save old sibling
  auto oldSibling = m_pendingTrees[idx.level];
  BOOST_ASSERT(oldSibling != nullptr);
  m_db.insertSubTreeData(idx.level, idx.seqNo, *oldSibling->encode());

  // get parent tree
  Node::Index parentIdx(0, idx.level + SubTreeBinary::SUB_TREE_DEPTH - 1);
  auto parent = m_pendingTrees[parentIdx.level];
  BOOST_ASSERT(parent != nullptr);

  // create a new sibling
  Node::Index newSiblingIdx(idx.seqNo + idx.range, idx.level);
  // std::cerr << "new Sibling: " << newSiblingIdx.level << ", " << newSiblingIdx.seqNo << std::endl;
  auto newSibling = make_shared<SubTreeBinary>(m_loggerName, newSiblingIdx,
    [this] (const Node::Index& idx) { this->getNewSibling(idx); },
    [parent] (const Node::Index& index,
         const NonNegativeInteger& seqNo,
         ndn::ConstBufferPtr hash) {
      // std::cerr << "update: " << index.level << ", " << index.seqNo << std::endl;
      // std::cerr << "seqNo: " << seqNo << std::endl;
      // std::cerr << "parent: " << parent->getRoot()->getIndex().level << ", " <<
      //                            parent->getRoot()->getIndex().seqNo << std::endl;
      bool result = parent->updateLeaf(seqNo, hash);
      BOOST_ASSERT(result);
    });

  m_pendingTrees[newSibling->getPeakIndex().level] = newSibling;
}

}// namespace nsl
