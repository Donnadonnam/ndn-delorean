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

#ifndef NDN_DELOREAN_CORE_MERKLE_TREE_HPP
#define NDN_DELOREAN_CORE_MERKLE_TREE_HPP

#include "common.hpp"
#include "db.hpp"
#include "sub-tree-binary.hpp"
#include <vector>

namespace nsl {

class MerkleTree
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  /**
   * @brief Constructor
   */
  MerkleTree(Db& db);

  MerkleTree(const Name& loggerName, Db& db);

  ~MerkleTree();

  void
  setLoggerName(const Name& loggerName);

  const NonNegativeInteger&
  getNextLeafSeqNo() const
  {
    return m_nextLeafSeqNo;
  }

  const ndn::ConstBufferPtr&
  getRootHash() const
  {
    return m_hash;
  }

  bool
  addLeaf(const NonNegativeInteger& seqNo, ndn::ConstBufferPtr hash);

  void
  loadPendingSubTrees();

  void
  savePendingTree();

  shared_ptr<Data>
  getPendingSubTreeData(size_t level);

  std::vector<ConstSubTreeBinaryPtr>
  getExistenceProof(const NonNegativeInteger& seqNo);

  std::vector<ConstSubTreeBinaryPtr>
  getConsistencyProof(const NonNegativeInteger& seqNo);

private:
  void
  getNewRoot(const Node::Index& idx);

  void
  getNewSibling(const Node::Index& idx);

private:
  Name m_loggerName;
  Db& m_db;

  shared_ptr<SubTreeBinary> m_rootSubTree;
  NonNegativeInteger m_nextLeafSeqNo;
  ndn::ConstBufferPtr m_hash;

  std::map<size_t, shared_ptr<SubTreeBinary>> m_pendingTrees;
};

}// namespace nsl

#endif // NDN_DELOREAN_CORE_MERKLE_TREE_HPP
