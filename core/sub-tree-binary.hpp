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

#ifndef NSL_CORE_SUB_TREE_HPP
#define NSL_CORE_SUB_TREE_HPP

#include "node.hpp"

namespace nsl {

typedef std::function<void(const Node::Index&)> CompleteCallback;
typedef std::function<void(const Node::Index&,
                           const NonNegativeInteger&,
                           ndn::ConstBufferPtr)> RootUpdateCallback;

class SubTreeBinary
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
   *
   * Create an empty subtree.
   *
   * @param loggerName The name of logger
   * @param completeCallback Callback when the subtree is complete
   * @param rootUpdateCallback Callback when the subtree root is updated
   */
  SubTreeBinary(const Name& loggerName,
                const CompleteCallback& completeCallback,
                const RootUpdateCallback& rootUpdateCallback);
  /**
   * @brief Constructor
   *
   * Create a subtree with its first leaf node hash.
   *
   * @param loggerName The name of logger
   * @param rootIndex The index of sub tree root when it is full
   * @param completeCallback Callback when the subtree is complete
   * @param rootUpdateCallback Callback when the subtree root is updated
   */
  SubTreeBinary(const Name& loggerName,
                const Node::Index& rootIndex,
                const CompleteCallback& completeCallback,
                const RootUpdateCallback& rootUpdateCallback);

  const Node::Index&
  getPeakIndex() const
  {
    return m_peakIndex;
  }

  const NonNegativeInteger&
  getMinSeqNo() const
  {
    return m_minSeqNo;
  }

  const NonNegativeInteger&
  getMaxSeqNo() const
  {
    return m_maxSeqNo;
  }

  size_t
  getLeafLevel() const
  {
    return m_leafLevel;
  }

  const NonNegativeInteger&
  getNextLeafSeqNo() const;

  /**
   * @brief get the root of the subtree
   *
   * @return pointer to the root, nullptr if no leaf added
   */
  ConstNodePtr
  getRoot() const
  {
    return m_actualRoot;
  }

  ndn::ConstBufferPtr
  getRootHash() const;

  ConstNodePtr
  getNode(const Node::Index& index) const;

  bool
  addLeaf(NodePtr leaf);

  bool
  updateLeaf(const NonNegativeInteger& nextSeqNo, ndn::ConstBufferPtr hash);

  bool
  isFull() const;

  shared_ptr<Data>
  encode() const;

  void
  decode(const Data& data);

public:
  static Node::Index
  toSubTreePeakIndex(const Node::Index& index, bool notRoot = true);

private:
  void
  initialize(const Node::Index& peakIndex);

  void
  updateActualRoot(NodePtr node);

  void
  updateParentNode(NodePtr node);

public:
  static const size_t SUB_TREE_DEPTH;

NSL_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const time::milliseconds INCOMPLETE_FRESHNESS_PERIOD;
  static const std::string COMPONENT_COMPLETE;
  static const ssize_t OFFSET_ROOTHASH;
  static const ssize_t OFFSET_COMPLETE;
  static const ssize_t OFFSET_SEQNO;
  static const ssize_t OFFSET_LEVEL;
  static const size_t N_LOGGER_SUFFIX;

private:
  Name m_loggerName;
  Node::Index m_peakIndex;
  NonNegativeInteger m_minSeqNo;
  NonNegativeInteger m_maxSeqNo;
  size_t m_leafLevel;

  CompleteCallback m_completeCallback;
  RootUpdateCallback m_rootUpdateCallback;

  NodePtr m_actualRoot;
  bool m_isPendingLeafEmpty;
  NonNegativeInteger m_pendingLeafSeqNo;

  std::map<Node::Index, NodePtr> m_nodes;
};

typedef shared_ptr<SubTreeBinary> SubTreeBinaryPtr;
typedef shared_ptr<const SubTreeBinary> ConstSubTreeBinaryPtr;

} // namespace nsl

#endif // NSL_CORE_SUB_TREE_HPP
