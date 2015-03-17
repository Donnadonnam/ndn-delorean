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

#include "sub-tree-binary.hpp"

#include <ndn-cxx/util/digest.hpp>
#include <ndn-cxx/util/crypto.hpp>
#include <ndn-cxx/security/digest-sha256.hpp>

namespace nsl {

const time::milliseconds SubTreeBinary::INCOMPLETE_FRESHNESS_PERIOD(60000);
const std::string SubTreeBinary::COMPONENT_COMPLETE("complete");
const ssize_t SubTreeBinary::OFFSET_ROOTHASH = -1;
const ssize_t SubTreeBinary::OFFSET_COMPLETE = -2;
const ssize_t SubTreeBinary::OFFSET_SEQNO = -3;
const ssize_t SubTreeBinary::OFFSET_LEVEL = -4;
const size_t SubTreeBinary::N_LOGGER_SUFFIX = 4;
const size_t SubTreeBinary::SUB_TREE_DEPTH = 6;


SubTreeBinary::SubTreeBinary(const Name& loggerName,
                             const CompleteCallback& completeCallback,
                             const RootUpdateCallback& rootUpdateCallback)
  : m_loggerName(loggerName)
  , m_completeCallback(completeCallback)
  , m_rootUpdateCallback(rootUpdateCallback)
{
}

SubTreeBinary::SubTreeBinary(const Name& loggerName,
                             const Node::Index& peakIndex,
                             const CompleteCallback& completeCallback,
                             const RootUpdateCallback& rootUpdateCallback)
  : m_loggerName(loggerName)
  , m_completeCallback(completeCallback)
  , m_rootUpdateCallback(rootUpdateCallback)
{
  initialize(peakIndex);
}

const NonNegativeInteger&
SubTreeBinary::getNextLeafSeqNo() const
{
  if (m_actualRoot != nullptr)
    return m_actualRoot->getLeafSeqNo();

  return m_peakIndex.seqNo;
}

ndn::ConstBufferPtr
SubTreeBinary::getRootHash() const
{
  if (m_actualRoot != nullptr)
    return m_actualRoot->getHash();

  return nullptr;
}

ConstNodePtr
SubTreeBinary::getNode(const Node::Index& index) const
{
  auto it = m_nodes.find(index);
  if (it != m_nodes.end()) {
    return it->second;
  }

  return nullptr;
}

bool
SubTreeBinary::addLeaf(NodePtr leaf)
{
  // sanity check: must be a valid leaf
  if (leaf->getIndex().level != m_leafLevel ||
      leaf->getIndex().seqNo < m_minSeqNo ||
      leaf->getIndex().seqNo >= m_maxSeqNo)
    return false;

  // sanity check: must be the expected next leaf
  if (leaf->getIndex().seqNo != m_pendingLeafSeqNo ||
      !m_isPendingLeafEmpty)
    return false;

  // add the leaf
  m_nodes[leaf->getIndex()] = leaf;

  // update actual root (guarantee we will have a root)
  updateActualRoot(leaf);

  // update nodes and their hashes
  updateParentNode(leaf);

  if (leaf->isFull()) {
    m_pendingLeafSeqNo = leaf->getIndex().seqNo + leaf->getIndex().range;
    m_isPendingLeafEmpty = true;
  }
  else {
    m_isPendingLeafEmpty = false;
  }

  return true;
}

bool
SubTreeBinary::updateLeaf(const NonNegativeInteger& nextSeqNo, ndn::ConstBufferPtr hash)
{
  // std::cerr << "NextSeqNo: " << nextSeqNo << std::endl;
  // std::cerr << "minSeqNo: " << m_minSeqNo << std::endl;
  // std::cerr << "maxSeqNo: " << m_maxSeqNo << std::endl;

  // sanity check
  if (nextSeqNo < m_minSeqNo || nextSeqNo > m_maxSeqNo)
    return false;

  // std::cerr << "2" << std::endl;
  // determine leaf index
  NonNegativeInteger leafSeqNo = ((nextSeqNo - 1) >> m_leafLevel) << m_leafLevel;
  if (m_pendingLeafSeqNo != leafSeqNo)
    return false;

  Node::Index index(leafSeqNo, m_leafLevel);
  auto leaf = m_nodes[index];

  if (leaf == nullptr) {
    leaf = make_shared<Node>(leafSeqNo, m_leafLevel, nextSeqNo, hash);
    m_nodes[index] = leaf;
    updateActualRoot(leaf);
  }
  else {
    leaf->setLeafSeqNo(nextSeqNo);
    leaf->setHash(hash);
  }

  if (nextSeqNo == leafSeqNo + (1 << m_leafLevel)) {
    m_pendingLeafSeqNo = nextSeqNo;
    m_isPendingLeafEmpty = true;
  }

  updateParentNode(leaf);

  return true;
}

bool
SubTreeBinary::isFull() const
{
  if (m_actualRoot != nullptr &&
      m_actualRoot->getIndex() == m_peakIndex &&
      m_actualRoot->isFull())
    return true;

  return false;
}

shared_ptr<Data>
SubTreeBinary::encode() const
{
  if (m_actualRoot == nullptr) {
    auto emptyData = make_shared<Data>();
    // Name
    Name emptyName = m_loggerName;
    emptyName.appendNumber(m_peakIndex.level)
      .appendNumber(m_peakIndex.seqNo)
      .appendNumber(m_peakIndex.seqNo)
      .append(Node::getEmptyHash()->buf(), Node::getEmptyHash()->size());
    emptyData->setName(emptyName);

    // MetaInfo
    emptyData->setFreshnessPeriod(time::milliseconds(0));

    // Signature
    ndn::DigestSha256 sig;
    emptyData->setSignature(sig);

    Block sigValue(tlv::SignatureValue,
                   ndn::crypto::sha256(emptyData->wireEncode().value(),
                                       emptyData->wireEncode().value_size() -
                                       emptyData->getSignature().getValue().size()));
    emptyData->setSignatureValue(sigValue);

    emptyData->wireEncode();

    return emptyData;
  }

  // Name
  Name dataName = m_loggerName;
  dataName.appendNumber(m_actualRoot->getIndex().level)
    .appendNumber(m_actualRoot->getIndex().seqNo);
  if (isFull())
    dataName.append(COMPONENT_COMPLETE.c_str());
  else
    dataName.appendNumber(m_actualRoot->getLeafSeqNo());
  dataName.append(m_actualRoot->getHash()->buf(), m_actualRoot->getHash()->size());

  auto data = make_shared<Data>(dataName);

  // MetaInfo
  if (!isFull())
    data->setFreshnessPeriod(INCOMPLETE_FRESHNESS_PERIOD);

  // Content
  auto buffer = make_shared<ndn::Buffer>();
  NonNegativeInteger range = 1 << m_leafLevel;
  for (NonNegativeInteger i = m_minSeqNo; i < m_maxSeqNo; i += range) {
    auto it = m_nodes.find(Node::Index(i, m_leafLevel));
    if (it == m_nodes.end())
      break;

    auto leaf = it->second;
    if (leaf == nullptr)
      break;
    BOOST_ASSERT(leaf->getHash() != nullptr);
    BOOST_ASSERT(leaf->getHash()->size() == 32);
    buffer->insert(buffer->end(), leaf->getHash()->begin(), leaf->getHash()->end());
  }
  data->setContent(buffer->buf(), buffer->size());

  // Signature
  ndn::DigestSha256 sig;
  data->setSignature(sig);

  Block sigValue(tlv::SignatureValue,
                 ndn::crypto::sha256(data->wireEncode().value(),
                                     data->wireEncode().value_size() -
                                     data->getSignature().getValue().size()));
  data->setSignatureValue(sigValue);

  data->wireEncode();
  return data;
}

void
SubTreeBinary::decode(const Data& data)
{
  bool isComplete = false;
  NonNegativeInteger nextSeqNo;
  ndn::ConstBufferPtr rootHash;
  NonNegativeInteger seqNo;
  size_t level;

  const Name& dataName = data.getName();

  if (!m_loggerName.isPrefixOf(dataName))
    throw Error("decode: logger name does not match");

  if (m_loggerName.size() + N_LOGGER_SUFFIX != dataName.size())
    throw Error("decode: data name does not follow the naming convention");

  try {
    if (dataName.get(OFFSET_COMPLETE).toUri() == COMPONENT_COMPLETE)
      isComplete = true;
    else
      nextSeqNo = dataName.get(OFFSET_COMPLETE).toNumber();

    rootHash = make_shared<ndn::Buffer>(dataName.get(OFFSET_ROOTHASH).value(),
                                        dataName.get(OFFSET_ROOTHASH).value_size());

    seqNo = dataName.get(OFFSET_SEQNO).toNumber();
    level = dataName.get(OFFSET_LEVEL).toNumber();
  }
  catch (tlv::Error&) {
    throw Error("decode: logger name encoding error");
  }

  if (seqNo == 0) {
    size_t peakLevel = 0;
    if (level % (SUB_TREE_DEPTH - 1) != 0)
      peakLevel = ((level + SUB_TREE_DEPTH - 1) / (SUB_TREE_DEPTH - 1)) * (SUB_TREE_DEPTH - 1);
    else
      peakLevel = level;

    if (nextSeqNo == 1 << peakLevel)
      peakLevel = peakLevel + SUB_TREE_DEPTH - 1;

    initialize(Node::Index(seqNo, peakLevel));
  }
  else
    initialize(Node::Index(seqNo, level));

  if (isComplete)
    nextSeqNo = seqNo + (1 << level);
  else if (nextSeqNo == seqNo) // empty tree
    return;

  if (rootHash->size() != 32)
    throw Error("decode: wrong root hash size");

  if (nextSeqNo <= seqNo || nextSeqNo > seqNo + (1 << level))
    throw Error("decode: wrong current leaf SeqNo");

  int nLeaves = (nextSeqNo - seqNo - 1) / (1 << m_leafLevel) + 1;

  // std::cerr << data.getName() << std::endl;
  // std::cerr << nextSeqNo << std::endl;
  // std::cerr << nLeaves * 32 << std::endl;
  // std::cerr << data.getContent().value_size() << std::endl;

  if (nLeaves * 32 != data.getContent().value_size())
    throw Error("decode: inconsistent content");

  const uint8_t* offset = data.getContent().value();
  NonNegativeInteger seqNoInterval = 1 << m_leafLevel;
  int i = 0;
  for (; i < nLeaves - 1; i++) {
    auto node = make_shared<Node>(seqNo + (i * seqNoInterval),
                                  m_peakIndex.level + 1 - SUB_TREE_DEPTH,
                                  seqNo + (i * seqNoInterval) + seqNoInterval,
                                  make_shared<ndn::Buffer>(offset + (i * 32), 32));
    addLeaf(node);
  }

  auto node = make_shared<Node>(seqNo + (i * seqNoInterval),
                                m_peakIndex.level + 1 - SUB_TREE_DEPTH,
                                nextSeqNo,
                                make_shared<ndn::Buffer>(offset + (i * 32), 32));
  addLeaf(node);

  if (*rootHash != *getRoot()->getHash())
    throw Error("decode: Inconsistent hash");
}

Node::Index
SubTreeBinary::toSubTreePeakIndex(const Node::Index& index, bool notRoot)
{
  size_t peakLevel =
    ((index.level + SUB_TREE_DEPTH - 1) / (SUB_TREE_DEPTH - 1)) * (SUB_TREE_DEPTH - 1);

  size_t leafLevel = peakLevel + 1 - SUB_TREE_DEPTH;

  if (index.level % (SUB_TREE_DEPTH - 1) == 0 && index.level > 0 && !notRoot) {
    peakLevel -= (SUB_TREE_DEPTH - 1);
    leafLevel -= (SUB_TREE_DEPTH - 1);
  }

  NonNegativeInteger peakSeqNo = (index.seqNo >> peakLevel) << peakLevel;

  return Node::Index(peakSeqNo, peakLevel);
}

void
SubTreeBinary::initialize(const Node::Index& peakIndex)
{
  m_peakIndex = peakIndex;

  if (peakIndex.level + 1 < SUB_TREE_DEPTH ||
      peakIndex.level % (SUB_TREE_DEPTH - 1) != 0)
    throw Error("SubTreeBinary: peak level does not match the depth");

  m_leafLevel = peakIndex.level + 1 - SUB_TREE_DEPTH;

  m_minSeqNo = peakIndex.seqNo;
  m_maxSeqNo = peakIndex.seqNo + peakIndex.range;

  m_pendingLeafSeqNo = m_minSeqNo;
  m_isPendingLeafEmpty = true;
}



void
SubTreeBinary::updateActualRoot(NodePtr node)
{
  if (m_actualRoot == nullptr) {
    // if actual root is not set yet
    if (node->getIndex().seqNo == 0) { // root sub-tree
      m_actualRoot = node;
      m_rootUpdateCallback(node->getIndex(), node->getLeafSeqNo(), node->getHash());
      return;
    }
    else {
      m_actualRoot = make_shared<Node>(m_peakIndex.seqNo, m_peakIndex.level);
      m_nodes[m_actualRoot->getIndex()] = m_actualRoot;
      return;
    }
  }

  if (m_actualRoot->getIndex() == m_peakIndex)
    return;

  if ((node->getIndex().seqNo >> m_actualRoot->getIndex().level) != 0) {
    // a new actual root at a higher is needed
    m_actualRoot = make_shared<Node>(m_minSeqNo, m_actualRoot->getIndex().level + 1);
    m_nodes[m_actualRoot->getIndex()] = m_actualRoot;
    return;
  }
}

void
SubTreeBinary::updateParentNode(NodePtr node)
{
  if (node->getIndex() == m_actualRoot->getIndex()) { // root does not have a parent
    return;
  }

  size_t parentLevel = node->getIndex().level + 1;
  NodePtr parentNode;

  if ((node->getIndex().seqNo >> node->getIndex().level) % 2 == 0) { // left child
    // parent may not exist
    Node::Index parentIndex(node->getIndex().seqNo, parentLevel);
    parentNode = m_nodes[parentIndex];

    ndn::util::Sha256 sha256;
    sha256 << parentIndex.level << parentIndex.seqNo;
    sha256.update(node->getHash()->buf(), node->getHash()->size());
    sha256.update(Node::getEmptyHash()->buf(), Node::getEmptyHash()->size());

    if (parentNode == nullptr) {
      parentNode = make_shared<Node>(node->getIndex().seqNo,
                                     parentLevel,
                                     node->getLeafSeqNo(),
                                     sha256.computeDigest());
    }
    else {
      parentNode->setHash(sha256.computeDigest());
      parentNode->setLeafSeqNo(node->getLeafSeqNo());
    }

    m_nodes[parentNode->getIndex()] = parentNode;
  }
  else { // right child
    // parent must exist
    NonNegativeInteger parentSeqNo = node->getIndex().seqNo - node->getIndex().range;

    Node::Index parentIndex(parentSeqNo, parentLevel);
    Node::Index siblingIndex(parentSeqNo, parentLevel - 1);

    parentNode = m_nodes[parentIndex];
    auto siblingNode = m_nodes[siblingIndex];

    ndn::util::Sha256 sha256;
    sha256 << parentNode->getIndex().level << parentNode->getIndex().seqNo;
    sha256.update(siblingNode->getHash()->buf(), siblingNode->getHash()->size());
    sha256.update(node->getHash()->buf(), node->getHash()->size());

    parentNode->setHash(sha256.computeDigest());
    parentNode->setLeafSeqNo(node->getLeafSeqNo());
  }

  if (parentNode->getIndex() == m_actualRoot->getIndex()) { // reach root
    m_rootUpdateCallback(parentNode->getIndex(),
                         parentNode->getLeafSeqNo(),
                         parentNode->getHash());
    if (parentNode->getIndex() == m_peakIndex && parentNode->isFull())
      m_completeCallback(parentNode->getIndex());
  }
  else
    updateParentNode(parentNode);
}

} // namespace nsl
