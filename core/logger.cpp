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

#include "logger.hpp"
#include "tlv.hpp"
#include "conf/config-file.hpp"

namespace ndn {
namespace delorean {

const int Logger::N_DATA_FETCHING_RETRIAL = 2;

Logger::Logger(ndn::Face& face, const std::string& configFile)
  : m_face(face)
  , m_merkleTree(m_db)
  , m_validator(m_face)
{
  conf::ConfigFile conf(configFile);
  conf.parse();

  m_loggerName = conf.getLoggerName();

  m_treePrefix = m_loggerName;
  m_treePrefix.append("tree");
  m_leafPrefix = m_loggerName;
  m_leafPrefix.append("leaf");
  m_logPrefix = m_loggerName;
  m_logPrefix.append("log");

  m_merkleTree.setLoggerName(m_treePrefix);
  m_merkleTree.loadPendingSubTrees();

  m_db.open(conf.getDbDir());

  // initialize security environment: keychain
  initializeKeys();

  // load policy checker
  m_policyChecker.loadPolicy(conf.getPolicy());

  // load validator rules
  m_validator.load(conf.getValidatorRule(), conf.getConfFileName());

  // register subtree prefix
  m_face.setInterestFilter(m_treePrefix,
                           bind(&Logger::onSubTreeInterest, this, _1, _2),
                           [] (const Name&) {},
                           [] (const Name&, const std::string&) {});

  // register leaf prefix
  m_face.setInterestFilter(m_leafPrefix,
                           bind(&Logger::onLeafInterest, this, _1, _2),
                           [] (const Name&) {},
                           [] (const Name&, const std::string&) {});

  // register log prefix
  m_face.setInterestFilter(m_logPrefix,
                           bind(&Logger::onLogRequestInterest, this, _1, _2),
                           [] (const Name&) {},
                           [] (const Name&, const std::string&) {});
}

NonNegativeInteger
Logger::addSelfSignedCert(ndn::IdentityCertificate& cert, const Timestamp& timestamp)
{
  if (!ndn::Validator::verifySignature(cert, cert.getPublicKeyInfo()))
    throw Error("Not self-signed cert");

  NonNegativeInteger dataSeqNo = m_merkleTree.getNextLeafSeqNo();
  Leaf leaf(cert.getFullName(), timestamp, dataSeqNo, dataSeqNo, m_leafPrefix);

  if (m_merkleTree.addLeaf(dataSeqNo, leaf.getHash())) {
    m_db.insertLeafData(leaf, cert);
    m_db.getLeaf(dataSeqNo);
  }
  else
    throw Error("Cannot add cert");

  return dataSeqNo;
}

void
Logger::initializeKeys()
{
  Name certName = m_keyChain.createIdentity(m_loggerName);

  Name dskKeyName = m_keyChain.generateEcKeyPair(m_loggerName);
  std::vector<ndn::CertificateSubjectDescription> subjectDescription;
  auto dskCert =
    m_keyChain.prepareUnsignedIdentityCertificate(dskKeyName, m_loggerName,
                                                  time::system_clock::now(),
                                                  time::system_clock::now() + time::days(1),
                                                  subjectDescription);
  m_keyChain.sign(*dskCert, certName);
  m_keyChain.addCertificate(*dskCert);
  m_dskCert = dskCert;
}

void
Logger::onSubTreeInterest(const ndn::InterestFilter& interestFilter, const Interest& interest)
{
  Name interestName = interest.getName();

  size_t levelOffset = m_treePrefix.size();
  size_t seqNoOffset = m_treePrefix.size() + 1;

  if (interestName.size() < seqNoOffset + 1)
    return; // interest is too short to answer

  NonNegativeInteger level;
  NonNegativeInteger seqNo;

  try {
    seqNo = interestName.get(seqNoOffset).toNumber();
    level = interestName.get(levelOffset).toNumber();
  }
  catch (tlv::Error&) {
    return;
  }

  Node::Index peakIndex = SubTreeBinary::toSubTreePeakIndex(Node::Index(seqNo, level));
  shared_ptr<Data> data;

  data = m_merkleTree.getPendingSubTreeData(peakIndex.level);

  if (data != nullptr && interestName.isPrefixOf(data->getName())) {
    m_face.put(*data);
    return;
  }

  data = m_db.getSubTreeData(peakIndex.level, peakIndex.seqNo);

  if (data != nullptr && interestName.isPrefixOf(data->getName())) {
    m_face.put(*data);
    return;
  }
}

void
Logger::onLeafInterest(const ndn::InterestFilter& interestFilter, const Interest& interest)
{
  Name interestName = interest.getName();

  size_t seqNoOffset = m_leafPrefix.size();
  size_t hashOffset = m_leafPrefix.size() + 1;

  if (interestName.size() < seqNoOffset + 1)
    return; // interest is too short to answer

  NonNegativeInteger seqNo;

  try {
    seqNo = interestName.get(seqNoOffset).toNumber();
  }
  catch (tlv::Error&) {
    return;
  }
  auto result = m_db.getLeaf(seqNo);

  if (result.first != nullptr) {
    if (interestName.size() >= hashOffset + 1) {
      ndn::ConstBufferPtr leafHash;
      try {
        leafHash = make_shared<ndn::Buffer>(interestName.get(hashOffset).value(),
                                            interestName.get(hashOffset).value_size());
        ndn::ConstBufferPtr hash = result.first->getHash();
        if (*hash != *leafHash)
          return;
      }
      catch (tlv::Error&) {
        return;
      }
    }
    result.first->setLoggerName(m_leafPrefix);
    m_face.put(*result.first->encode());
  }
}

void
Logger::onLogRequestInterest(const ndn::InterestFilter& interestFilter, const Interest& interest)
{
  m_validator.validate(interest,
                       bind(&Logger::requestValidatedCallback, this, _1),
                       [] (const shared_ptr<const Interest>&, const std::string&) {});
}

void
Logger::requestValidatedCallback(const shared_ptr<const Interest>& interest)
{
  BOOST_ASSERT(interest->getName().size() == (m_logPrefix.size() + 6));

  Name request = interest->getName().getPrefix(-4); // TODO: remove sig-related components

  size_t dataOffset = m_logPrefix.size();
  size_t signerOffset = m_logPrefix.size() + 1;

  if (request.size() < signerOffset + 1)
    return; // request is too short to answer

  Name dataName;
  NonNegativeInteger signerSeqNo;
  try {
    dataName.wireDecode(request.get(dataOffset).blockFromValue());
    signerSeqNo = request.get(signerOffset).toNumber();
  }
  catch (tlv::Error&) {
    return;
  }

  auto result = m_db.getLeaf(signerSeqNo);
  if (result.first == nullptr || result.second == nullptr)
    return;

  Interest dataInterest(dataName);
  m_face.expressInterest(dataInterest,
                         bind(&Logger::dataReceivedCallback, this, _1, _2,
                              signerSeqNo, *interest),
                         bind(&Logger::dataTimeoutCallback, this, _1,
                              N_DATA_FETCHING_RETRIAL, signerSeqNo, *interest));
}

void
Logger::dataReceivedCallback(const Interest& interest, Data& data,
                             const NonNegativeInteger& signerSeqNo,
                             const Interest& reqInterest)
{
  auto result = m_db.getLeaf(signerSeqNo);
  BOOST_ASSERT(result.first != nullptr);
  BOOST_ASSERT(result.second != nullptr);

  Timestamp dataTimestamp = time::toUnixTimestamp(time::system_clock::now()).count() / 1000;

  try {
    ndn::IdentityCertificate cert(*result.second);

    if (m_policyChecker.check(dataTimestamp, data, result.first->getTimestamp(), cert)) {
      NonNegativeInteger dataSeqNo = m_merkleTree.getNextLeafSeqNo();
      Leaf leaf(data.getFullName(), dataTimestamp, dataSeqNo, signerSeqNo, m_leafPrefix);

      if (m_merkleTree.addLeaf(dataSeqNo, leaf.getHash())) {
        if (data.getContentType() == ndn::tlv::ContentType_Key)
          m_db.insertLeafData(leaf, data);
        else
          m_db.insertLeafData(leaf);

        makeLogResponse(reqInterest, LoggerResponse(dataSeqNo));
      }
      else
        makeLogResponse(reqInterest,
                        LoggerResponse(tlv::LogResponse_Error_Tree, "cannot add leaf"));
    }
    else
      makeLogResponse(reqInterest,
                      LoggerResponse(tlv::LogResponse_Error_Policy, "cannot pass policy checking"));
  }
  catch (tlv::Error&) {
    makeLogResponse(reqInterest,
                    LoggerResponse(tlv::LogResponse_Error_Signer, "signer is wrong"));
  }
}

void
Logger::dataTimeoutCallback(const Interest& interest, int nRetrials,
                            const NonNegativeInteger& signerSeqNo,
                            const Interest& reqInterest)
{
  if (nRetrials > 0) {
    m_face.expressInterest(interest,
                           bind(&Logger::dataReceivedCallback, this, _1, _2,
                                signerSeqNo, reqInterest),
                           bind(&Logger::dataTimeoutCallback, this, _1,
                                nRetrials - 1, signerSeqNo, reqInterest));
  }
}

void
Logger::makeLogResponse(const Interest& reqInterest, const LoggerResponse& response)
{
  auto data = make_shared<Data>(reqInterest.getName());
  data->setContent(response.wireEncode());

  BOOST_ASSERT(m_dskCert != nullptr);
  m_keyChain.sign(*data, m_dskCert->getName());
  m_face.put(*data);
}


} // namespace delorean
} // namespace ndn
