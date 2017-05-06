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

#include "leaf.hpp"
#include "tlv.hpp"
#include <ndn-cxx/security/digest-sha256.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/util/crypto.hpp>

namespace nsl {

const Name Leaf::EMPTY_NAME;
const size_t Leaf::N_LOGGER_LEAF_SUFFIX = 4;
const ssize_t Leaf::OFFSET_LEAF_SEQNO = -2;
const ssize_t Leaf::OFFSET_LEAF_HASH = -1;

Leaf::Leaf()
{
}

Leaf::Leaf(const Name& dataName,
       const Timestamp& timestamp,
       const NonNegativeInteger& dataSeqNo,
       const NonNegativeInteger& signerSeqNo,
       const Name& loggerName)
  : m_dataName(dataName)
  , m_timestamp(timestamp)
  , m_dataSeqNo(dataSeqNo)
  , m_signerSeqNo(signerSeqNo)
  , m_loggerName(loggerName)
{
  if (m_dataSeqNo < m_signerSeqNo)
    throw Error("Leaf: signer seqNo should be less than the data seqNo");
}

void
Leaf::setDataSeqNo(const NonNegativeInteger& dataSeqNo)
{
  if (dataSeqNo < m_signerSeqNo)
    throw Error("Leaf: signer seqNo should be less than the data seqNo");

  m_wire.reset();
  m_dataSeqNo = dataSeqNo;
}

void
Leaf::setDataName(const Name& dataName)
{
  m_wire.reset();
  m_dataName = dataName;
}

void
Leaf::setTimestamp(const Timestamp& timestamp)
{
  m_wire.reset();
  m_timestamp = timestamp;
}

void
Leaf::setSignerSeqNo(const NonNegativeInteger& signerSeqNo)
{
  if (m_dataSeqNo < signerSeqNo)
    throw Error("Leaf: signer seqNo should be less than the data seqNo");

  m_wire.reset();
  m_signerSeqNo = signerSeqNo;
}

void
Leaf::setLoggerName(const Name& loggerName)
{
  m_loggerName = loggerName;
}

ndn::ConstBufferPtr
Leaf::getHash() const
{
  wireEncode();
  return ndn::crypto::sha256(m_wire.wire(), m_wire.size());
}

shared_ptr<Data>
Leaf::encode() const
{
  auto data = make_shared<Data>();

  ndn::ConstBufferPtr hash = getHash();

  // Name
  Name dataName = m_loggerName;
  dataName.appendNumber(m_dataSeqNo).append(hash->buf(), hash->size());
  data->setName(dataName);

  // Content
  data->setContent(wireEncode());

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
Leaf::decode(const Data& data)
{
  const Name& dataName = data.getName();

  if (!m_loggerName.isPrefixOf(dataName))
    throw Error("decode: leaf data name does not match logger name");

  if (m_loggerName.size() + N_LOGGER_LEAF_SUFFIX != dataName.size())
    throw Error("decode: leaf data name does not follow the naming convention");

  ndn::ConstBufferPtr leafHash;
  NonNegativeInteger dataSeqNo;
  try {
    leafHash = make_shared<ndn::Buffer>(dataName.get(OFFSET_LEAF_HASH).value(),
                                        dataName.get(OFFSET_LEAF_HASH).value_size());

    dataSeqNo = dataName.get(OFFSET_LEAF_SEQNO).toNumber();
  }
  catch (tlv::Error&) {
    throw Error("decode: logger name encoding error");
  }

  wireDecode(data.getContent().blockFromValue());

  if (*leafHash != *getHash())
    throw Error("decode: inconsistent hash");

  if (m_dataSeqNo != dataSeqNo)
    throw Error("decode: seqNo does not match");
}

template<ndn::encoding::Tag TAG>
size_t
Leaf::wireEncode(ndn::EncodingImpl<TAG>& block) const
{
  size_t totalLength = 0;

  totalLength += ndn::prependNonNegativeIntegerBlock(block, tlv::SignerSeqNo, m_signerSeqNo);
  totalLength += ndn::prependNonNegativeIntegerBlock(block, tlv::DataSeqNo, m_dataSeqNo);
  totalLength += ndn::prependNonNegativeIntegerBlock(block, tlv::Timestamp, m_timestamp);
  totalLength += m_dataName.wireEncode(block);

  totalLength += block.prependVarNumber(totalLength);
  totalLength += block.prependVarNumber(tlv::LoggerLeaf);

  return totalLength;
}

template size_t
Leaf::wireEncode<ndn::encoding::EncoderTag>(ndn::EncodingImpl<ndn::encoding::EncoderTag>&) const;

template size_t
Leaf::wireEncode<ndn::encoding::EstimatorTag>(ndn::EncodingImpl<ndn::encoding::EstimatorTag>&) const;


const Block&
Leaf::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  ndn::EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  ndn::EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
Leaf::wireDecode(const Block& wire)
{
  if (!wire.hasWire()) {
    throw Error("The supplied block does not contain wire format");
  }

  m_wire = wire;
  m_wire.parse();

  if (m_wire.type() != tlv::LoggerLeaf)
    throw tlv::Error("Unexpected TLV type when decoding logger leaf");

  Block::element_const_iterator it = m_wire.elements_begin();

  // the first block must be dataName
  if (it != m_wire.elements_end() && it->type() == tlv::Name) {
    m_dataName.wireDecode(*it);
    it++;
  }
  else
    throw Error("The first sub-TLV is not Name");

  // the second block must be timestamp
  if (it != m_wire.elements_end() && it->type() == tlv::Timestamp) {
    m_timestamp = readNonNegativeInteger(*it);
    it++;
  }
  else
    throw Error("The second sub-TLV is not Timestamp");

  // the third block must be DataSeqNo
  if (it != m_wire.elements_end() && it->type() == tlv::DataSeqNo) {
    m_dataSeqNo = readNonNegativeInteger(*it);
    it++;
  }
  else
    throw Error("The third sub-TLV is not DataSeqNo");

  // the third block must be SignerSeqNo
  if (it != m_wire.elements_end() && it->type() == tlv::SignerSeqNo) {
    m_signerSeqNo = readNonNegativeInteger(*it);
    it++;
  }
  else
    throw Error("The fourth sub-TLV is not SignerSeqNo");

  if (it != m_wire.elements_end())
    throw Error("No more sub-TLV in LoggerLeaf");
}

} // namespace nsl
