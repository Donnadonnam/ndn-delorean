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

#include "logger-response.hpp"
#include "tlv.hpp"

namespace ndn {
namespace delorean {

LoggerResponse::LoggerResponse()
  : m_code(-1)
{
}

LoggerResponse::LoggerResponse(int32_t code, const std::string& msg)
  : m_code(code)
  , m_msg(msg)
  , m_dataSeqNo(0)
{
}

LoggerResponse::LoggerResponse(const NonNegativeInteger& seqNo)
  : m_code(0)
  , m_dataSeqNo(seqNo)
{
}

template<ndn::encoding::Tag TAG>
size_t
LoggerResponse::wireEncode(ndn::EncodingImpl<TAG>& block) const
{
  size_t totalLength = 0;

  if (m_code != 0) {
    totalLength += block.prependByteArrayBlock(tlv::ResultMsg,
                                               reinterpret_cast<const uint8_t*>(m_msg.c_str()),
                                               m_msg.size());
  }
  else {
    totalLength += prependNonNegativeIntegerBlock(block, tlv::DataSeqNo, m_dataSeqNo);
  }
  totalLength += prependNonNegativeIntegerBlock(block, tlv::ResultCode, m_code);

  totalLength += block.prependVarNumber(totalLength);
  totalLength += block.prependVarNumber(tlv::LogResponse);

  return totalLength;
}

template size_t
LoggerResponse::wireEncode<ndn::encoding::EncoderTag>(ndn::EncodingImpl<ndn::encoding::EncoderTag>&) const;

template size_t
LoggerResponse::wireEncode<ndn::encoding::EstimatorTag>(ndn::EncodingImpl<ndn::encoding::EstimatorTag>&) const;


const Block&
LoggerResponse::wireEncode() const
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
LoggerResponse::wireDecode(const Block& wire)
{
  if (!wire.hasWire()) {
    throw Error("The supplied block does not contain wire format");
  }

  m_wire = wire;
  m_wire.parse();

  if (m_wire.type() != tlv::LogResponse)
    throw tlv::Error("Unexpected TLV type when decoding log response");

  Block::element_const_iterator it = m_wire.elements_begin();

  // the first block must be result code
  if (it != m_wire.elements_end() && it->type() == tlv::ResultCode) {
    m_code = readNonNegativeInteger(*it);
    it++;
  }
  else
    throw Error("The first sub-TLV is not ResultCode");

  // the second block could be result msg
  if (it == m_wire.elements_end())
    return;
  else if (it->type() == tlv::ResultMsg) {
    m_msg = std::string(reinterpret_cast<const char*>(it->value()), it->value_size());
    it++;
  }
  else if (it->type() == tlv::DataSeqNo) {
    m_dataSeqNo = readNonNegativeInteger(*it);
    it++;
  }
  else
    throw Error("The second sub-TLV is not ResultMsg");

  if (it != m_wire.elements_end())
    throw Error("No more sub-TLV in log response");
}

} // namespace delorean
} // namespace ndn
