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

#ifndef NSL_CORE_LEAF_HPP
#define NSL_CORE_LEAF_HPP

#include "common.hpp"
#include "util/non-negative-integer.hpp"
#include "util/timestamp.hpp"
#include <ndn-cxx/encoding/buffer.hpp>

namespace nsl {

class Leaf
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
  Leaf();

  Leaf(const Name& dataName,
       const Timestamp& timestamp,
       const NonNegativeInteger& leafSeqNo,
       const NonNegativeInteger& signerSeqNo,
       const Name& loggerName = EMPTY_NAME);

  void
  setDataSeqNo(const NonNegativeInteger& dataSeqNo);

  const NonNegativeInteger&
  getDataSeqNo() const
  {
    return m_dataSeqNo;
  }

  void
  setDataName(const Name& dataName);

  const Name&
  getDataName() const
  {
    return m_dataName;
  }

  void
  setTimestamp(const Timestamp& timestamp);

  const Timestamp&
  getTimestamp() const
  {
    return m_timestamp;
  }

  void
  setSignerSeqNo(const NonNegativeInteger& signerSeqNo);

  const NonNegativeInteger&
  getSignerSeqNo() const
  {
    return m_signerSeqNo;
  }

  void
  setLoggerName(const Name& loggerName);

  const Name&
  getLoggerName() const
  {
    return m_loggerName;
  }

  ndn::ConstBufferPtr
  getHash() const;

  shared_ptr<Data>
  encode() const;

  void
  decode(const Data& data);

NSL_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  /// @brief Encode to a wire format or estimate wire format
  template<ndn::encoding::Tag TAG>
  size_t
  wireEncode(ndn::EncodingImpl<TAG>& block) const;

  /// @brief Encode to a wire format
  const Block&
  wireEncode() const;

  /// @brief Decode from a wire format
  void
  wireDecode(const Block& wire);

public:
  static const Name EMPTY_NAME;

NSL_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const size_t N_LOGGER_LEAF_SUFFIX;
  static const ssize_t OFFSET_LEAF_SEQNO;
  static const ssize_t OFFSET_LEAF_HASH;

private:
  Name m_dataName;
  Timestamp m_timestamp;
  NonNegativeInteger m_dataSeqNo;
  NonNegativeInteger m_signerSeqNo;

  mutable Block m_wire;

  Name m_loggerName;
};

} // namespace nsl

#endif // NSL_CORE_LEAF_HPP
