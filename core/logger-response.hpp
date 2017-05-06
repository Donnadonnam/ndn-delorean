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

#ifndef NDN_DELOREAN_CORE_LOGGER_RESPONSE_HPP
#define NDN_DELOREAN_CORE_LOGGER_RESPONSE_HPP

#include "common.hpp"
#include "util/non-negative-integer.hpp"
#include <ndn-cxx/encoding/buffer.hpp>

namespace ndn {
namespace delorean {

class LoggerResponse
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
  LoggerResponse();

  LoggerResponse(int32_t resultCode, const std::string& resultMsg);

  LoggerResponse(const NonNegativeInteger& seqNo);

  int32_t
  getCode() const
  {
    return m_code;
  }

  const std::string&
  getMsg() const
  {
    if (m_code == 0)
      throw Error("Error msg is not available");

    return m_msg;
  }

  const NonNegativeInteger&
  getDataSeqNo() const
  {
    if (m_code != 0)
      throw Error("Data seqNo is not available");

    return m_dataSeqNo;
  }

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

private:
  int32_t m_code;
  std::string m_msg; // optional
  NonNegativeInteger m_dataSeqNo; // optional

  mutable Block m_wire;
};

} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_CORE_LOGGER_RESPONSE_HPP
