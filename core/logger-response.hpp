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

#ifndef NSL_CORE_LOGGER_RESPONSE_HPP
#define NSL_CORE_LOGGER_RESPONSE_HPP

#include "common.hpp"
#include "util/non-negative-integer.hpp"
#include <ndn-cxx/encoding/buffer.hpp>

namespace nsl {

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

} // namespace nsl

#endif // NSL_CORE_LOGGER_RESPONSE_HPP
