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

#ifndef NDN_DELOREAN_CORE_TLV_HPP
#define NDN_DELOREAN_CORE_TLV_HPP

namespace nsl {
namespace tlv {

/**
 * @brief Type value of leaf related TLVs
 */
enum {
  LoggerLeaf  = 128, // 0x80
  Timestamp   = 129, // 0x81
  DataSeqNo   = 130, // 0x82
  SignerSeqNo = 131, // 0x83

  LogResponse = 144, // 0x90
  ResultCode  = 145, // 0x91
  ResultMsg   = 146 // 0x92
};

enum {
  LogResponse_Accept       = 0,
  LogResponse_Error_Tree   = 1,
  LogResponse_Error_Policy = 2,
  LogResponse_Error_Signer = 3
};

} // namespace tlv
} // namespace nsl

#endif // NDN_DELOREAN_CORE_TLV_HPP
