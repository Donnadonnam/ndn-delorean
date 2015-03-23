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

#ifndef NSL_CORE_LOGGER_HPP
#define NSL_CORE_LOGGER_HPP

#include "common.hpp"
#include "logger-response.hpp"
#include "db.hpp"
#include "policy-checker.hpp"
#include "merkle-tree.hpp"
#include "util/non-negative-integer.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator-config.hpp>

namespace nsl {

class Logger
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
  Logger(ndn::Face& face, const std::string& configFile);

  NonNegativeInteger
  addSelfSignedCert(ndn::IdentityCertificate& cert, const Timestamp& timestamp);

NSL_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  initializeKeys();

  void
  loadConfiguration(const std::string& filename);

  void
  onSubTreeInterest(const ndn::InterestFilter& interestFilter, const Interest& interest);

  void
  onLeafInterest(const ndn::InterestFilter& interestFilter, const Interest& interest);

  void
  onLogRequestInterest(const ndn::InterestFilter& interestFilter, const Interest& interest);

  void
  requestValidatedCallback(const shared_ptr<const Interest>& interest);

  void
  dataReceivedCallback(const Interest& interest, Data& data,
                       const NonNegativeInteger& signerSeqNo,
                       const Interest& reqInterest);

  void
  dataTimeoutCallback(const Interest& interest, int nRetrials,
                      const NonNegativeInteger& signerSeqNo,
                      const Interest& reqInterest);

  void
  makeLogResponse(const Interest& reqInterest, const LoggerResponse& response);

  const Name&
  getLoggerName() const
  {
    return m_loggerName;
  }

  const Name&
  getTreePrefix() const
  {
    return m_treePrefix;
  }

  const Name&
  getLeafPrefix() const
  {
    return m_leafPrefix;
  }

  const Name&
  getLogPrefix() const
  {
    return m_logPrefix;
  }

  Db&
  getDb()
  {
    return m_db;
  }

private:
  static const int N_DATA_FETCHING_RETRIAL;

private:
  ndn::Face& m_face;
  Name m_loggerName;
  Name m_treePrefix;
  Name m_leafPrefix;
  Name m_logPrefix;

  Db m_db;
  MerkleTree  m_merkleTree;

  ndn::KeyChain m_keyChain;
  shared_ptr<ndn::IdentityCertificate> m_dskCert;

  ndn::ValidatorConfig m_validator;
  PolicyChecker m_policyChecker;
};

} // namespace nsl

#endif // NSL_CORE_LOGGER_HPP
