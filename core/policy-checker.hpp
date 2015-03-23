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

#ifndef NSL_CORE_POLICY_CHECKER_HPP
#define NSL_CORE_POLICY_CHECKER_HPP

#include "common.hpp"
#include "db.hpp"
#include "util/non-negative-integer.hpp"
#include "conf/config.hpp"
#include "conf/rule.hpp"
#include <ndn-cxx/security/identity-certificate.hpp>


namespace nsl {

class PolicyChecker
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
  PolicyChecker();

  void
  reset();

  void
  loadPolicy(const conf::ConfigSection& policy);

  bool
  check(const Timestamp& dataTimestamp, const Data& data,
        const Timestamp& keyTimestamp, const ndn::IdentityCertificate& cert);
private:

  void
  onConfigRule(const conf::ConfigSection& section);

  bool
  checkRule(const Data& data);

private:
  typedef std::vector<shared_ptr<conf::Rule>> DataRuleList;

  DataRuleList m_dataRules;
};

} // namespace nsl

#endif // NSL_CORE_POLICY_CHECKER_HPP
