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

#include "policy-checker.hpp"
#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/security/validator.hpp>
#include <boost/algorithm/string.hpp>

namespace nsl {

using ndn::time::system_clock;

PolicyChecker::PolicyChecker()
{
}

void
PolicyChecker::reset()
{
  m_dataRules.clear();
}

void
PolicyChecker::loadPolicy(const conf::ConfigSection& configSection)
{
  reset();

  for (const auto& section : configSection) {
    if (boost::iequals(section.first, "rule")) {
      onConfigRule(section.second);
    }
    else
      throw Error("Error in loading policy checker: unrecognized section " + section.first);
  }
}

void
PolicyChecker::onConfigRule(const conf::ConfigSection& section)
{
  using namespace nsl::conf;

  auto it = section.begin();

  // Get rule.id
  if (it == section.end() || !boost::iequals(it->first, "id"))
    throw Error("Expect <rule.id>");

  std::string ruleId = it->second.data();
  it++;

  // Get rule.for
  if (it == section.end() || !boost::iequals(it->first, "for"))
    throw Error("Expect <rule.for> in rule: " + ruleId);

  std::string usage = it->second.data();
  it++;

  bool isForData;
  if (boost::iequals(usage, "data"))
    isForData = true;
  else if (boost::iequals(usage, "interest"))
    isForData = false;
  else
    throw Error("Unrecognized <rule.for>: " + usage + " in rule: " + ruleId);

  // Get rule.filter(s)
  std::vector<shared_ptr<Filter> > filters;
  for (; it != section.end(); it++) {
    if (!boost::iequals(it->first, "filter")) {
      if (boost::iequals(it->first, "checker"))
        break;
      throw Error("Expect <rule.filter> in rule: " + ruleId);
    }

    filters.push_back(FilterFactory::create(it->second));
    continue;
  }

  // Get rule.checker(s)
  std::vector<shared_ptr<Checker> > checkers;
  for (; it != section.end(); it++) {
    if (!boost::iequals(it->first, "checker"))
      throw Error("Expect <rule.checker> in rule: " + ruleId);

    checkers.push_back(CheckerFactory::create(it->second));
    continue;
  }

  // Check other stuff
  if (it != section.end())
    throw Error("Expect the end of rule: " + ruleId);

  if (checkers.size() == 0)
    throw Error("No <rule.checker> is specified in rule: " + ruleId);

  if (isForData) {
    auto rule = make_shared<conf::Rule>(ruleId);
    for (size_t i = 0; i < filters.size(); i++)
      rule->addFilter(filters[i]);
    for (size_t i = 0; i < checkers.size(); i++)
      rule->addChecker(checkers[i]);

    m_dataRules.push_back(rule);
  }
}

bool
PolicyChecker::check(const Timestamp& dataTimestamp, const Data& data,
                     const Timestamp& keyTimestamp, const ndn::IdentityCertificate& cert)
{
  system_clock::TimePoint dataTs((time::seconds(dataTimestamp)));
  system_clock::TimePoint keyTs((time::seconds(keyTimestamp)));
  system_clock::TimePoint endTs = cert.getNotAfter();
  system_clock::TimePoint startTs = cert.getNotBefore();

  if (dataTs > endTs || dataTs < keyTs || dataTs < startTs)
    return false;

  if (!checkRule(data))
    return false;

  Name keyLocatorName;
  try {
    keyLocatorName = data.getSignature().getKeyLocator().getName();
  }
  catch (tlv::Error&) {
    return false;
  }

  if (!keyLocatorName.isPrefixOf(cert.getName()))
    return false;

  if (!ndn::Validator::verifySignature(data, cert.getPublicKeyInfo()))
    return false;

  return true;
}

bool
PolicyChecker::checkRule(const Data& data)
{
  for (auto& rule : m_dataRules) {
    if (rule->match(data)) {
      return rule->check(data);
    }
  }

  return false;
}


} // namespace nsl
