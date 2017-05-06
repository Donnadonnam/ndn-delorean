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

#ifndef NDN_DELOREAN_CONF_KEY_LOCATOR_CHECKER_HPP
#define NDN_DELOREAN_CONF_KEY_LOCATOR_CHECKER_HPP

#include "common.hpp"
#include "config.hpp"
#include <ndn-cxx/util/regex.hpp>

namespace nsl {
namespace conf {

class KeyLocatorCheckerFactory;

/**
 * @brief KeyLocatorChecker is one of the classes used by ValidatorConfig.
 *
 * The ValidatorConfig class consists of a set of rules.
 * The KeyLocatorChecker class is part of a rule and is used to check if the KeyLocator field of a
 * packet satisfy the requirements.
 */


class KeyLocatorChecker
{
public:
  enum Relation {
    RELATION_EQUAL,
    RELATION_IS_PREFIX_OF,
    RELATION_IS_STRICT_PREFIX_OF
  };

  virtual
  ~KeyLocatorChecker();

  bool
  check(const Data& data, const KeyLocator& keyLocator, std::string& failInfo);

protected:
  virtual bool
  check(const Name& packetName, const KeyLocator& keyLocator, std::string& failInfo) = 0;

  bool
  checkRelation(const Relation& relation, const Name& name1, const Name& name2);
};

class RelationKeyLocatorNameChecker : public KeyLocatorChecker
{
public:
  RelationKeyLocatorNameChecker(const Name& name, const KeyLocatorChecker::Relation& relation);

protected:
  virtual bool
  check(const Name& packetName, const KeyLocator& keyLocator, std::string& failInfo);

private:
  Name m_name;
  KeyLocatorChecker::Relation m_relation;
};

class RegexKeyLocatorNameChecker : public KeyLocatorChecker
{
public:
  explicit
  RegexKeyLocatorNameChecker(const ndn::Regex& regex);

protected:
  virtual bool
  check(const Name& packetName, const KeyLocator& keyLocator, std::string& failInfo);

private:
  ndn::Regex m_regex;
};

class HyperKeyLocatorNameChecker : public KeyLocatorChecker
{
public:
  HyperKeyLocatorNameChecker(const std::string& pExpr, const std::string pExpand,
                             const std::string& kExpr, const std::string kExpand,
                             const Relation& hyperRelation);

protected:
  virtual bool
  check(const Name& packetName, const KeyLocator& keyLocator, std::string& failInfo);

private:
  shared_ptr<ndn::Regex> m_hyperPRegex;
  shared_ptr<ndn::Regex> m_hyperKRegex;
  Relation m_hyperRelation;
};


class KeyLocatorCheckerFactory
{
public:
  static shared_ptr<KeyLocatorChecker>
  create(const ConfigSection& configSection);

private:
  static shared_ptr<KeyLocatorChecker>
  createKeyLocatorNameChecker(const ConfigSection& configSection);
};


} // namespace conf
} // namespace nsl

#endif // NDN_DELOREAN_CONF_KEY_LOCATOR_CHECKER_HPP
