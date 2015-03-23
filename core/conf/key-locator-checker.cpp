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

#include "key-locator-checker.hpp"

#include <boost/algorithm/string.hpp>

namespace nsl {
namespace conf {

KeyLocatorChecker::~KeyLocatorChecker()
{
}

bool
KeyLocatorChecker::check(const Data& data, const KeyLocator& keyLocator, std::string& failInfo)
{
  return check(data.getName(), keyLocator, failInfo);
}

bool
KeyLocatorChecker::checkRelation(const Relation& relation, const Name& name1, const Name& name2)
{
  switch (relation) {
  case RELATION_EQUAL:
    return (name1 == name2);
  case RELATION_IS_PREFIX_OF:
    return name1.isPrefixOf(name2);
  case RELATION_IS_STRICT_PREFIX_OF:
    return (name1.isPrefixOf(name2) && name1 != name2);
  default:
    return false;
  }
}

RelationKeyLocatorNameChecker::RelationKeyLocatorNameChecker(const Name& name,
  const KeyLocatorChecker::Relation& relation)
  : m_name(name)
  , m_relation(relation)
{
}

bool
RelationKeyLocatorNameChecker::check(const Name& packetName,
                                     const KeyLocator& keyLocator,
                                     std::string& failInfo)
{
  try {
    if (checkRelation(m_relation, m_name, keyLocator.getName()))
      return true;

    failInfo = "KeyLocatorChecker failed";
    return false;
  }
  catch (KeyLocator::Error&) {
    failInfo = "KeyLocator does not have name";
    return false;
  }
}

RegexKeyLocatorNameChecker::RegexKeyLocatorNameChecker(const ndn::Regex& regex)
  : m_regex(regex)
{
}

bool
RegexKeyLocatorNameChecker::check(const Name& packetName,
                                  const KeyLocator& keyLocator,
                                  std::string& failInfo)
{
  try {
    if (m_regex.match(keyLocator.getName()))
      return true;

    failInfo = "KeyLocatorChecker failed";
    return false;
  }
  catch (KeyLocator::Error&) {
    failInfo = "KeyLocator does not have name";
    return false;
  }
}

HyperKeyLocatorNameChecker::HyperKeyLocatorNameChecker(const std::string& pExpr,
                                                       const std::string pExpand,
                                                       const std::string& kExpr,
                                                       const std::string kExpand,
                                                       const Relation& hyperRelation)
  : m_hyperPRegex(new ndn::Regex(pExpr, pExpand))
  , m_hyperKRegex(new ndn::Regex(kExpr, kExpand))
  , m_hyperRelation(hyperRelation)
{
}

bool
HyperKeyLocatorNameChecker::check(const Name& packetName,
                                  const KeyLocator& keyLocator,
                                  std::string& failInfo)
{
  try {
    if (m_hyperPRegex->match(packetName) &&
        m_hyperKRegex->match(keyLocator.getName()) &&
        checkRelation(m_hyperRelation,
                      m_hyperKRegex->expand(),
                      m_hyperPRegex->expand()))
      return true;

    failInfo = "KeyLocatorChecker failed";
    return false;
  }
  catch (KeyLocator::Error&) {
    failInfo = "KeyLocator does not have name";
    return false;
  }
}

shared_ptr<KeyLocatorChecker>
KeyLocatorCheckerFactory::create(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();

  // Get checker.key-locator.type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "type"))
    throw Error("Expect <checker.key-locator.type>");

  std::string type = propertyIt->second.data();

  if (boost::iequals(type, "name"))
    return createKeyLocatorNameChecker(configSection);
  else
    throw Error("Unsupported checker.key-locator.type: " + type);
}

shared_ptr<KeyLocatorChecker>
KeyLocatorCheckerFactory::createKeyLocatorNameChecker(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();
  propertyIt++;

  if (propertyIt == configSection.end())
    throw Error("Expect more checker.key-locator properties");

  if (boost::iequals(propertyIt->first, "name")) {
    Name name;
    try {
      name = Name(propertyIt->second.data());
    }
    catch (Name::Error& e) {
      throw Error("Invalid checker.key-locator.name: " +
                  propertyIt->second.data());
    }
    propertyIt++;

    if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "relation"))
      throw Error("Expect <checker.key-locator.relation>!");

    std::string relationString = propertyIt->second.data();
    propertyIt++;

    KeyLocatorChecker::Relation relation;
    if (boost::iequals(relationString, "equal"))
      relation = KeyLocatorChecker::RELATION_EQUAL;
    else if (boost::iequals(relationString, "is-prefix-of"))
      relation = KeyLocatorChecker::RELATION_IS_PREFIX_OF;
    else if (boost::iequals(relationString, "is-strict-prefix-of"))
      relation = KeyLocatorChecker::RELATION_IS_STRICT_PREFIX_OF;
    else
      throw Error("Unsupported relation: " + relationString);

    if (propertyIt != configSection.end())
      throw Error("Expect the end of checker.key-locator!");

    return shared_ptr<RelationKeyLocatorNameChecker>
      (new RelationKeyLocatorNameChecker(name, relation));
  }
  else if (boost::iequals(propertyIt->first, "regex")) {
    std::string regexString = propertyIt->second.data();
    propertyIt++;

    if (propertyIt != configSection.end())
      throw Error("Expect the end of checker.key-locator!");

    try {
      return shared_ptr<RegexKeyLocatorNameChecker>
        (new RegexKeyLocatorNameChecker(regexString));
    }
    catch (ndn::Regex::Error& e) {
      throw Error("Invalid checker.key-locator.regex: " + regexString);
    }
  }
  else if (boost::iequals(propertyIt->first, "hyper-relation")) {
    const ConfigSection& hSection = propertyIt->second;

    ConfigSection::const_iterator hPropertyIt = hSection.begin();

    // Get k-regex
    if (hPropertyIt == hSection.end() || !boost::iequals(hPropertyIt->first, "k-regex"))
      throw Error("Expect <checker.key-locator.hyper-relation.k-regex>!");

    std::string kRegex = hPropertyIt->second.data();
    hPropertyIt++;

    // Get k-expand
    if (hPropertyIt == hSection.end() || !boost::iequals(hPropertyIt->first, "k-expand"))
      throw Error("Expect <checker.key-locator.hyper-relation.k-expand>!");

    std::string kExpand = hPropertyIt->second.data();
    hPropertyIt++;

    // Get h-relation
    if (hPropertyIt == hSection.end() || !boost::iequals(hPropertyIt->first, "h-relation"))
      throw Error("Expect <checker.key-locator.hyper-relation.h-relation>!");

    std::string hRelation = hPropertyIt->second.data();
    hPropertyIt++;

    // Get p-regex
    if (hPropertyIt == hSection.end() || !boost::iequals(hPropertyIt->first, "p-regex"))
      throw Error("Expect <checker.key-locator.hyper-relation.p-regex>!");

    std::string pRegex = hPropertyIt->second.data();
    hPropertyIt++;

    // Get p-expand
    if (hPropertyIt == hSection.end() || !boost::iequals(hPropertyIt->first, "p-expand"))
      throw Error("Expect <checker.key-locator.hyper-relation.p-expand>!");

    std::string pExpand = hPropertyIt->second.data();
    hPropertyIt++;

    if (hPropertyIt != hSection.end())
      throw Error("Expect the end of checker.key-locator.hyper-relation!");

    KeyLocatorChecker::Relation relation;
    if (boost::iequals(hRelation, "equal"))
      relation = KeyLocatorChecker::RELATION_EQUAL;
    else if (boost::iequals(hRelation, "is-prefix-of"))
      relation = KeyLocatorChecker::RELATION_IS_PREFIX_OF;
    else if (boost::iequals(hRelation, "is-strict-prefix-of"))
      relation = KeyLocatorChecker::RELATION_IS_STRICT_PREFIX_OF;
    else
      throw Error("Unsupported checker.key-locator.hyper-relation.h-relation: " + hRelation);

    try {
      return shared_ptr<HyperKeyLocatorNameChecker>
        (new HyperKeyLocatorNameChecker(pRegex, pExpand,
                                        kRegex, kExpand,
                                        relation));
    }
    catch (ndn::Regex::Error& e) {
      throw Error("Invalid regex for key-locator.hyper-relation");
    }
  }
  else
    throw Error("Unsupported checker.key-locator");
}

} // namespace conf
} // namespace nsl
