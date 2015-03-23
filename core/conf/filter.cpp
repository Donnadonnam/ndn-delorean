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


#include "filter.hpp"

#include <boost/algorithm/string.hpp>

namespace nsl {
namespace conf {

Filter::~Filter()
{
}

bool
Filter::match(const Data& data)
{
  return matchName(data.getName());
}

RelationNameFilter::RelationNameFilter(const Name& name, Relation relation)
  : m_name(name)
  , m_relation(relation)
{
}

RelationNameFilter::~RelationNameFilter()
{
}

bool
RelationNameFilter::matchName(const Name& name)
{
  switch (m_relation) {
  case RELATION_EQUAL:
    return (name == m_name);
  case RELATION_IS_PREFIX_OF:
    return m_name.isPrefixOf(name);
  case RELATION_IS_STRICT_PREFIX_OF:
    return (m_name.isPrefixOf(name) && m_name.size() < name.size());
  default:
    return false;
  }
}

RegexNameFilter::RegexNameFilter(const ndn::Regex& regex)
  : m_regex(regex)
{
}

RegexNameFilter::~RegexNameFilter()
{
}

bool
RegexNameFilter::matchName(const Name& name)
{
  return m_regex.match(name);
}

shared_ptr<Filter>
FilterFactory::create(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();

  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "type"))
    throw Error("Expect <filter.type>!");

  std::string type = propertyIt->second.data();

  if (boost::iequals(type, "name"))
    return createNameFilter(configSection);
  else
    throw Error("Unsupported filter.type: " + type);
}

shared_ptr<Filter>
FilterFactory::createNameFilter(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();
  propertyIt++;

  if (propertyIt == configSection.end())
    throw Error("Expect more properties for filter(name)");

  if (boost::iequals(propertyIt->first, "name")) {
    // Get filter.name
    Name name;
    try {
      name = Name(propertyIt->second.data());
    }
    catch (Name::Error& e) {
      throw Error("Wrong filter.name: " + propertyIt->second.data());
    }

    propertyIt++;

    // Get filter.relation
    if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "relation"))
      throw Error("Expect <filter.relation>!");

    std::string relationString = propertyIt->second.data();
    propertyIt++;

    RelationNameFilter::Relation relation;
    if (boost::iequals(relationString, "equal"))
      relation = RelationNameFilter::RELATION_EQUAL;
    else if (boost::iequals(relationString, "is-prefix-of"))
      relation = RelationNameFilter::RELATION_IS_PREFIX_OF;
    else if (boost::iequals(relationString, "is-strict-prefix-of"))
      relation = RelationNameFilter::RELATION_IS_STRICT_PREFIX_OF;
    else
      throw Error("Unsupported relation: " + relationString);

    if (propertyIt != configSection.end())
      throw Error("Expect the end of filter!");

    return make_shared<RelationNameFilter>(name, relation);
  }
  else if (boost::iequals(propertyIt->first, "regex")) {
    std::string regexString = propertyIt->second.data();
    propertyIt++;

    if (propertyIt != configSection.end())
      throw Error("Expect the end of filter!");

    try {
      return shared_ptr<RegexNameFilter>(new RegexNameFilter(regexString));
    }
    catch (ndn::Regex::Error& e) {
      throw Error("Wrong filter.regex: " + regexString);
    }
  }
  else
    throw Error("Wrong filter(name) properties");
}

} // namespace conf
} // namespace ndn
