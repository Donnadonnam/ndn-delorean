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

#ifndef NDN_DELOREAN_CONF_FILTER_HPP
#define NDN_DELOREAN_CONF_FILTER_HPP

#include "common.hpp"
#include "config.hpp"
#include <ndn-cxx/util/regex.hpp>

namespace ndn {
namespace delorean {
namespace conf {

/**
 * @brief Filter is one of the classes used by ValidatorConfig.
 *
 * The ValidatorConfig class consists of a set of rules.
 * The Filter class is a part of a rule and is used to match packet.
 * Matched packets will be checked against the checkers defined in the rule.
 */

class Filter
{
public:

  virtual
  ~Filter();

  bool
  match(const Data& data);

protected:
  virtual bool
  matchName(const Name& name) = 0;
};

class RelationNameFilter : public Filter
{
public:
  enum Relation
    {
      RELATION_EQUAL,
      RELATION_IS_PREFIX_OF,
      RELATION_IS_STRICT_PREFIX_OF
    };

  RelationNameFilter(const Name& name, Relation relation);

  virtual
  ~RelationNameFilter();

protected:
  virtual bool
  matchName(const Name& name);

private:
  Name m_name;
  Relation m_relation;
};

class RegexNameFilter : public Filter
{
public:
  explicit
  RegexNameFilter(const ndn::Regex& regex);

  virtual
  ~RegexNameFilter();

protected:
  virtual bool
  matchName(const Name& name);

private:
  ndn::Regex m_regex;
};

class FilterFactory
{
public:
  static shared_ptr<Filter>
  create(const ConfigSection& configSection);

private:
  static shared_ptr<Filter>
  createNameFilter(const ConfigSection& configSection);
};

} // namespace conf
} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_CONF_FILTER_HPP
