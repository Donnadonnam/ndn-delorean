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

#include "rule.hpp"

namespace ndn {
namespace delorean {
namespace conf {

Rule::Rule(const std::string& id)
  : m_id(id)
{
}

Rule::~Rule()
{
}

const std::string&
Rule::getId()
{
  return m_id;
}

void
Rule::addFilter(const shared_ptr<Filter>& filter)
{
  m_filters.push_back(filter);
}

void
Rule::addChecker(const shared_ptr<Checker>& checker)
{
  m_checkers.push_back(checker);
}

bool
Rule::match(const Data& data)
{
  if (m_filters.empty())
    return true;

  for (auto& filter : m_filters) {
    if (!filter->match(data))
      return false;
  }

  return true;
}

bool
Rule::check(const Data& data)
{
  for (auto& checker : m_checkers) {
    bool result = checker->check(data);
    if (result)
      return result;
  }

  return false;
}

} // namespace conf
} // namespace delorean
} // namespace ndn
