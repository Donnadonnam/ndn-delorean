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

#ifndef NSL_CONF_RULE_HPP
#define NSL_CONF_RULE_HPP

#include "filter.hpp"
#include "checker.hpp"

namespace nsl {
namespace conf {

class Rule
{
public:
  explicit
  Rule(const std::string& id);

  virtual
  ~Rule();

  const std::string&
  getId();

  void
  addFilter(const shared_ptr<Filter>& filter);

  void
  addChecker(const shared_ptr<Checker>& checker);

  bool
  match(const Data& data);

  /**
   * @brief check if data satisfies certain condition
   *
   * @param packet The packet
   * @return false if data is immediately invalid
   */
  bool
  check(const Data& data);

private:
  typedef std::vector<shared_ptr<Filter> > FilterList;
  typedef std::vector<shared_ptr<Checker> > CheckerList;

  std::string m_id;
  FilterList m_filters;
  CheckerList m_checkers;
};

} // namespace conf
} // namespace nsl

#endif // NSL_CONF_RULE_HPP
