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

#ifndef NDN_DELOREAN_TESTS_DB_FIXTURE_HPP
#define NDN_DELOREAN_TESTS_DB_FIXTURE_HPP

#include "db.hpp"
#include <boost/filesystem.hpp>

namespace nsl {
namespace tests {

class DbFixture
{
public:
  DbFixture()
    : m_dbTmpPath(boost::filesystem::path(TEST_DB_PATH) / "DbTest")
  {
    db.open(m_dbTmpPath.c_str());
  }

  ~DbFixture()
  {
    boost::filesystem::remove_all(m_dbTmpPath);
  }

protected:
  boost::filesystem::path m_dbTmpPath;

public:
  Db db;
};

} // namespace tests
} // namespace nsl

#endif // NDN_DELOREAN_TESTS_DB_FIXTURE_HPP
