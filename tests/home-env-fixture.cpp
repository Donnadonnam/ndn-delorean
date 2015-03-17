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

#include "common.hpp"
#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace nsl {
namespace tests {

class HomeEnvFixture
{
public:
  HomeEnvFixture()
  {
    // initialize KeyChain from test specific HOME: TEST_HOME_PATH
    if (std::getenv("HOME"))
      m_HOME = std::getenv("HOME");

    setenv("HOME", "tests/test-home", 1);
  }

  ~HomeEnvFixture()
  {
    boost::filesystem::remove_all(boost::filesystem::path("/tmp/test/nsl"));

    if (!m_HOME.empty())
      setenv("HOME", m_HOME.c_str(), 1);
    else
      unsetenv("HOME");
  }

private:
  std::string m_HOME;

  Name m_newIdentity;
};

BOOST_GLOBAL_FIXTURE(HomeEnvFixture)

} // namespace tests
} // namespace nsl
