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

#include "conf/config-file.hpp"

#include <boost/filesystem.hpp>
#include <fstream>

#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestConfig)

BOOST_AUTO_TEST_CASE(Basic)
{
  const std::string CONFIG =
    "logger-name /test/logger                             \n"
    "db-dir /test/db                                      \n"
    "policy                                               \n"
    "{                                                    \n"
    "  policy-key policy-value                            \n"
    "}                                                    \n"
    "validator                                            \n"
    "{                                                    \n"
    "  validator-key validator-value                      \n"
    "}                                                    \n";

  namespace fs = boost::filesystem;

  fs::create_directory(fs::path(TEST_LOGGER_PATH));

  fs::path configPath = fs::path(TEST_LOGGER_PATH) / "logger-test.conf";
  std::ofstream os(configPath.c_str());
  os << CONFIG;
  os.close();

  conf::ConfigFile config(configPath.string());

  BOOST_CHECK_NO_THROW(config.parse());

  BOOST_CHECK_EQUAL(config.getConfFileName(), configPath.string());
  BOOST_CHECK_EQUAL(config.getLoggerName(), Name("/test/logger"));
  BOOST_CHECK_EQUAL(config.getDbDir(), "/test/db");
  BOOST_CHECK_EQUAL(config.getPolicy().begin()->first, "policy-key");
  BOOST_CHECK_EQUAL(config.getPolicy().begin()->second.data(), "policy-value");
  BOOST_CHECK_EQUAL(config.getValidatorRule().begin()->first, "validator-key");
  BOOST_CHECK_EQUAL(config.getValidatorRule().begin()->second.data(), "validator-value");

  fs::remove_all(fs::path(TEST_LOGGER_PATH));
}

BOOST_AUTO_TEST_CASE(Basic2)
{
  const std::string CONFIG =
    "logger-name /test/logger                             \n"
    "policy                                               \n"
    "{                                                    \n"
    "  policy-key policy-value                            \n"
    "}                                                    \n"
    "validator                                            \n"
    "{                                                    \n"
    "  validator-key validator-value                      \n"
    "}                                                    \n";

  namespace fs = boost::filesystem;

  fs::create_directory(fs::path(TEST_LOGGER_PATH));

  fs::path configPath = fs::path(TEST_LOGGER_PATH) / "logger-test.conf";
  std::ofstream os(configPath.c_str());
  os << CONFIG;
  os.close();

  conf::ConfigFile config(configPath.string());

  BOOST_CHECK_NO_THROW(config.parse());

  BOOST_CHECK_EQUAL(config.getConfFileName(), configPath.string());
  BOOST_CHECK_EQUAL(config.getLoggerName(), Name("/test/logger"));
  BOOST_CHECK_EQUAL(config.getDbDir(), fs::path(TEST_LOGGER_PATH).string());
  BOOST_CHECK_EQUAL(config.getPolicy().begin()->first, "policy-key");
  BOOST_CHECK_EQUAL(config.getPolicy().begin()->second.data(), "policy-value");
  BOOST_CHECK_EQUAL(config.getValidatorRule().begin()->first, "validator-key");
  BOOST_CHECK_EQUAL(config.getValidatorRule().begin()->second.data(), "validator-value");

  fs::remove_all(fs::path(TEST_LOGGER_PATH));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
