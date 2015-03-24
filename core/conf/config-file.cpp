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

#include "config-file.hpp"
#include <boost/property_tree/info_parser.hpp>
#include <boost/filesystem.hpp>
namespace nsl {
namespace conf {

ConfigFile::ConfigFile(const std::string& filename)
  : m_filename(filename)
{
}

void
ConfigFile::parse()
{
  std::ifstream input;
  input.open(m_filename.c_str());
  if (!input.good() || !input.is_open())
    throw Error("Failed to read configuration file: " + m_filename);

  ConfigSection configSection;
  try {
    boost::property_tree::read_info(input, configSection);
  }
  catch (boost::property_tree::info_parser_error& error) {
    std::stringstream msg;
    msg << "Failed to parse configuration file";
    msg << " " << m_filename;
    msg << " " << error.message() << " line " << error.line();
    throw Error(msg.str());
  }

  bool hasLoggerName = false;
  bool hasDbDir = false;
  bool hasPolicy = false;
  bool hasValidatorRule = false;
  for (const auto& section : configSection) {
    if (boost::iequals(section.first, "logger-name")) {
      try {
        m_loggerName = Name(section.second.data());
      }
      catch (Name::Error& e) {
        throw Error("Wrong logger-name: " + section.second.data());
      }
      hasLoggerName = true;
    }
    else if (boost::iequals(section.first, "db-dir")) {
      using namespace boost::filesystem;

      m_dbDir = absolute(section.second.data(), path(m_filename).parent_path()).string();
      hasDbDir = true;
    }
    else if (boost::iequals(section.first, "policy")) {
      m_policy = section.second;
      hasPolicy = true;
    }
    else if (boost::iequals(section.first, "validator")) {
      m_validatorRule = section.second;
      hasValidatorRule = true;
    }
    else
      throw Error("Error in loading policy checker: unrecognized section " + section.first);
  }

  if (!hasDbDir) {
    m_dbDir = boost::filesystem::path(m_filename).parent_path().string();
    hasDbDir = true;
  }

  if (hasDbDir && hasLoggerName && hasPolicy && hasValidatorRule)
    return;

  throw Error("incomplete configuration");
}

} // namespace conf
} // namespace nsl
