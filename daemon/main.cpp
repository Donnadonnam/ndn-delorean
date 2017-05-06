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

#include "common.hpp"
#include "../core/logger.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>

int
main(int argc, char** argv)
{
  namespace po = boost::program_options;
  namespace fs = boost::filesystem;

  std::string configFile;

  po::options_description description("General Usage\n"
                                      "  nsl [-h] [-c config]\n"
                                      "General options");
  description.add_options()
    ("help,h", "produce help message")
    ("config,c", po::value<std::string>(&configFile))
    ;

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, description), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (vm.count("help") != 0) {
    std::cerr << description << std::endl;
    return 0;
  }

  if (vm.count("config") == 0) {

    if (!getenv("HOME")) {
      configFile = NDN_DELOREAN_DEFAULT_CONFIG_FILE;
    }
    else {
      configFile = getenv("HOME");
      configFile += "/.ndn/ndn-delorean.conf";
    }

    if (!fs::exists(fs::path(configFile))) {
      std::cerr << "ERROR: config file is not available: " << configFile << std::endl;
      return 1;
    }
  }

  try {
    ndn::Face face;
    ndn::delorean::Logger(face, configFile);
    face.processEvents();
  }
  catch (std::runtime_error& e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }

  return 0;
}
