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

#ifndef NDN_DELOREAN_TESTS_IDENTITY_FIXTURE_HPP
#define NDN_DELOREAN_TESTS_IDENTITY_FIXTURE_HPP

#include "unit-test-time-fixture.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <vector>

#include <boost/filesystem.hpp>

namespace nsl {
namespace tests {

class IdentityFixture : public UnitTestTimeFixture
{
public:
  IdentityFixture()
    : m_keyChainTmpPath(boost::filesystem::path(TEST_KEYCHAIN_PATH) / "IdentityFixture")
    , m_keyChain(std::string("pib-sqlite3:").append(m_keyChainTmpPath.string()),
                 std::string("tpm-file:").append(m_keyChainTmpPath.string()))
  {
  }

  ~IdentityFixture()
  {
    for (const auto& identity : m_identities) {
      m_keyChain.deleteIdentity(identity);
    }

    boost::filesystem::remove_all(m_keyChainTmpPath);
  }
  /// @brief add identity, return true if succeed.
  bool
  addIdentity(const Name& identity,
              const ndn::KeyParams& params = ndn::KeyChain::DEFAULT_KEY_PARAMS)
  {
    try {
      m_keyChain.createIdentity(identity, params);
      m_identities.push_back(identity);
      return true;
    }
    catch (std::runtime_error&) {
      return false;
    }
  }

protected:
  boost::filesystem::path m_keyChainTmpPath;
  ndn::KeyChain m_keyChain;
  std::vector<Name> m_identities;
};

} // namespace tests
} // namespace nsl

#endif // NDN_DELOREAN_TESTS_IDENTITY_FIXTURE_HPP
