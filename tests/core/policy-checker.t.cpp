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

#include "policy-checker.hpp"
#include "identity-fixture.hpp"
#include <boost/property_tree/info_parser.hpp>

#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestPolicyChecker, IdentityFixture)

BOOST_AUTO_TEST_CASE(TimeCheck)
{
  const std::string CONFIG =
    "rule                                               \n"
    "{                                                  \n"
    "  id \"Simple Rule\"                               \n"
    "  for data                                         \n"
    "  checker                                          \n"
    "  {                                                \n"
    "    type customized                                \n"
    "    sig-type rsa-sha256                            \n"
    "    key-locator                                    \n"
    "    {                                              \n"
    "      type name                                    \n"
    "      hyper-relation                               \n"
    "      {                                            \n"
    "        k-regex ^([^<KEY>]*)<KEY>(<>*)<><ID-CERT>$ \n"
    "        k-expand \\\\1\\\\2                        \n"
    "        h-relation is-strict-prefix-of             \n"
    "        p-regex ^(<>*)$                            \n"
    "        p-expand \\\\1                             \n"
    "      }                                            \n"
    "    }                                              \n"
    "  }                                                \n"
    "}                                                  \n";

  std::istringstream input(CONFIG);
  conf::ConfigSection policy;
  BOOST_REQUIRE_NO_THROW(boost::property_tree::read_info(input, policy));

  PolicyChecker policyChecker;
  policyChecker.loadPolicy(policy);

  Name identity("/test/id");
  addIdentity(identity);
  Name selfSignedCertName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  auto selfSignedCert = m_keyChain.getCertificate(selfSignedCertName);

  time::system_clock::TimePoint notBefore = time::system_clock::now();
  time::system_clock::TimePoint notAfter = time::system_clock::now() + time::seconds(10);
  std::vector<ndn::CertificateSubjectDescription> subDesc;

  auto unsignedCert =
    m_keyChain.prepareUnsignedIdentityCertificate(selfSignedCert->getPublicKeyName(),
                                                  selfSignedCert->getPublicKeyInfo(),
                                                  identity,
                                                  notBefore,
                                                  notAfter,
                                                  subDesc);

  m_keyChain.sign(*unsignedCert, selfSignedCertName);
  m_keyChain.addCertificate(*unsignedCert);

  time::system_clock::TimePoint dataTs1 = time::system_clock::now() + time::seconds(5);
  time::system_clock::TimePoint dataTs2 = time::system_clock::now() + time::seconds(1);
  time::system_clock::TimePoint dataTs3 = time::system_clock::now() + time::seconds(15);
  time::system_clock::TimePoint dataTs4 = time::system_clock::now() - time::seconds(1);
  time::system_clock::TimePoint keyTs1 = time::system_clock::now() + time::seconds(2);
  time::system_clock::TimePoint keyTs2 = time::system_clock::now() - time::seconds(2);
  Timestamp dataTimestamp1 = time::toUnixTimestamp(dataTs1).count() / 1000;
  Timestamp dataTimestamp2 = time::toUnixTimestamp(dataTs2).count() / 1000;
  Timestamp dataTimestamp3 = time::toUnixTimestamp(dataTs3).count() / 1000;
  Timestamp dataTimestamp4 = time::toUnixTimestamp(dataTs4).count() / 1000;
  Timestamp keyTimestamp1 = time::toUnixTimestamp(keyTs1).count() / 1000;
  Timestamp keyTimestamp2 = time::toUnixTimestamp(keyTs2).count() / 1000;

  Data data("/test/id/data");
  m_keyChain.sign(data, unsignedCert->getName());

  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp1, data, keyTimestamp1, *unsignedCert), true);
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp2, data, keyTimestamp1, *unsignedCert), false);
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp3, data, keyTimestamp1, *unsignedCert), false);
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp4, data, keyTimestamp2, *unsignedCert), false);
}

BOOST_AUTO_TEST_CASE(RuleCheck)
{
  const std::string CONFIG =
    "rule                                               \n"
    "{                                                  \n"
    "  id \"Simple Rule\"                               \n"
    "  for data                                         \n"
    "  checker                                          \n"
    "  {                                                \n"
    "    type customized                                \n"
    "    sig-type rsa-sha256                            \n"
    "    key-locator                                    \n"
    "    {                                              \n"
    "      type name                                    \n"
    "      hyper-relation                               \n"
    "      {                                            \n"
    "        k-regex ^([^<KEY>]*)<KEY>(<>*)<><ID-CERT>$ \n"
    "        k-expand \\\\1\\\\2                        \n"
    "        h-relation is-strict-prefix-of             \n"
    "        p-regex ^(<>*)$                            \n"
    "        p-expand \\\\1                             \n"
    "      }                                            \n"
    "    }                                              \n"
    "  }                                                \n"
    "}                                                  \n";

  std::istringstream input(CONFIG);
  conf::ConfigSection policy;
  BOOST_REQUIRE_NO_THROW(boost::property_tree::read_info(input, policy));

  PolicyChecker policyChecker;
  policyChecker.loadPolicy(policy);


  Name identity("/test/id");
  addIdentity(identity);
  Name selfSignedCertName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  auto selfSignedCert = m_keyChain.getCertificate(selfSignedCertName);

  time::system_clock::TimePoint notBefore = time::system_clock::now();
  time::system_clock::TimePoint notAfter = time::system_clock::now() + time::seconds(10);
  std::vector<ndn::CertificateSubjectDescription> subDesc;

  auto unsignedCert =
    m_keyChain.prepareUnsignedIdentityCertificate(selfSignedCert->getPublicKeyName(),
                                                  selfSignedCert->getPublicKeyInfo(),
                                                  identity,
                                                  notBefore,
                                                  notAfter,
                                                  subDesc);

  m_keyChain.sign(*unsignedCert, selfSignedCertName);
  m_keyChain.addCertificate(*unsignedCert);

  time::system_clock::TimePoint dataTs1 = time::system_clock::now() + time::seconds(5);
  time::system_clock::TimePoint keyTs1 = time::system_clock::now() + time::seconds(2);
  Timestamp dataTimestamp1 = time::toUnixTimestamp(dataTs1).count() / 1000;
  Timestamp keyTimestamp1 = time::toUnixTimestamp(keyTs1).count() / 1000;


  Data data1("/test/id/data");
  m_keyChain.sign(data1, unsignedCert->getName());
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp1, data1, keyTimestamp1, *unsignedCert),
                    true);

  Data data2("/test/id");
  m_keyChain.sign(data2, unsignedCert->getName());
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp1, data2, keyTimestamp1, *unsignedCert),
                    false);

  Data data3("/test/wrong");
  m_keyChain.sign(data3, unsignedCert->getName());
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp1, data3, keyTimestamp1, *unsignedCert),
                    false);

  Data data4("/test");
  m_keyChain.sign(data4, unsignedCert->getName());
  BOOST_CHECK_EQUAL(policyChecker.check(dataTimestamp1, data4, keyTimestamp1, *unsignedCert),
                    false);
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
