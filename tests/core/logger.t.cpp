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

#include "logger.hpp"
#include "identity-fixture.hpp"
#include "db-fixture.hpp"
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/util/io.hpp>

#include "boost-test.hpp"

namespace ndn {
namespace delorean {
namespace tests {

class LoggerFixture : public IdentityFixture
                    , public DbFixture
{
public:
  LoggerFixture()
    : face1(io, {true, true})
    , face2(io, {true, true})
    , readInterestOffset1(0)
    , readDataOffset1(0)
    , readInterestOffset2(0)
    , readDataOffset2(0)
  {
  }

  ~LoggerFixture()
  {
  }

  bool
  passPacket()
  {
    bool hasPassed = false;

    checkFace(face1.sentInterests, readInterestOffset1, face2, hasPassed);
    checkFace(face1.sentData, readDataOffset1, face2, hasPassed);
    checkFace(face2.sentInterests, readInterestOffset2, face1, hasPassed);
    checkFace(face2.sentData, readDataOffset2, face1, hasPassed);

    return hasPassed;
  }

  template<typename Packet>
  void
  checkFace(std::vector<Packet>& receivedPackets,
            size_t& readPacketOffset,
            ndn::util::DummyClientFace& receiver,
            bool& hasPassed)
  {
    while (receivedPackets.size() > readPacketOffset) {
      receiver.receive(receivedPackets[readPacketOffset]);
      readPacketOffset++;
      hasPassed = true;
    }
  }

  void
  clear()
  {
    face1.sentData.clear();
    face1.sentInterests.clear();
    face2.sentData.clear();
    face2.sentInterests.clear();

    readInterestOffset1 = 0;
    readDataOffset1 = 0;
    readInterestOffset2 = 0;
    readDataOffset2 = 0;
  }

public:
  ndn::util::DummyClientFace face1;
  ndn::util::DummyClientFace face2;

  size_t readInterestOffset1;
  size_t readDataOffset1;
  size_t readInterestOffset2;
  size_t readDataOffset2;
};

BOOST_FIXTURE_TEST_SUITE(TestLogger, LoggerFixture)

const std::string CONFIG =
  "logger-name /test/logger                             \n"
  "policy                                               \n"
  "{                                                    \n"
  "  rule                                               \n"
  "  {                                                  \n"
  "    id \"Simple Rule\"                               \n"
  "    for data                                         \n"
  "    checker                                          \n"
  "    {                                                \n"
  "      type customized                                \n"
  "      sig-type rsa-sha256                            \n"
  "      key-locator                                    \n"
  "      {                                              \n"
  "        type name                                    \n"
  "        hyper-relation                               \n"
  "        {                                            \n"
  "          k-regex ^([^<KEY>]*)<KEY>(<>*)<><ID-CERT>$ \n"
  "          k-expand \\\\1\\\\2                        \n"
  "          h-relation is-strict-prefix-of             \n"
  "          p-regex ^(<>*)$                            \n"
  "          p-expand \\\\1                             \n"
  "        }                                            \n"
  "      }                                              \n"
  "    }                                                \n"
  "  }                                                  \n"
  "}                                                    \n"
  "validator                                            \n"
  "{                                                    \n"
  "  rule                                               \n"
  "  {                                                  \n"
  "    id \"Request Rule\"                              \n"
  "    for interest                                     \n"
  "    filter                                           \n"
  "    {                                                \n"
  "      type name                                      \n"
  "      name /test/logger/log                          \n"
  "      relation is-strict-prefix-of                   \n"
  "    }                                                \n"
  "    checker                                          \n"
  "    {                                                \n"
  "      type customized                                \n"
  "      sig-type rsa-sha256                            \n"
  "      key-locator                                    \n"
  "      {                                              \n"
  "        type name                                    \n"
  "        regex ^[^<KEY>]*<KEY><>*<><ID-CERT>$         \n"
  "      }                                              \n"
  "    }                                                \n"
  "  }                                                  \n"
  "  rule                                               \n"
  "  {                                                  \n"
  "    id \"Simple Rule\"                               \n"
  "    for data                                         \n"
  "    checker                                          \n"
  "    {                                                \n"
  "      type customized                                \n"
  "      sig-type rsa-sha256                            \n"
  "      key-locator                                    \n"
  "      {                                              \n"
  "        type name                                    \n"
  "        hyper-relation                               \n"
  "        {                                            \n"
  "          k-regex ^([^<KEY>]*)<KEY>(<>*)<><ID-CERT>$ \n"
  "          k-expand \\\\1\\\\2                        \n"
  "          h-relation is-strict-prefix-of             \n"
  "          p-regex ^(<>*)$                            \n"
  "          p-expand \\\\1                             \n"
  "        }                                            \n"
  "      }                                              \n"
  "    }                                                \n"
  "  }                                                  \n"
  "  trust-anchor                                       \n"
  "  {                                                  \n"
  "    type file                                        \n"
  "    file-name \"trust-anchor.cert\"                  \n"
  "  }                                                  \n"
  "}                                                    \n";

BOOST_AUTO_TEST_CASE(Basic)
{
  namespace fs = boost::filesystem;

  fs::create_directory(fs::path(TEST_LOGGER_PATH));

  fs::path configPath = fs::path(TEST_LOGGER_PATH) / "logger-test.conf";
  std::ofstream os(configPath.c_str());
  os << CONFIG;
  os.close();

  Name root("/ndn");
  addIdentity(root);
  auto rootCert = m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForIdentity(root));
  fs::path certPath = fs::path(TEST_LOGGER_PATH) / "trust-anchor.cert";
  ndn::io::save(*rootCert, certPath.string());

  Logger logger(face1, configPath.string());

  BOOST_CHECK_EQUAL(logger.getLoggerName(), Name("/test/logger"));
  BOOST_CHECK_EQUAL(logger.getTreePrefix(), Name("/test/logger/tree"));
  BOOST_CHECK_EQUAL(logger.getLeafPrefix(), Name("/test/logger/leaf"));
  BOOST_CHECK_EQUAL(logger.getLogPrefix(), Name("/test/logger/log"));

  advanceClocks(time::milliseconds(2), 100);

  Timestamp rootTs = time::toUnixTimestamp(time::system_clock::now()).count() / 1000;
  NonNegativeInteger rootSeqNo = logger.addSelfSignedCert(*rootCert, rootTs);
  BOOST_CHECK_EQUAL(rootSeqNo, 0);

  Name leafInterestName("/test/logger/leaf");
  leafInterestName.appendNumber(0);
  auto leafInterest = make_shared<Interest>(leafInterestName);

  face1.receive(*leafInterest);
  advanceClocks(time::milliseconds(2), 100);

  BOOST_CHECK_EQUAL(face1.sentData.size(), 1);
  BOOST_CHECK(leafInterestName.isPrefixOf(face1.sentData[0].getName()));

  face1.sentData.clear();

  Name treeInterestName("/test/logger/tree");
  treeInterestName.appendNumber(0);
  treeInterestName.appendNumber(0);
  auto treeInterest = make_shared<Interest>(treeInterestName);

  face1.receive(*treeInterest);
  advanceClocks(time::milliseconds(2), 100);

  BOOST_CHECK_EQUAL(face1.sentData.size(), 1);
  BOOST_CHECK(treeInterestName.isPrefixOf(face1.sentData[0].getName()));

  face1.sentData.clear();

  Name tld("/ndn/tld");
  Name tldKeyName = m_keyChain.generateRsaKeyPair(tld);
  std::vector<ndn::CertificateSubjectDescription> subjectDescription;
  auto tldCert =
    m_keyChain.prepareUnsignedIdentityCertificate(tldKeyName, root,
                                                  time::system_clock::now(),
                                                  time::system_clock::now() + time::days(1),
                                                  subjectDescription);
  m_keyChain.signByIdentity(*tldCert, root);
  m_keyChain.addCertificate(*tldCert);

  face2.setInterestFilter(tldCert->getName().getPrefix(-1),
    [&] (const ndn::InterestFilter&, const Interest&) { face2.put(*tldCert); },
    ndn::RegisterPrefixSuccessCallback(),
    [] (const Name&, const std::string&) {});
  advanceClocks(time::milliseconds(2), 100);
  clear();

  Name logInterestName("/test/logger/log");
  logInterestName.append(tldCert->getFullName().wireEncode());
  logInterestName.appendNumber(0);
  auto logInterest = make_shared<Interest>(logInterestName);
  m_keyChain.sign(*logInterest, tldCert->getName());

  face1.receive(*logInterest);
  do {
    advanceClocks(time::milliseconds(2), 100);
  } while (passPacket());
  clear();

  BOOST_CHECK_EQUAL(logger.getDb().getMaxLeafSeq(), 2);
  auto leafResult1 = logger.getDb().getLeaf(1);
  BOOST_CHECK(leafResult1.first != nullptr);
  BOOST_CHECK(leafResult1.second != nullptr);



  Name leafInterestName2("/test/logger/leaf");
  leafInterestName2.appendNumber(1);
  auto leafInterest2 = make_shared<Interest>(leafInterestName2);

  face1.receive(*leafInterest2);
  advanceClocks(time::milliseconds(2), 100);

  BOOST_CHECK_EQUAL(face1.sentData.size(), 1);
  BOOST_CHECK(leafInterestName2.isPrefixOf(face1.sentData[0].getName()));
  clear();



  Name treeInterestName2("/test/logger/tree");
  treeInterestName2.appendNumber(1);
  treeInterestName2.appendNumber(0);
  auto treeInterest2 = make_shared<Interest>(treeInterestName2);

  face1.receive(*treeInterest2);
  advanceClocks(time::milliseconds(2), 100);

  BOOST_CHECK_EQUAL(face1.sentData.size(), 1);
  BOOST_CHECK(treeInterestName2.isPrefixOf(face1.sentData[0].getName()));
  clear();


  auto data = make_shared<Data>(Name("/ndn/tld/data"));
  m_keyChain.sign(*data, tldCert->getName());

  face2.setInterestFilter(data->getName(),
    [&] (const ndn::InterestFilter&, const Interest&) { face2.put(*data); },
    ndn::RegisterPrefixSuccessCallback(),
    [] (const Name&, const std::string&) {});
  advanceClocks(time::milliseconds(2), 100);
  clear();

  Name logInterestName2("/test/logger/log");
  logInterestName2.append(data->getFullName().wireEncode());
  logInterestName2.appendNumber(1);
  auto logInterest2 = make_shared<Interest>(logInterestName2);
  m_keyChain.sign(*logInterest2, tldCert->getName());

  face1.receive(*logInterest2);
  do {
    advanceClocks(time::milliseconds(2), 100);
  } while (passPacket());
  clear();

  BOOST_CHECK_EQUAL(logger.getDb().getMaxLeafSeq(), 3);
  auto leafResult2 = logger.getDb().getLeaf(2);
  BOOST_CHECK(leafResult2.first != nullptr);
  BOOST_CHECK(leafResult2.second == nullptr);


  fs::remove_all(fs::path(TEST_LOGGER_PATH));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace delorean
} // namespace ndn
