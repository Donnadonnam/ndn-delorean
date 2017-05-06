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

#include "auditor.hpp"
#include "../tree-generator.hpp"
#include "cryptopp.hpp"

#include <boost/mpl/list.hpp>
#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestAuditor)

void
printHex(const uint8_t* buf, size_t size)
{
  using namespace CryptoPP;
  StringSource ss(buf, size, true, new HexEncoder(new FileSink(std::cerr), false));
  std::cerr << std::endl;
}

BOOST_AUTO_TEST_CASE(LoadProofTests)
{
  std::vector<shared_ptr<Data>> proofs;
  proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32)->encode());
  proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(32, 5), 64)->encode());

  std::map<Node::Index, ConstSubTreeBinaryPtr> tree1;

  BOOST_CHECK(Auditor::loadProof(tree1, proofs, TreeGenerator::LOGGER_NAME));

  proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(32, 5), 64)->encode());
  std::map<Node::Index, ConstSubTreeBinaryPtr> tree2;
  BOOST_CHECK_EQUAL(Auditor::loadProof(tree2, proofs, TreeGenerator::LOGGER_NAME), false);
}

size_t
getRootLevel(const NonNegativeInteger& leafSeqNo) {
  size_t rootLevel = 0;
  NonNegativeInteger seqNo = leafSeqNo;
  while (seqNo != 0) {
    seqNo = seqNo >> 1;
    rootLevel++;
  }

  return rootLevel;
}

template<NonNegativeInteger L, NonNegativeInteger O, NonNegativeInteger N>
class AuditorProofParam1
{
public:
  void
  createProof()
  {
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32, true)->encode());

    leafHash = TreeGenerator::getHash(Node::Index(L, 0), L + 1, false);
    oldHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(O - 1)), O, false);
    newHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(N - 1)), N, false);
  }

  std::vector<shared_ptr<Data>> proofs;
  const NonNegativeInteger leafSeqNo = L;
  ndn::ConstBufferPtr leafHash;
  const NonNegativeInteger oldNextSeqNo = O;
  ndn::ConstBufferPtr oldHash;
  const NonNegativeInteger newNextSeqNo = N;
  ndn::ConstBufferPtr newHash;
};

template<NonNegativeInteger L, NonNegativeInteger O, NonNegativeInteger N>
class AuditorProofParam2
{
public:
  void
  createProof()
  {
    // proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32, true)->encode());
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(32, 5), 64, true)->encode());
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 10), 64, true)->encode());

    leafHash = TreeGenerator::getHash(Node::Index(L, 0), L + 1, false);
    oldHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(O - 1)), O, false);
    newHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(N - 1)), N, false);
  }

  std::vector<shared_ptr<Data>> proofs;
  const NonNegativeInteger leafSeqNo = L;
  ndn::ConstBufferPtr leafHash;
  const NonNegativeInteger oldNextSeqNo = O;
  ndn::ConstBufferPtr oldHash;
  const NonNegativeInteger newNextSeqNo = N;
  ndn::ConstBufferPtr newHash;
};

template<NonNegativeInteger L, NonNegativeInteger O, NonNegativeInteger N>
class AuditorProofParam3
{
public:
  void
  createProof()
  {
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32, true)->encode());
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(32, 5), 33, true)->encode());
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 10), 33, true)->encode());

    leafHash = TreeGenerator::getHash(Node::Index(L, 0), L + 1, false);
    oldHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(O - 1)), O, false);
    newHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(N - 1)), N, false);
  }

  std::vector<shared_ptr<Data>> proofs;
  const NonNegativeInteger leafSeqNo = L;
  ndn::ConstBufferPtr leafHash;
  const NonNegativeInteger oldNextSeqNo = O;
  ndn::ConstBufferPtr oldHash;
  const NonNegativeInteger newNextSeqNo = N;
  ndn::ConstBufferPtr newHash;
};

typedef boost::mpl::list<AuditorProofParam1<0, 1, 1>,
                         AuditorProofParam1<0, 2, 2>,
                         AuditorProofParam1<0, 4, 4>,
                         AuditorProofParam1<1, 2, 2>,
                         AuditorProofParam1<1, 4, 4>,
                         AuditorProofParam1<2, 4, 4>,
                         AuditorProofParam1<3, 4, 4>,
                         AuditorProofParam1<4, 6, 6>,
                         AuditorProofParam1<31, 32, 32>,
                         AuditorProofParam3<0, 33, 33>,
                         AuditorProofParam2<32, 33, 33>,
                         AuditorProofParam2<48, 64, 64>> ExistenceProofTestParams;

BOOST_AUTO_TEST_CASE_TEMPLATE(ExistenceProof, P, ExistenceProofTestParams)
{
  P params;
  params.createProof();

  BOOST_CHECK(Auditor::doesExist(params.leafSeqNo, params.leafHash,
                                 params.newNextSeqNo, params.newHash,
                                 params.proofs, TreeGenerator::LOGGER_NAME));
}

template<NonNegativeInteger L, NonNegativeInteger O, NonNegativeInteger N>
class AuditorProofParam4
{
public:
  void
  createProof()
  {
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 5), 32, true)->encode());
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(32, 5), 64, true)->encode());
    proofs.push_back(TreeGenerator::getSubTreeBinary(Node::Index(0, 10), 64, true)->encode());

    leafHash = TreeGenerator::getHash(Node::Index(L, 0), L + 1, false);
    oldHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(O - 1)), O, false);
    newHash = TreeGenerator::getHash(Node::Index(0, getRootLevel(N - 1)), N, false);
  }

  std::vector<shared_ptr<Data>> proofs;
  const NonNegativeInteger leafSeqNo = L;
  ndn::ConstBufferPtr leafHash;
  const NonNegativeInteger oldNextSeqNo = O;
  ndn::ConstBufferPtr oldHash;
  const NonNegativeInteger newNextSeqNo = N;
  ndn::ConstBufferPtr newHash;
};

typedef boost::mpl::list<AuditorProofParam1<0, 1, 1>,
                         AuditorProofParam1<0, 1, 2>,
                         AuditorProofParam1<0, 1, 32>,
                         AuditorProofParam1<0, 2, 32>,
                         AuditorProofParam1<0, 31, 32>,
                         AuditorProofParam4<0, 32, 64>,
                         AuditorProofParam3<0, 1, 33>,
                         AuditorProofParam3<0, 31, 33>,
                         AuditorProofParam4<0, 1, 64>> ConsistencyProofTestParams;

BOOST_AUTO_TEST_CASE_TEMPLATE(ConsistencyProof, P, ConsistencyProofTestParams)
{
  P params;
  params.createProof();

  BOOST_CHECK(Auditor::isConsistent(params.oldNextSeqNo, params.oldHash,
                                    params.newNextSeqNo, params.newHash,
                                    params.proofs, TreeGenerator::LOGGER_NAME));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
