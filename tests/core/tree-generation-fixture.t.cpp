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

#include "../tree-generator.hpp"

#include "boost-test.hpp"

namespace nsl {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestTreeGenerator)

BOOST_AUTO_TEST_CASE(HashGeneration)
{
  for (size_t n = 5; n <= 8; n++) {
    auto hash1 = TreeGenerator::getHash(Node::Index(0, 3), n);
    SubTreeBinary tree(TreeGenerator::LOGGER_NAME, Node::Index(0, 5),
                       [&] (const Node::Index&) {},
                       [&] (const Node::Index&,
                            const NonNegativeInteger&,
                            ndn::ConstBufferPtr) {});
    for (size_t i = 0; i < n; i++) {
      auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
      tree.addLeaf(node);
    }
    auto hash2 = tree.getRoot()->getHash();
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
  }

  for (size_t n = 33; n <= 64; n++) {
    auto hash1 = TreeGenerator::getHash(Node::Index(32, 5), n);
    SubTreeBinary tree(TreeGenerator::LOGGER_NAME, Node::Index(32, 5),
                       [&] (const Node::Index&) {},
                       [&] (const Node::Index&,
                            const NonNegativeInteger&,
                            ndn::ConstBufferPtr) {});
    for (size_t i = 32; i < n; i++) {
      auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
      tree.addLeaf(node);
    }
    auto hash2 = tree.getRoot()->getHash();
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
  }
}

BOOST_AUTO_TEST_CASE(TreeGeneration)
{
  for (size_t n = 1; n <= 32; n++) {
    auto hash1 = TreeGenerator::getSubTreeBinary(Node::Index(0, 5), n)->getRoot()->getHash();
    SubTreeBinary tree(TreeGenerator::LOGGER_NAME, Node::Index(0, 5),
                       [&] (const Node::Index&) {},
                       [&] (const Node::Index&,
                            const NonNegativeInteger&,
                            ndn::ConstBufferPtr) {});
    for (size_t i = 0; i < n; i++) {
      auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
      tree.addLeaf(node);
    }
    auto hash2 = tree.getRoot()->getHash();
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
  }

  for (size_t n = 33; n <= 64; n++) {
    auto hash1 = TreeGenerator::getSubTreeBinary(Node::Index(32, 5), n)->getRoot()->getHash();
    SubTreeBinary tree(TreeGenerator::LOGGER_NAME, Node::Index(32, 5),
                       [&] (const Node::Index&) {},
                       [&] (const Node::Index&,
                            const NonNegativeInteger&,
                            ndn::ConstBufferPtr) {});
    for (size_t i = 32; i < n; i++) {
      auto node = make_shared<Node>(i, 0, i + 1, Node::getEmptyHash());
      tree.addLeaf(node);
    }
    auto hash2 = tree.getRoot()->getHash();
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
  }

  for (size_t n = 513; n <= 1024; n++) {
    auto hash1 = TreeGenerator::getSubTreeBinary(Node::Index(0, 10), n)->getRoot()->getHash();
    auto hash2 = TreeGenerator::getHash(Node::Index(0, 10), n);
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
  }

  for (size_t n = 1025; n <= 2048; n++) {
    auto hash1 = TreeGenerator::getSubTreeBinary(Node::Index(1024, 10), n)->getRoot()->getHash();
    auto hash2 = TreeGenerator::getHash(Node::Index(1024, 10), n);
    BOOST_CHECK_EQUAL_COLLECTIONS(hash1->begin(), hash1->end(), hash2->begin(), hash2->end());
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nsl
