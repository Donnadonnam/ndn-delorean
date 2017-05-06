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

#ifndef NDN_DELOREAN_CORE_DB_HPP
#define NDN_DELOREAN_CORE_DB_HPP

#include "common.hpp"
#include "leaf.hpp"
#include "util/non-negative-integer.hpp"
#include <vector>

struct sqlite3;

namespace ndn {
namespace delorean {

class Db : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  void
  open(const std::string& dbDir);

  bool
  insertSubTreeData(size_t level, const NonNegativeInteger& seqNo,
                    const Data& data,
                    bool isFull = true,
                    const NonNegativeInteger& nextLeafSeqNo = 0);

  shared_ptr<Data>
  getSubTreeData(size_t level, const NonNegativeInteger& seqNo);

  std::vector<shared_ptr<Data>>
  getPendingSubTrees();

  bool
  insertLeafData(const Leaf& leaf);

  bool
  insertLeafData(const Leaf& leaf, const Data& data);

  std::pair<shared_ptr<Leaf>, shared_ptr<Data>>
  getLeaf(const NonNegativeInteger& seqNo);

NDN_DELOREAN_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  const NonNegativeInteger&
  getMaxLeafSeq();

private:
  sqlite3* m_db;

  NonNegativeInteger m_nextLeafSeqNo;
};

} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_CORE_DB_HPP
