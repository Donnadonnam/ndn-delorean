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

#ifndef NSL_CORE_DB_HPP
#define NSL_CORE_DB_HPP

#include "common.hpp"
#include "leaf.hpp"
#include "util/non-negative-integer.hpp"
#include <vector>

struct sqlite3;

namespace nsl {

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

NSL_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  const NonNegativeInteger&
  getMaxLeafSeq();

private:
  sqlite3* m_db;

  NonNegativeInteger m_nextLeafSeqNo;
};

} // namespace nsl

#endif // NSL_CORE_DB_HPP
