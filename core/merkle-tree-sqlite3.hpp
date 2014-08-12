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
 * @author Peizhen Guo <patrick.guopz@gmail.com>
 */

#ifndef NLS_CORE_MERKLE_TREE_SQLITE3_HPP
#define NLS_CORE_MERKLE_TREE_SQLITE3_HPP

#include <sqlite3.h>
#include <map>
#include "sub-tree.hpp"
typedef ndn::shared_ptr<const nsl::SubTree> ConstSubTreePtr;
typedef ndn::shared_ptr<nsl::SubTree> SubTreePtr;

struct sqlite3;

namespace nsl {

class MerkleTreeSqlite3
{
public:

  MerkleTreeSqlite3();

  ~MerkleTreeSqlite3();

  // SubTree
  void
  addSubTree(SubTreePtr oldSubTree);

  std::string
  getSubTree(Index rootIndex);

  bool
  doesSubTreeExist(Index rootIndex);

  void
  deleteSubTree(Index rootIndex);

  void
  getAllSubTree(std::vector<std::string> subTreeInfoList);


  // LeafInfo (no need of encoding/decoding scheme)
  void
  addLeafInfo(uint64_t sequence, ndn::ConstBufferPtr buf_ptr);

  ndn::ConstBufferPtr
  getLeafInfo(uint64_t sequence);

  bool
  doesLeafInfoExist(uint64_t sequence);

  void
  deleteLeafInfo(uint64_t sequence);

  void
  getAllLeafInfo(std::map<uint64_t, ndn::ConstBufferPtr> leaves);


private:
  sqlite3* m_database;

};


} // namespace nsl


#endif // NLS_CORE_MERKLE_TREE_SQLITE3_HPP
