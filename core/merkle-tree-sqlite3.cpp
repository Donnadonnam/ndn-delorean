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

#include "merkle-tree-sqlite3.hpp"
#include <stdlib.h>
#include <boost/filesystem.hpp>


namespace nsl {

static const std::string INIT_SUBTREE_TABLE = "\
CREATE TABLE IF NOT EXISTS                                           \n \
  SubTree(                                                           \n \
      subTree_sequence     INTEGER,                                  \n \
      subTree_level        INTEGER,                                  \n \
      subTree_info         BLOB,                                     \n \
                                                                     \
      PRIMARY KEY (subTree_sequence, subTree_level)                  \n \
  );                                                                 \n \
                                                                     \
CREATE INDEX subTree_index ON SubTree(subTree_sequence);             \n \
";

static const std::string INIT_LEAF_TABLE = "\
CREATE TABLE IF NOT EXISTS                                           \n \
  Leaf(                                                              \n \
      leaf_sequence     INTEGER,                                     \n \
      leaf_info         BLOB,                                        \n \
                                                                     \
      PRIMARY KEY (leaf_sequence)                                    \n \
  );                                                                 \n \
                                                                     \
CREATE INDEX leaf_index ON Leaf(leaf_sequence);                      \n \
";

/**
 * A utility function to call the normal sqlite3_bind_text where the value and length are
 * value.c_str() and value.size().
 */
static int sqlite3_bind_text(sqlite3_stmt* statement,
                             int index,
                             const std::string& value,
                             void(*destructor)(void*))
{
  return sqlite3_bind_text(statement, index, value.c_str(), value.size(), destructor);
}


MerkleTreeSqlite3::MerkleTreeSqlite3()
{
  boost::filesystem::path identityDir = boost::filesystem::path("/Users/GPZ/Develop/nslDB");
  boost::filesystem::create_directories(identityDir);

  /// @todo Add define for windows/unix in wscript. The following may completely fail on windows
  int res = sqlite3_open_v2((identityDir / "nsl-merkle-tree.db").c_str(), &m_database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
#ifdef NDN_CXX_DISABLE_SQLITE3_FS_LOCKING
                            "unix-dotfile"
#else
                            0
#endif
                            );

  if (res != SQLITE_OK)
    std::cout << "DB cannot be opened/created";

  //Check if SubTree table exists;
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT name FROM sqlite_master WHERE type='table' And name='SubTree'",
                     -1, &statement, 0);
  res = sqlite3_step(statement);

  bool SubTreeTableExists = false;
  if (res == SQLITE_ROW)
    SubTreeTableExists = true;

  sqlite3_finalize(statement);

  if (!SubTreeTableExists)
    {
      char* errorMessage = 0;
      res = sqlite3_exec(m_database, INIT_SUBTREE_TABLE.c_str(), NULL, NULL, &errorMessage);

      if (res != SQLITE_OK && errorMessage != 0)
        {
          sqlite3_free(errorMessage);
        }
    }

  //Check if Leaf table exists;
  sqlite3_prepare_v2(m_database,
                     "SELECT name FROM sqlite_master WHERE type='table' And name='Leaf'",
                     -1, &statement, 0);
  res = sqlite3_step(statement);

  bool LeafTableExists = false;
  if (res == SQLITE_ROW)
    LeafTableExists = true;

  sqlite3_finalize(statement);

  if (!LeafTableExists)
    {
      char* errorMessage = 0;
      res = sqlite3_exec(m_database, INIT_LEAF_TABLE.c_str(), NULL, NULL, &errorMessage);

      if (res != SQLITE_OK && errorMessage != 0)
        {
          sqlite3_free(errorMessage);
        }
    }

}


MerkleTreeSqlite3::~MerkleTreeSqlite3()
{
}


void
MerkleTreeSqlite3::addSubTree(SubTreePtr oldSubTree)
{
  Index old_idx = oldSubTree->getRootIndex();
  std::string old_info = oldSubTree->encoding();

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "INSERT OR REPLACE INTO SubTree \
                      (subTree_sequence, subTree_level, subTree_info)   \
                      values (?, ?, ?)",
                     -1, &statement, 0);
  sqlite3_bind_int64(statement, 1, old_idx.number);
  sqlite3_bind_int64(statement, 2, old_idx.level);
  sqlite3_bind_text(statement, 3, old_info, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}


std::string
MerkleTreeSqlite3::getSubTree(Index rootIndex)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT subTree_info FROM SubTree \
                      WHERE subTree_sequence=? AND subTree_level=?",
                     -1, &statement, 0);
  sqlite3_bind_int64(statement, 1, rootIndex.number);
  sqlite3_bind_int64(statement, 2, rootIndex.level);
  int res = sqlite3_step(statement);
  std::string result;
  if (res == SQLITE_ROW)
    {
      result = std::string(reinterpret_cast<const char *>(sqlite3_column_text(statement, 0)),
                           sqlite3_column_bytes(statement, 0));
      sqlite3_finalize(statement);
      return result;
    }
  else
    {
      sqlite3_finalize(statement);
      return result;
    }
}


bool
MerkleTreeSqlite3::doesSubTreeExist(Index rootIndex)
{
  bool result = false;
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT count(*) FROM SubTree WHERE subTree_sequence=? AND subTree_level=?",
                     -1, &statement, 0);
  sqlite3_bind_int64(statement, 1, rootIndex.number);
  sqlite3_bind_int64(statement, 2, rootIndex.level);
  int res = sqlite3_step(statement);
  if (res == SQLITE_ROW)
    {
      int countAll = sqlite3_column_int(statement, 0);
      if (countAll > 0)
        result = true;
    }
  sqlite3_finalize(statement);
  return result;
}


void
MerkleTreeSqlite3::deleteSubTree(Index rootIndex)
{
  sqlite3_stmt* stmt;
  sqlite3_prepare_v2(m_database, "DELETE FROM SubTree WHERE subTree_sequence=? AND subTree_level=?",
                     -1, &stmt, 0);
  sqlite3_bind_int64(stmt, 1, rootIndex.number);
  sqlite3_bind_int64(stmt, 2, rootIndex.level);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}


void
MerkleTreeSqlite3::getAllSubTree(std::vector<std::string> subTreeInfoList)
{
  sqlite3_stmt* stmt;
  sqlite3_prepare_v2(m_database,
                     "SELECT subTree_info FROM SubTree",
                     -1, &stmt, 0);
  while (sqlite3_step(stmt) == SQLITE_ROW)
    subTreeInfoList.push_back(std::string(reinterpret_cast<const char *>
                                          (sqlite3_column_text(stmt, 0)),
                                          sqlite3_column_bytes(stmt, 0)));

  sqlite3_finalize(stmt);
}


// For leafInfo

void
MerkleTreeSqlite3::addLeafInfo(uint64_t sequence, ndn::ConstBufferPtr buf_ptr)
{

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "INSERT OR REPLACE INTO Leaf  \
                      (leaf_sequence, leaf_info)   \
                      values (?, ?)", -1, &statement, 0);
  sqlite3_bind_int64(statement, 1, sequence);
  sqlite3_bind_blob(statement, 2, buf_ptr->buf(), buf_ptr->size(), SQLITE_STATIC);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}


ndn::ConstBufferPtr
MerkleTreeSqlite3::getLeafInfo(uint64_t sequence)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT leaf_info FROM Leaf \
                      WHERE leaf_sequence=?", -1, &statement, 0);
  sqlite3_bind_int64(statement, 1, sequence);
  int res = sqlite3_step(statement);
  if (res == SQLITE_ROW)
    {
      ndn::Buffer res_buf(sqlite3_column_blob(statement, 0), sqlite3_column_bytes(statement, 0));
      ndn::ConstBufferPtr result = ndn::make_shared<ndn::Buffer>(res_buf);
      sqlite3_finalize(statement);
      return result;
    }
  else
    {
      sqlite3_finalize(statement);
      return ndn::ConstBufferPtr();
    }
}


bool
MerkleTreeSqlite3::doesLeafInfoExist(uint64_t sequence)
{
  bool result = false;
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT count(*) FROM Leaf WHERE leaf_sequence=?",
                     -1, &statement, 0);
  sqlite3_bind_int64(statement, 1, sequence);
  int res = sqlite3_step(statement);
  if (res == SQLITE_ROW)
    {
      int countAll = sqlite3_column_int(statement, 0);
      if (countAll > 0)
        result = true;
    }
  sqlite3_finalize(statement);
  return result;
}


void
MerkleTreeSqlite3::deleteLeafInfo(uint64_t sequence)
{
  sqlite3_stmt* stmt;
  sqlite3_prepare_v2(m_database, "DELETE FROM Leaf WHERE leaf_sequence=?",
                     -1, &stmt, 0);
  sqlite3_bind_int64(stmt, 1, sequence);
  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}


void
MerkleTreeSqlite3::getAllLeafInfo(std::map<uint64_t, ndn::ConstBufferPtr> leaves)
{
  sqlite3_stmt* stmt;
  sqlite3_prepare_v2(m_database,
                     "SELECT leaf_sequence, leaf_info FROM Leaf",
                     -1, &stmt, 0);
  while (sqlite3_step(stmt) == SQLITE_ROW)
    {
      uint64_t seq = sqlite3_column_int64(stmt, 0);
      ndn::ConstBufferPtr buf = ndn::make_shared<ndn::Buffer>(sqlite3_column_blob(stmt, 1),
                                                              sqlite3_column_bytes(stmt, 1));
      leaves[seq] = buf;
    }

  sqlite3_finalize(stmt);
}


} // namespace nsl
