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

#include "db.hpp"

#include <sqlite3.h>
#include <string>
#include <boost/filesystem.hpp>

namespace nsl {

static const std::string INITIALIZATION =
  "CREATE TABLE IF NOT EXISTS                    \n"
  "  cTrees(                                     \n"
  "    id                    INTEGER PRIMARY KEY,\n"
  "    level                 INTEGER NOT NULL,   \n"
  "    seqNo                 INTEGER NOT NULL,   \n"
  "    data                  BLOB NOT NULL       \n"
  "  );                                          \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS             \n"
  "  cTreeIndex ON cTrees(level, seqNo);         \n"
  "CREATE TRIGGER IF NOT EXISTS                  \n"
  "  cTrees_after_insert_trigger                 \n"
  "  AFTER INSERT ON cTrees                      \n"
  "  FOR EACH ROW                                \n"
  "  BEGIN                                       \n"
  "    DELETE FROM pTrees                        \n"
  "    WHERE level=NEW.level AND seqNo=NEW.seqNo;\n"
  "  END;                                        \n"
  "                                              \n"
  "CREATE TABLE IF NOT EXISTS                    \n"
  "  pTrees(                                     \n"
  "    id                    INTEGER PRIMARY KEY,\n"
  "    level                 INTEGER NOT NULL,   \n"
  "    seqNo                 INTEGER NOT NULL,   \n"
  "    nextLeafSeqNo         INTEGER NOT NULL,   \n"
  "    data                  BLOB NOT NULL       \n"
  "  );                                          \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS             \n"
  "  pTreeIndex ON pTrees(level, seqNo);         \n"
  "                                              \n"
  "CREATE TABLE IF NOT EXISTS                    \n"
  "  leaves(                                     \n"
  "    id                    INTEGER PRIMARY KEY,\n"
  "    dataSeqNo             INTEGER NOT NULL,   \n"
  "    dataName              BLOB NOT NULL,      \n"
  "    signerSeqNo           INTEGER NOT NULL,   \n"
  "    timestamp             INTEGER NOT NULL,   \n"
  "    isCert                INTEGER DEFAULT 0,  \n"
  "    cert                  BLOB                \n"
  "  );                                          \n"
  "CREATE UNIQUE INDEX IF NOT EXISTS             \n"
  "  leavesIndex ON leaves(dataSeqNo);           \n";


/**
 * A utility function to call the normal sqlite3_bind_blob where the value and length are
 * block.wire() and block.size().
 */
static int
sqlite3_bind_block(sqlite3_stmt* statement,
                   int index,
                   const Block& block,
                   void(*destructor)(void*))
{
  return sqlite3_bind_blob(statement, index, block.wire(), block.size(), destructor);
}

/**
 * A utility function to generate block by calling the normal sqlite3_column_text.
 */
static Block
sqlite3_column_block(sqlite3_stmt* statement, int column)
{
  return Block(sqlite3_column_blob(statement, column), sqlite3_column_bytes(statement, column));
}

void
Db::open(const std::string& dbDir)
{
  // Determine the path of logger database
  if (dbDir == "")
    throw Error("Db: empty db path");

  boost::filesystem::path dir = boost::filesystem::path(dbDir);
  boost::filesystem::create_directories(dir);

  // Open database
  int result = sqlite3_open_v2((dir / "sig-logger.db").c_str(), &m_db,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
#ifdef NSL_DISABLE_SQLITE3_FS_LOCKING
                               "unix-dotfile"
#else
                               nullptr
#endif
                               );

  if (result != SQLITE_OK)
    throw Error("SigLogger DB cannot be opened/created: " + dbDir);

  // initialize SigLogger specific tables
  char* errorMessage = nullptr;
  result = sqlite3_exec(m_db, INITIALIZATION.c_str(), nullptr, nullptr, &errorMessage);
  if (result != SQLITE_OK && errorMessage != nullptr) {
    sqlite3_free(errorMessage);
    throw Error("SigLogger DB cannot be initialized");
  }

  getMaxLeafSeq();
}

bool
Db::insertSubTreeData(size_t level, const NonNegativeInteger& seqNo,
                      const Data& data,
                      bool isFull, const NonNegativeInteger& nextLeafSeqNo)
{
  sqlite3_stmt* statement;
  if (isFull) {
    sqlite3_prepare_v2(m_db,
                       "INSERT INTO cTrees (level, seqNo, data) VALUES (?, ?, ?)",
                       -1, &statement, nullptr);
  }
  else {
    sqlite3_prepare_v2(m_db,
                       "INSERT OR REPLACE INTO pTrees (level, seqNo, data, nextLeafSeqNo)\
                        VALUES (?, ?, ?, ?)",
                       -1, &statement, nullptr);
  }
  sqlite3_bind_int(statement, 1, level);
  sqlite3_bind_int(statement, 2, seqNo);
  sqlite3_bind_block(statement, 3, data.wireEncode(), SQLITE_TRANSIENT);
  if (!isFull)
    sqlite3_bind_int(statement, 4, nextLeafSeqNo);

  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_OK)
    return true;
  return false;
}

shared_ptr<Data>
Db::getSubTreeData(size_t level, const NonNegativeInteger& seqNo)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_db,
                     "SELECT data FROM cTrees WHERE level=? AND seqNo=?",
                     -1, &statement, nullptr);
  sqlite3_bind_int(statement, 1, level);
  sqlite3_bind_int(statement, 2, seqNo);

  if (sqlite3_step(statement) == SQLITE_ROW) {
    auto result = make_shared<Data>(sqlite3_column_block(statement, 0));
    sqlite3_finalize(statement);
    return result;
  }

  sqlite3_prepare_v2(m_db,
                     "SELECT data FROM pTrees WHERE level=? AND seqNo=?",
                     -1, &statement, nullptr);
  sqlite3_bind_int(statement, 1, level);
  sqlite3_bind_int(statement, 2, seqNo);

  shared_ptr<Data> result;
  if (sqlite3_step(statement) == SQLITE_ROW)
    result = make_shared<Data>(sqlite3_column_block(statement, 0));

  sqlite3_finalize(statement);
  return result;
}

std::vector<shared_ptr<Data>>
Db::getPendingSubTrees()
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_db,
                     "SELECT data FROM pTrees ORDER BY level DESC",
                     -1, &statement, nullptr);

  std::vector<shared_ptr<Data>> datas;
  while (sqlite3_step(statement) == SQLITE_ROW)
    datas.push_back(make_shared<Data>(sqlite3_column_block(statement, 0)));

  sqlite3_finalize(statement);
  return datas;
}

bool
Db::insertLeafData(const Leaf& leaf)
{
  if (leaf.getDataSeqNo() != m_nextLeafSeqNo)
    return false;

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_db,
                     "INSERT INTO leaves (dataSeqNo, dataName, signerSeqNo, timestamp, isCert)\
                      VALUES (?, ?, ?, ?, 0)",
                     -1, &statement, nullptr);

  sqlite3_bind_int(statement, 1, leaf.getDataSeqNo());
  sqlite3_bind_block(statement, 2, leaf.getDataName().wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_int(statement, 3, leaf.getSignerSeqNo());
  sqlite3_bind_int(statement, 4, leaf.getTimestamp());

  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_OK || result == SQLITE_DONE) {
    m_nextLeafSeqNo++;
    return true;
  }

  return false;
}

bool
Db::insertLeafData(const Leaf& leaf, const Data& data)
{
  if (leaf.getDataSeqNo() != m_nextLeafSeqNo)
    return false;

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_db,
                     "INSERT INTO leaves (dataSeqNo, dataName, signerSeqNo, timestamp, isCert, cert)\
                      VALUES (?, ?, ?, ?, 1, ?)",
                     -1, &statement, nullptr);

  sqlite3_bind_int(statement, 1, leaf.getDataSeqNo());
  sqlite3_bind_block(statement, 2, leaf.getDataName().wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_int(statement, 3, leaf.getSignerSeqNo());
  sqlite3_bind_int(statement, 4, leaf.getTimestamp());
  sqlite3_bind_block(statement, 5, data.wireEncode(), SQLITE_TRANSIENT);

  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_OK || result == SQLITE_DONE) {
    m_nextLeafSeqNo++;
    return true;
  }

  return false;
}

std::pair<shared_ptr<Leaf>, shared_ptr<Data>>
Db::getLeaf(const NonNegativeInteger& seqNo)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_db,
                     "SELECT dataName, signerSeqNo, timestamp, cert\
                      FROM leaves WHERE dataSeqNo=?",
                     -1, &statement, nullptr);

  sqlite3_bind_int(statement, 1, seqNo);

  if (sqlite3_step(statement) == SQLITE_ROW) {
    auto leaf = make_shared<Leaf>(Name(sqlite3_column_block(statement, 0)),
                                  sqlite3_column_int(statement, 2),
                                  seqNo,
                                  sqlite3_column_int(statement, 1));

    shared_ptr<Data> data;
    if (sqlite3_column_bytes(statement, 3) != 0) {
      data = make_shared<Data>(sqlite3_column_block(statement, 3));
    }
    sqlite3_finalize(statement);
    return std::make_pair(leaf, data);
  }
  else {
    sqlite3_finalize(statement);
    return std::make_pair(nullptr, nullptr);
  }
}

const NonNegativeInteger&
Db::getMaxLeafSeq()
{
  sqlite3_stmt* statement;

  sqlite3_prepare_v2(m_db, "SELECT count(dataSeqNo) FROM leaves", -1, &statement, nullptr);
  if (sqlite3_step(statement) == SQLITE_ROW)
    m_nextLeafSeqNo = sqlite3_column_int(statement, 0);
  else
    throw Error("getMaxLeafSeq: db error");

  sqlite3_finalize(statement);
  return m_nextLeafSeqNo;
}

} // namespace nsl
