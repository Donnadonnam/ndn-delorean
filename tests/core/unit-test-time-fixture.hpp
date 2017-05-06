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

#ifndef NDN_DELOREAN_TESTS_UNIT_TESTS_UNIT_TEST_TIME_FIXTURE_HPP
#define NDN_DELOREAN_TESTS_UNIT_TESTS_UNIT_TEST_TIME_FIXTURE_HPP

#include <ndn-cxx/util/time-unit-test-clock.hpp>

#include <boost/asio.hpp>

namespace ndn {
namespace delorean {
namespace tests {

class UnitTestTimeFixture
{
public:
  UnitTestTimeFixture()
    : steadyClock(make_shared<ndn::time::UnitTestSteadyClock>())
    , systemClock(make_shared<ndn::time::UnitTestSystemClock>())
  {
    time::setCustomClocks(steadyClock, systemClock);
  }

  ~UnitTestTimeFixture()
  {
    time::setCustomClocks(nullptr, nullptr);
  }

  void
  advanceClocks(const time::nanoseconds& tick, size_t nTicks = 1)
  {
    for (size_t i = 0; i < nTicks; ++i) {
      steadyClock->advance(tick);
      systemClock->advance(tick);

      if (io.stopped())
        io.reset();
      io.poll();
    }
  }

public:
  shared_ptr<ndn::time::UnitTestSteadyClock> steadyClock;
  shared_ptr<ndn::time::UnitTestSystemClock> systemClock;
  boost::asio::io_service io;
};

} // namespace tests
} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_TESTS_UNIT_TESTS_UNIT_TEST_TIME_FIXTURE_HPP
