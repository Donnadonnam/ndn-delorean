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

#ifndef NDN_DELOREAN_COMMON_HPP
#define NDN_DELOREAN_COMMON_HPP

#include "config.hpp"

#ifdef NDN_DELOREAN_HAVE_TESTS
#define NDN_DELOREAN_VIRTUAL_WITH_TESTS virtual
#define NDN_DELOREAN_PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define NDN_DELOREAN_PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define NDN_DELOREAN_PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define NDN_DELOREAN_VIRTUAL_WITH_TESTS
#define NDN_DELOREAN_PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define NDN_DELOREAN_PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define NDN_DELOREAN_PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <cstddef>
#include <list>
#include <set>
#include <queue>
#include <vector>

#include <ndn-cxx/common.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/assert.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/scoped_ptr.hpp>

namespace ndn {
namespace delorean {

using std::size_t;

using boost::noncopyable;
using boost::scoped_ptr;

using std::shared_ptr;
using std::weak_ptr;
using std::enable_shared_from_this;
using std::make_shared;
using std::static_pointer_cast;
using std::dynamic_pointer_cast;
using std::const_pointer_cast;
using std::function;
using std::bind;
using std::ref;
using std::cref;

using ndn::Interest;
using ndn::Data;
using ndn::Name;
using ndn::Exclude;
using ndn::Block;
using ndn::Signature;
using ndn::KeyLocator;

namespace tlv {
using namespace ndn::tlv;
}

namespace name = ndn::name;
namespace time = ndn::time;

} // namespace delorean
} // namespace ndn

#endif // NDN_DELOREAN_COMMON_HPP
