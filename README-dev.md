Notes for NSL (NDN Signature Logger) developers
===============================================

Requirements
------------

Include the following license boilerplate into all `.hpp` and `.cpp` files:

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
     ////// [optional part] //////
     *
     * \author Author's Name <email@domain>
     * \author Other Author's Name <another.email@domain>
     ////// [end of optional part] //////
     */

Recommendations
---------------

NSL code is subject to ndn-cxx [code style](http://named-data.net/doc/ndn-cxx/0.2.0/code-style.html).


Running unit-tests
------------------

To run unit tests, NSL needs to be configured and build with unit test support:

    ./waf configure --with-tests
    ./waf

The simplest way to run tests, is just to run the compiled binary without any parameters:

    # Run tests
    ./build/unit-tests

However, [Boost.Test framework](http://www.boost.org/doc/libs/1_48_0/libs/test/doc/html/)
is very flexible and allows a number of run-time customization of what tests should be run.
For example, it is possible to choose to run only a specific test suite, only a specific
test case within a suite, or specific test cases within specific test suites:

    # Run Basic test case from all core test suites
    ./build/unit-tests -t */Basic

By default, Boost.Test framework will produce verbose output only when a test case fails.
If it is desired to see verbose output (result of each test assertion), add `-l all`
option to `./build/unit-tests` command.  To see test progress, you can use `-l test_suite`
or `-p` to show progress bar:

    # Show report all log messages including the passed test notification
    ./build/unit-tests -l all

    # Show test suite messages
    ./build/unit-tests -l test_suite

    # Show nothing
    ./build/unit-tests -l nothing

    # Show progress bar
    ./build/unit-tests -p

There are many more command line options available, information about
which can be obtained either from the command line using `--help`
switch, or online on [Boost.Test library](http://www.boost.org/doc/libs/1_48_0/libs/test/doc/html/)
website.
