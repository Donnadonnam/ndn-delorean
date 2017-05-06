# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

"""
Copyright (c) 2014-2017, Regents of the University of California

This file is part of NDN DeLorean, An Authentication System for Data Archives in
Named Data Networking.  See AUTHORS.md for complete list of NDN DeLorean authors
and contributors.

NDN DeLorean is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

NDN DeLorean is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with NDN
DeLorean, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
"""

from waflib import Logs, Utils, Context
import os

VERSION = "0.1.0"
APPNAME = "ndn-delorean"

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs', 'c_osx'])
    opt.load(['default-compiler-flags', 'boost', 'cryptopp',
              'sqlite3', 'doxygen', 'sphinx_build'],
             tooldir=['.waf-tools'])

    opt = opt.add_option_group('NDN DeLorean Options')

    opt.add_option('--with-tests', action='store_true', default=False, dest='with_tests',
                   help='''build unit tests''')

    opt.add_option('--without-tools', action='store_false', default=True, dest='with_tools',
                   help='''Do not build tools''')

    opt.add_option('--without-sqlite-locking', action='store_false', default=True,
                   dest='with_sqlite_locking',
                   help='''Disable filesystem locking in sqlite3 database '''
                        '''(use unix-dot locking mechanism instead). '''
                        '''This option may be necessary if home directory is hosted on NFS.''')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs', 'c_osx',
               'default-compiler-flags', 'boost', 'cryptopp',
               'sqlite3', 'doxygen', 'sphinx_build'])

    conf.env['WITH_TESTS'] = conf.options.with_tests
    conf.env['WITH_TOOLS'] = conf.options.with_tools

    conf.find_program('sh', var='SH', mandatory=True)

    conf.check_cxx(lib='pthread', uselib_store='PTHREAD', define_name='HAVE_PTHREAD',
                   mandatory=False)
    conf.check_sqlite3(mandatory=True)
    conf.check_cryptopp(mandatory=True, use='PTHREAD')

    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    USED_BOOST_LIBS = ['system', 'filesystem', 'date_time', 'iostreams',
                       'program_options', 'chrono']
    if conf.env['WITH_TESTS']:
        USED_BOOST_LIBS += ['unit_test_framework']
        conf.define('HAVE_TESTS', 1)

    conf.check_boost(lib=USED_BOOST_LIBS, mandatory=True)
    if conf.env.BOOST_VERSION_NUMBER < 104800:
        Logs.error("Minimum required boost version is 1.48.0")
        Logs.error("Please upgrade your distribution or install custom boost libraries" +
                    " (http://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)")
        return

    if not conf.options.with_sqlite_locking:
        conf.define('DISABLE_SQLITE3_FS_LOCKING', 1)

    conf.define('DEFAULT_CONFIG_FILE', '%s/ndn/ndn-delorean.conf' % conf.env['SYSCONFDIR'])

    conf.write_config_header('config.hpp', define_prefix='NDN_DELOREAN_')

def build(bld):
    version(bld)

    bld(features="subst",
        name='version',
        source='version.hpp.in',
        target='version.hpp',
        install_path=None,
        VERSION_STRING=VERSION_BASE,
        VERSION_BUILD=VERSION,
        VERSION=int(VERSION_SPLIT[0]) * 1000000 +
                int(VERSION_SPLIT[1]) * 1000 +
                int(VERSION_SPLIT[2]),
        VERSION_MAJOR=VERSION_SPLIT[0],
        VERSION_MINOR=VERSION_SPLIT[1],
        VERSION_PATCH=VERSION_SPLIT[2],
        )

    core = bld(
        target='core-objects',
        name='core-objects',
        features='cxx',
        source=bld.path.ant_glob(['core/**/*.cpp']),
        use='version BOOST NDN_CXX CRYPTOPP SQLITE3',
        includes='. core',
        export_includes='. core',
        headers='common.hpp',
        )

    logger_objects = bld(
        target='daemon-objects',
        name='daemon-objects',
        features='cxx',
        source=bld.path.ant_glob(['daemon/**/*.cpp'],
                                 excl=['daemon/main.cpp']),
        use='core-objects',
        includes='daemon',
        export_includes='daemon',
        )

    bld(target='bin/ndn-delorean',
        features='cxx cxxprogram',
        source='daemon/main.cpp',
        use='daemon-objects',
        )

    if bld.env['WITH_TESTS']:
        bld.recurse('tests')

    if bld.env['WITH_TOOLS']:
        bld.recurse("tools")

    bld(features="subst",
        source='ndn-delorean.conf.sample.in',
        target='ndn-delorean.conf.sample',
        install_path="${SYSCONFDIR}/ndn",
        )

    # if bld.env['SPHINX_BUILD']:
    #     bld(features="sphinx",
    #         builder="man",
    #         outdir="docs/manpages",
    #         config="docs/conf.py",
    #         source=bld.path.ant_glob('docs/manpages/**/*.rst'),
    #         install_path="${MANDIR}/",
    #         VERSION=VERSION)

def docs(bld):
    from waflib import Options
    Options.commands = ['doxygen', 'sphinx'] + Options.commands

def doxygen(bld):
    version(bld)

    if not bld.env.DOXYGEN:
        Logs.error("ERROR: cannot build documentation (`doxygen' is not found in $PATH)")
    else:
        bld(features="subst",
            name="doxygen-conf",
            source=["docs/doxygen.conf.in",
                    "docs/named_data_theme/named_data_footer-with-analytics.html.in"],
            target=["docs/doxygen.conf",
                    "docs/named_data_theme/named_data_footer-with-analytics.html"],
            VERSION=VERSION,
            HTML_FOOTER="../build/docs/named_data_theme/named_data_footer-with-analytics.html" \
                          if os.getenv('GOOGLE_ANALYTICS', None) \
                          else "../docs/named_data_theme/named_data_footer.html",
            GOOGLE_ANALYTICS=os.getenv('GOOGLE_ANALYTICS', ""),
            )

        bld(features="doxygen",
            doxyfile='docs/doxygen.conf',
            use="doxygen-conf")

def sphinx(bld):
    version(bld)

    if not bld.env.SPHINX_BUILD:
        bld.fatal("ERROR: cannot build documentation (`sphinx-build' is not found in $PATH)")
    else:
        bld(features="sphinx",
            outdir="docs",
            source=bld.path.ant_glob("docs/**/*.rst"),
            config="docs/conf.py",
            VERSION=VERSION)


def version(ctx):
    if getattr(Context.g_module, 'VERSION_BASE', None):
        return

    Context.g_module.VERSION_BASE = Context.g_module.VERSION
    Context.g_module.VERSION_SPLIT = [v for v in VERSION_BASE.split('.')]

    try:
        cmd = ['git', 'describe', '--match', 'ndn-delorean-*']
        p = Utils.subprocess.Popen(cmd, stdout=Utils.subprocess.PIPE,
                                   stderr=None, stdin=None)
        out = p.communicate()[0].strip()
        if p.returncode == 0 and out != "":
            Context.g_module.VERSION = out[8:]
    except:
        pass
