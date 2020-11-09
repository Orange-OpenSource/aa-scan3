# Software Name : aa-scan3
# SPDX-FileCopyrightText: Copyright (c) 2020 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GPLv2;
# see the COPYING file for more details.
#
# Author: Yann E. MORIN <yann.morin@orange.com> et al.

"""
Test if the ELF file embeds resources from one or more qrc
files, in which case scan it to generate a ruleset to allow the
resources recursively referenced from the qrc file. If the file
is not an ELF file, no qrc scan is attempted on it (but it might
be attempted on its dependencies, or on its dependee).

For each qrc referenced in the executable, the qrc plugin will list
all the resources (qml or js) from that qrc file. Those resources
are bundled in the ELF file, so need no appArmor rule. However,
for each resource, scan them for the qml modules they import. For
each such module, generate AppArmor rules for the resources (qml
or js, but also .so plugins) exported by the module. Finally, for
each such resource, recurse to identify the modules they import...

The ELF file must have been generated using a modified rcc, that
stores the path to the qrc, prefixed with a constant pattern,
in the generated binary (e.g. as a const char*) so that the path
can be extracted from the .rodata section. The source tree of
aa-scan3 contains a wrapper to rcc that does this.
"""


import glob
import os
import re
import subprocess


class Scanner:
    def __init__(self, parser):
        self.first = True
        self.known_modules = set()
        parser.add_argument('--rcc', metavar='RCC',
                            help='The path to the rcc utility to use.'
                            + ' If not provided, no qrc scan is attempted.')
        parser.add_argument('--base-dir', metavar='DIR',
                            help='The path to the directory under which'
                            + ' all qml-related modules are located.')
        parser.add_argument('--pattern', metavar='PATTERN',
                            help='The pattern to filter on to find the'
                            + ' qrc paths.')
        parser.add_argument('--files', action='append', metavar='FILE',
                            default=[],
                            help='The path to a qrc file. This option can'
                            + ' be specified more than once, in which'
                            + ' case all files will be used.')
        parser.add_argument('--internal', metavar='PREFIX', action='append',
                            default=[],
                            help='Prefix for modules considered internal'
                            + ' (i.e. modules created in C++). Can be'
                            + ' specified more than once, to add more'
                            + ' than one prefix.')
        parser.add_argument('--strict', action='store_true',
                            help='Fail on missing resources (qml, js),'
                            + ' rather than ignoring them.')

    def scan(self, path):
        if self.rcc is None: return  # noqa: E701
        qrc_files = []
        if self.first:
            if self.pattern is None:
                raise AttributeError('no pattern specified')
            if self.base_dir is None:
                raise AttributeError('no base-dir specified')
            self.first = False
            qrc_files.extend(self.files)

        qrc_files.extend(self.get_qrc_from_file(path))
        for qrc in qrc_files:
            self.logger('scanning qrc: {}'.format(qrc))
            for res in self.list_resources(qrc):
                self.logger('scanning resource: {}'.format(res))
                yield from self.scan_resource(res)
                self.logger('done scanning resource: {}'.format(res))
            self.logger('done scanning qrc: {}\n'.format(qrc))

    def scan_resource(self, path):
        """Scan resources imported by resource in path
        :param path: resource to scan (.qml or .js)
        :return: a list of files to further scan with aa-scan
        """
        if path.endswith('.qml') or path.endswith('.js'):
            self.logger('looking modules for {}'.format(path))
            for mod, ver in self.get_modules_from_res(path):
                self.logger('scanning mod={}, ver={}'.format(mod, ver))
                if mod[0] == '"' and mod[-1] == '"':
                    yield from self.scan_private(path, mod[1:-1])
                else:
                    yield from self.scan_module(mod, ver)
                self.logger('done scanning mod={}, ver={}'.format(mod, ver))

    def scan_private(self, path, mod):
        """Scan a private module
        :param path: the path to the file the module was imported from
        :param mod: the module name
        :return: a list of files to further scan with aa-scan
        """
        if not path.startswith(self.profile.joinpath(self.root_dir, self.base_dir)):
            self.logger('skipping internal, private import {}'.format(path))
            return

        mod_path = self.profile.joinpath(os.path.dirname(path), mod)
        if os.path.isdir(mod_path):
            self.profile.add_path(mod_path[len(self.root_dir):] + '/', 'r')
            for r in glob.iglob(mod_path + '/*'):
                self.profile.add_path(r[len(self.root_dir):], 'r')
                yield from self.scan_resource(r)
        elif os.path.isfile(mod_path):
            self.profile.add_path(mod_path[len(self.root_dir):], 'r')
            yield from self.scan_resource(mod_path)
        else:
            raise FileNotFoundError('import of non existent private resource {}'.format(mod))

    def scan_module(self, mod, ver):
        """Scan a module (non private)
        :param mod: the module name
        :param ver: the module version
        :return: a list of files to further scan with aa-scan
        """
        if len(ver) == 0:
            raise ValueError('module {} without a version'.format(mod))
        if (mod, ver) in self.known_modules:
            self.logger('skipping already parsed (or being parsed) module {} {}'.format(mod, ver))
            return
        self.known_modules.add((mod, ver))

        for pfx in self.internal:
            if mod.startswith(pfx):
                self.logger('ignoring module {} {} matching internal prefix {}'.format(mod, ver, pfx))
                return

        mod_dir = self.find_module(mod, ver)
        if mod_dir is None:
            if self.strict:
                raise FileNotFoundError('missing (internal?) module {} {}'.format(mod, ver))
            else:
                self.logger.warning('ignoring missing (internal?) module {} {}'.format(mod, ver))
                return

        self.profile.add_path(self.profile.joinpath(mod_dir, 'qmldir'), 'r')
        with open(self.profile.joinpath(self.root_dir, mod_dir, 'qmldir'), 'rb') as f:
            for l in [l.decode().strip() for l in f.readlines()]:
                self.logger('scanning line {}'.format(l))
                if re.match(r'^.+\s'+ver+'\sqrc:/.+$', l):
                    self.logger('skipping built-in qrc')
                elif re.match(r'^(\S.+\s'+ver+'\s.+\S|internal\s\S+\s\S+)$', l):
                    res = re.sub(r'(\S+\s+)+', '', l)
                    res_path = self.profile.joinpath(mod_dir, res)
                    if not os.path.exists(self.profile.joinpath(self.root_dir, res_path)):
                        if self.strict:
                            raise FileNotFoundError('missing resource {}'.format(res_path))
                        else:
                            self.logger.warning('ignoring missing resource {}'.format(res_path))
                    self.logger('adding new resource {}'.format(res_path))
                    self.profile.add_path(res_path, 'r')
                    yield from self.scan_resource(self.profile.joinpath(self.root_dir, res_path))
                elif re.match(r'^plugin\s\S+$', l):
                    plug = re.sub(r'^plugin\s+(\S+)$', r'\1', l)
                    plug_path = self.profile.joinpath(mod_dir, 'lib'+plug+'.so')
                    self.logger('adding plugin {}'.format(plug_path))
                    self.profile.add_path(plug_path, 'mr')
                    yield plug_path
                elif len(l):
                    self.logger('ignoring qmldir rule {}'.format(l))

    def list_resources(self, path):
        """List the resources listed in a qrc file
        :param path: path to the qrc file to scan
        :return: a list of strings that are paths to resources
        """
        rcc_cmd = [self.rcc, '--list', path]
        rcc_out = subprocess.Popen(rcc_cmd, stdout=subprocess.PIPE).communicate()[0]
        yield from (res.decode() for res in rcc_out.splitlines())

    def get_qrc_from_file(self, path):
        """Extract the qrc that are bundled in a file
        :param path: the path to a file from which to extract the list of qrc files
        :return: a list of strings that are paths to qrc files
        """
        p = '{}:'.format(self.pattern).encode()
        for dir in [self.root_dir, self.staging_dir]:
            try:
                with open(self.profile.joinpath(dir, path), 'rb') as f:
                    for l in (l for l in f.readlines() if l.startswith(p)):
                        yield l.split(b'\x00')[0].decode()[len(self.pattern)+1:]
                break
            except FileNotFoundError:
                pass

    def get_modules_from_res(self, path):
        """Scan a resource for the modules it needs
        :param path: path to the resource file (a .qml or a .js)
        :return: a list of modules as tuples of (name, version)
        """
        if path.endswith('.qml'):
            lead = 'import '
            mod_re = re.compile(r'^import\s+(\S+)(\s+(\S+).*)?$')
        else:  # .js
            lead = '.import '
            mod_re = re.compile(r'^\.import\s+(\S+)(\s+(\S+).*)?$')
        with open(path, 'rb') as f:
            for l in (l.decode().strip() for l in f.readlines() if l.decode().startswith(lead)):
                self.logger('{}: found module {} version {}'.format(path, mod_re.sub(r'\1', l), mod_re.sub(r'\3', l)))
                yield (mod_re.sub(r'\1', l), mod_re.sub(r'\3', l))

    def find_module(self, mod, ver):
        """Locate a module
        :param mod: the module name
        :param ver: the module version
        :return: the directory where the module was found
        """
        mod_dir = mod.replace('.', '/')
        for v in ['.'+ver, re.sub(r'^([^.]+)\..+', r'.\1', ver), '']:
            d = self.profile.joinpath(self.base_dir, mod_dir+v)
            self.logger('looking for module {} {} in {}'.format(mod, ver, d))
            if os.path.isfile(self.profile.joinpath(self.root_dir, d, 'qmldir')):
                self.logger('--> found')
                return d
        return None
