# Software Name : aa-scan3
# SPDX-FileCopyrightText: Copyright (c) 2020 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GPLv2;
# see the COPYING file for more details.
#
# Author: Yann E. MORIN <yann.morin@orange.com> et al.

"""
Test if the file has associated AppArmor snippets in .aa files.

Snippets are located in the `staging` directory, and are named
after the file they apply to, with any `.aa*` extension added.
For example, when scanning file `/bin/foo`, any file that matches
`/bin/foo.aa*` will be considered a snippet that contains rules
to be included in the profile.

A snippet file contains one or more pattern-rules, one per line.
No sanity-check is done on the file, and each line must end with
a new-line '\\n' character (even the last one).

The snippet plugin also has (very crude) support for child
profiles. Child profiles are detected as a line starting with
the keyword 'profile' followed by a path and ending with an
opening curly brace, and extend until the first closing curly
brace. Everything in-between is copied as-is without any mangling
at all (except leading spaces are added or removed to maintain
a consistent indentation in the generated file).
"""


import glob
import os
import re


class Scanner:
    def __init__(self, parser):
        parser.add_argument('--enable', '--disable', default='--enable',
                            action=parser.ToggleAction(['--enable']),
                            help='Enable or disable snippets.')
        parser.add_argument('--file', metavar='FILE',
                            action='append', default=[],
                            help='Read rules and capabilities from the specified file.'
                            + ' This option can be specified more than once, in which'
                            + ' case all files will be used. This option is not'
                            + ' impacted by the --disable option.')

    def once(self, path):
        for snippet in self.file:
            yield from self.read_one_snippet(snippet)

    def scan(self, path):
        if not self.enable:
            return
        for snippet in glob.glob(os.path.join(self.staging_dir, path[1:] + '.aa*')):
            yield from self.read_one_snippet(snippet)

    def read_one_snippet(self, snippet):
        self.logger('parsing snippet {!r}'.format(snippet))
        with open(snippet, 'r') as f:
            for l in (l.strip().rstrip(',') for l in f):
                self.logger('  parsing line {!r}'.format(l))
                if l.startswith('/'):
                    self.logger('    -> is a path')
                    path, mode = re.split(' +', l)
                    self.profile.add_path(path, mode)
                    if 'm' in mode:
                        if '*' not in path:
                            yield path
                elif l.startswith('capability '):
                    self.logger('    -> is a capability')
                    _, cap = re.split(' +', l)
                    self.profile.add_capability(cap)
                elif l.startswith('network '):
                    self.logger('    -> is a network')
                    _, domain, proto = re.split(' +', l)
                    self.profile.add_network(domain, proto)
                elif l.startswith('profile '):
                    self.logger('    -> starts a child profile')
                    self.profile.start_child_profile(re.split(' +', l)[-2])
                elif l.startswith('}'):
                    self.logger('    -> ends a child profile')
                    self.profile.end_child_profile()
