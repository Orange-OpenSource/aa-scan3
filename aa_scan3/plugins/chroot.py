# Software Name : aa-scan3
# SPDX-FileCopyrightText: Copyright (c) 2020 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GPLv2;
# see the COPYING file for more details.
#
# Author: Yann E. MORIN <yann.morin@orange.com> et al.

"""
This plugins adds the path to a chroot directory in front
of all paths.

Note: if a path starts with '/=/' the chroot is not added,
and the leading '/=' is removed, to allow rules to access
files outside the chroot (e.g. via filedescriptors passed
through a socket).
"""


class Scanner:
    def __init__(self, parser):
        parser.add_argument('--dir', metavar='DIR',
                            default=None,
                            help='The chroot directory')

    def emit(self, path):
        if path.startswith('/=/'):
            if self.dir is None:
                self.logger.warning('out-of-chroot path but not in a chroot: {}'.format(path))
            return path[2:]
        elif self.dir is not None:
            return '/'.join([self.dir, path])
        return path
