"""
This mangle plugin applies a set of pattern substitutions (aka
replacements) on the path of pattern rule.

The @PROG_NAME@ placeholder is automatically replaced with the
program_invocation_short_name(3) of the scanned executable.
"""


import re


class Scanner:
    def __init__(self, parser):
        self.first = True
        parser.add_argument('--regexp', metavar='s/REGEXP/REPLACE/',
                            dest='regexps', action='append', default=[],
                            help='Apply the sed(1) substitution, where any match'
                            + ' of REGEXP is replaced with REPLACE. References'
                            + ' from \\1 to \\9 have their usual meaning (but &'
                            + ' is not supported). Can be used more than once,'
                            + ' in which case they are applied in the order they'
                            + ' appear on the command line.')

    def mangle(self, path):
        if self.first:
            self.first = False
            esc = '\\\\'
            self._regexps = []
            for r in self.regexps:
                if r[0] != 's':
                    raise NotImplementedError('Unexpected sed expression {}'.format(r))
                sep = r[1]
                _r = [re.sub(esc+sep, sep, i) for i in re.split('(?<!'+esc+')'+sep, r)[1:-1]]
                self._regexps.append((_r[0], _r[1]))
            prog_name = self.profile.get_path().split('/')[-1]
            self._regexps.append(('@PROG_NAME@', prog_name))

        for r in self._regexps:
            self.logger('r={}'.format(r))
            path = re.sub(r[0], r[1], path)

        return path
