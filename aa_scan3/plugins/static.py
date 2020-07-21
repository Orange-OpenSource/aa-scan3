"""
This plugins adds options to specify a list of rules and
capabilities from the command line.

The input file is not scanned by this plugin.
"""

import argparse


class Scanner:
    def __init__(self, parser):
        def check_path_rule(arg):
            if len(arg.split(':')) != 2:
                raise argparse.ArgumentTypeError('Malformed static path rule {!r}, expecting \'path:mode\''.format(arg))
            return arg

        def check_net_rule(arg):
            if len(arg.split(':')) != 2:
                raise argparse.ArgumentTypeError('Malformed static network rule {!r}, expecting \'domain:protocol\''.format(arg))
            return arg

        parser.add_argument('--rule', metavar='PATH:MODE',
                            dest='rules', action='append', default=[], type=check_path_rule,
                            help='Accepts as argument path-based rule, where access MODE'
                            + ' is allowed on PATH.')
        parser.add_argument('--capability', metavar='CAPABILITY',
                            dest='capabilities', action='append', default=[],
                            help='Accepts as argument a capability, e.g.: dac_override.')
        parser.add_argument('--network', metavar='DOMAIN:PROTOCOL',
                            dest='networks', action='append', default=[], type=check_net_rule,
                            help='Accepts as argument a network rule, e.g.: inet6:stream.')

    def once(self, _):
        new_files = []
        for rule in self.rules:
            path, mode = rule.split(':')
            self.profile.add_path(path, mode)
            if 'm' in mode:
                new_files.append(path)
        for capability in self.capabilities:
            self.profile.add_capability(capability)
        for network in self.networks:
            domain, protocol = network.split(':')
            self.profile.add_network(domain, protocol)
        return new_files
