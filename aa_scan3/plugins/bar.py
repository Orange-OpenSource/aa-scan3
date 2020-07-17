"""
Hello there, my bar...
"""


class Scanner:
    def __init__(self, parser):
        parser.add_argument('--hello', metavar='WHO', default='world',
                            help='Say hello to WHO.')

    def once(self, path):
        self.logger('bar called once for {}'.format(path))
        self.profile.add_path(path, 'r')
        return []

    def scan(self, path):
        return []

    def mangle(self, path):
        return path

    def emit(self, path):
        return path
