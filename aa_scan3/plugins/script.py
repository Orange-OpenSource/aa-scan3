"""
Complete the AppArmor profile with the rules required for the
interpreter of a script (e.g. shell, python, node...)
"""

class Scanner:
    def __init__(self, parser):
        parser.add_argument('--self-read', action='store_true',
                            help='Add a rule that allows the interpreter to read'
                            + ' itself. This is needed when e.g. it is linked'
                            + ' with -zrelro or -znow.')

    def once(self, path):
        with open(self.profile.joinpath(self.root_dir, path), 'rb') as f:
            blob = f.read()
        if blob[:2] != b'#!':
            return []
        interpreter = blob.splitlines()[0][2:].decode().lstrip()
        if interpreter.split()[0] == '/usr/bin/env':
            self.logger.critical('nested interpreter {!r} not supported'.format(interpreter))
        self.profile.add_path(path, 'r')
        self.logger('adding interpreter {!r}'.format(interpreter))
        if self.self_read:
            self.profile.add_path(interpreter, 'r')
        return [interpreter]
