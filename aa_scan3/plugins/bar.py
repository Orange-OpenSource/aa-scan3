"""
Hello there, my bar...
"""


class Scanner:
    def __init__(self, parser):
        parser.add_argument('--hello', metavar='WHO', default='world',
                            help='Say hello to WHO.')
