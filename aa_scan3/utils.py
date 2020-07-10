import argparse


class AAScanArgParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        argparse.ArgumentParser.__init__(self,
                                         formatter_class=AAScanArgParser.DescFormatter,
                                         *args, **kwargs)

    class DescFormatter(argparse.HelpFormatter):
        """Format text like argparse.HelpFormatter, but keeping existing paragraphs"""
        def _fill_text(self, text, width, indent):
            sup = super(AAScanArgParser.DescFormatter, self)
            paragraphs = []
            for p in text.split('\n\n'):
                paragraphs.append(sup._fill_text(p, width, indent))
            return "\n\n".join(paragraphs)

    # Inspired by: https://stackoverflow.com/questions/12151306
    def add_argument(self, *args, help_with_default=True, **kwargs):
        if 'default' in kwargs and args[0] != '-h':
            if 'help' in kwargs and help_with_default:
                kwargs['help'] += ' [default: {}]'.format(kwargs['default'])

        if 'action' in kwargs and type(kwargs['action']) is type:
            kwargs['default'] = kwargs['action'].is_default(kwargs['default'])

        super().add_argument(*args, **kwargs)

    @classmethod
    def ToggleAction(_, true_list):
        """Return a toggle action class which is true for items in the true_list

        true_list: list of arguments that are 'True'
        """

        if type(true_list) is not list:
            raise TypeError('l1 is a {}, expecting a list'.format(type(true_list).__name__))

        class _ToggleAction(argparse.Action):
            def __init__(self, option_strings, dest, **kwargs):
                for key in ["type", "nargs"]:
                    if key in kwargs:
                        raise ValueError('"{}" not allowed'.format(key))
                self.true_list = true_list
                super(_ToggleAction, self).__init__(option_strings, dest, nargs=0,
                                                    type=bool, **kwargs)

            def __call__(self, parser, namespace, values, option_string=None):
                setattr(namespace, self.dest, option_string in self.true_list)

            @classmethod
            def is_default(_, value):
                return value in true_list

        return _ToggleAction