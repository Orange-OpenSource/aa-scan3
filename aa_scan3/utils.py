import argparse
import logging
import pathlib
import sys


class AAprofile:
    X_MOD = set('pPcCuUi')

    def __init__(self, path, path_filter):
        self.path = path
        self.filter = path_filter
        self.paths = dict()

    def get_path(self):
        return self.filter(self.path)

    def add_path(self, path, mode):
        path = self.filter(path)
        if not path: return  # noqa: E701
        try:
            old_x = set(self.paths[path]) & AAprofile.X_MOD
            new_x = set(mode) & AAprofile.X_MOD
            if len(old_x ^ new_x) > 1:
                raise ValueError('Adding new executable mode {}, while {} already used'.format(new_x,
                                                                                               old_x))
            logging.debug('Updating {} with new mode {}'.format(path, mode))
            self.paths[path] += mode
        except KeyError:
            logging.debug('Adding {} with mode {}'.format(path, mode))
            self.paths[path] = mode

    def add_capability(self, capability):
        pass

    def add_network(self, domain, protocol):
        pass

    def start_child_profile(self, path):
        pass

    def end_child_profile(self):
        pass

    def get_paths(self):
        for p in self.paths:
            x = set(self.paths[p]) & AAprofile.X_MOD
            if x:
                yield (p, '{}x'.format(''.join(x)))
            yield (p, ''.join(sorted(set(self.paths[p]) -
                                        (AAprofile.X_MOD | {'x'}))))

    def get_capabilities(self):
        return []

    def get_networks(self):
        return []

    def get_children(self):
        return []

    @staticmethod
    def joinpath(*components):
        """like os.path.join(), except components with a
        leading '/' do not ignore previous components
        """
        p = pathlib.Path('/')
        for comp in components:
            p = p.joinpath(comp[1:] if comp[0] == '/' else comp)
        return str(p)


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

    class _ArgGroupPlugin:
        def __init__(self, plugin, group):
            self.plugin = plugin
            self.group = group

        def add_argument(self, *args, **kwargs):
            new_args = []
            for a in args:
                if not a.startswith('--'):
                    raise ValueError('Incorrect option "{}", only long options allowed'.format(a))
                new_args.append('--{}-{}'.format(self.plugin, a[2:]))

            if 'default' in kwargs and 'help' in kwargs:
                kwargs['help'] += ' [default: {}]'.format(kwargs['default'])

            if 'dest' in kwargs:
                kwargs['dest'] = '{}_{}'.format(self.plugin, kwargs['dest'])

            self.group.add_argument(*new_args, **kwargs)

        def ToggleAction(self, true_list):
            new_list = ['--{}-{}'.format(self.plugin, i[2:]) for i in true_list]
            return AAScanArgParser.ToggleAction(new_list)

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


class AALogger:
    def __init__(self, plugin):
        self.prefix = '{}: '.format(plugin)

    def __call__(self, msg, *args, **kwargs):
        self.debug(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        logging.debug(self.prefix + msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        logging.info(self.prefix + msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        logging.warning(self.prefix + msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        logging.error(self.prefix + msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        logging.critical(self.prefix + msg, *args, **kwargs)
        sys.exit(1)
