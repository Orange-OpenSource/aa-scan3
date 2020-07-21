"""
Test if the file is an ELF, and if so emit the list of patterns
to allow it load the libraries specified in DT_NEEDED flags.
"""


import contextlib
import elftools.elf.elffile as ELF


class Scanner:
    def __init__(self, parser):
        parser.add_argument('--lib-dirs', metavar='DIRS',
                            default='/lib,/usr/lib',
                            help='The comma-separated list of directories in which'
                            + ' to look for libraries. If this option is speciffied'
                            + ' multiple times, the last one wins.')
        parser.add_argument('--self-read', action='store_true',
                            help='Add a rule that allows the executable to read itself.'
                            + ' This is needed when e.g. linking with -zrelro or -znow.')

    def once(self, path):
        if self.self_read and self.ELF_open(self.root_dir, path):
            with self.ELF_open(self.root_dir, path) as elf:
                if elf:
                    self.profile.add_path(path, 'r')
        return []

    def scan(self, path):
        def search_libdir(lib):
            for rootdir in [self.root_dir, self.staging_dir]:
                for libdir in self.lib_dirs.split(','):
                    self.logger('trying to locate {} in {} :: {}'.format(lib, rootdir, libdir))
                    with self.ELF_open(rootdir, libdir, lib) as elf:
                        if elf: return libdir  # noqa: E701
            return None

        for search_dir in [self.root_dir, self.staging_dir]:
            self.logger('looking for {} in {}'.format(path, search_dir))
            with self.ELF_open(search_dir, path) as elf:
                if not elf:
                    self.logger('-> not an ELF or missing')
                    continue
                for lib in self.ELF_get_DT_NEEDED(elf):
                    self.logger('looking for DT_NEEDED {}'.format(lib))
                    libdir = search_libdir(lib)
                    if libdir:
                        lib_path = self.profile.joinpath(libdir, lib)
                        self.logger('Adding {}'.format(lib_path))
                        self.profile.add_path(lib_path, 'mr')
                        yield lib_path
                break

    @contextlib.contextmanager
    def ELF_open(self, *dirs):
        p = self.profile.joinpath(*dirs)
        self.logger('opening {}'.format(p))
        try:
            with open(p, 'rb') as f:
                yield ELF.ELFFile(f)
        except FileNotFoundError:
            yield
        except ELF.ELFError:
            yield
        finally:
            self.logger('closing {}'.format(p))

    def ELF_get_DT_NEEDED(self, elf):
        s = elf.get_section_by_name('.dynamic')
        if s:
            for t in s.iter_tags():
                if t.entry.d_tag == "DT_NEEDED":
                    yield t.needed
