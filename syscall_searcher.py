#!/usr/bin/env python3
import re
import os
from collections import namedtuple

Arg = namedtuple('Arg', ['type', 'name'])

VALID_FILTER_ATTRS = list(Arg._fields + ('arg', 'syscall_name'))


class Syscall:
    _PARENTHESIS_REXP = re.compile(r'(?<=\()[^)]+')

    def __init__(self, name, args=[]):
        self.name = name
        self.raw_args = args.copy()
        if len(args) == 0:
            self._type_arg_tuples = []
            self.type_names = []
            self.arg_names = []
            self.argcount = 0
            self._repr = "%s()" % self.name
            return

        self._type_arg_tuples = [Arg(*i) for i in zip(*(iter(args),)*2)]
        self._repr = "%s(%s)" % (self.name, ', '.join(' '.join(i) for i in self._type_arg_tuples))
        self.type_names, self.arg_names = list(zip(*self._type_arg_tuples))
        self.argcount = len(self.arg_names)

    def __repr__(self):
        return self._repr

    @staticmethod
    def from_string(string):
        match = re.search(Syscall._PARENTHESIS_REXP, string)
        if match is None:
            raise Exception("Invalid syscall define string")

        all_args = [i.strip() for i in match[0].split(',')]
        name = all_args[0]
        return Syscall(name, all_args[1:])

    @property
    def args(self):
        return self._type_arg_tuples

    def match_mulitple_filters(self, *args):
        if any(not isinstance(i, dict) for i in args):
            return False
        if len(args) == 0:
            return False

        if any(not self.validate_filter(**i) for i in args):
            return False
        raise NotImplementedError("Not yet implemented")
        # an or condition applies across multiple filters for this syscall
        # for filt in args:
        #     argno = None
        #     for k, v in filt.items():

    def match_args(self, **kwargs):
        if self.validate_filter(**kwargs) is False:
            return False

        if kwargs.get('arg') is None:
            return any(self._match_syscall_args(i, **kwargs) for i in range(self.argcount))

        return self._match_syscall_args(**kwargs)

    def _match_syscall_args(self, arg, name=None, type=None, syscall_name=None):
        syscall_arg = self.args[arg]
        res = True
        if name is not None:
            res &= re.search(name, syscall_arg.name) is not None

        if type is not None:
            res &= re.search(type, syscall_arg.type) is not None

        if syscall_name is not None:
            res &= re.search(syscall_name, self.name) is not None

        return res

    def validate_filter(self, **kwarg):
        for k, v in kwarg.items():
            if k not in VALID_FILTER_ATTRS:
                return False
            if isinstance(v, int) and (v >= self.argcount or
                                       v < 0):
                return False
        return True


class SyscallSearcher:
    def __init__(self, syscall_list=[]):
        self.syscall_list = syscall_list.copy()

    def repr_search(self, pattern):
        """
        Search the repr of syscalls for the presence of the given pattern
        """
        return [i for i in self.syscall_list if re.search(pattern, i._repr) is not None]

    @staticmethod
    def from_sigs_file(filepath):
        with open(os.path.expanduser(filepath), "r") as f:
            content = f.read().splitlines()

        syscalls = [Syscall.from_string(i) for i in content]
        return SyscallSearcher(syscalls)

    def __repr__(self):
        return "SyscallSearcher with %d syscalls" % len(self.syscall_list)

    def match_args(self, **kwargs):
        return [i for i in self.syscall_list if i.match_args(**kwargs) is True]

    def search(self, filters):
        ...



ss = SyscallSearcher.from_sigs_file("~/.syscall_sigs")
