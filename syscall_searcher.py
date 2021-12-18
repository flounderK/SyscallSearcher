#!/usr/bin/env python3
import re
import os
from collections import namedtuple
import argparse
import sys

Arg = namedtuple('Arg', ['type', 'name'])

VALID_FILTER_ATTRS = list(Arg._fields + ('arg', 'syscall_name', 'negate'))


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
        self._repr = "%s(%s)" % (self.name, ', '.join(' '.join(i)
                                            for i in self._type_arg_tuples))
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
            # pop to avoid having arg specified twice
            if 'arg' in kwargs.keys():
                kwargs.pop('arg')
            return any(self._match_syscall_args(i, **kwargs)
                       for i in range(self.argcount))

        return self._match_syscall_args(**kwargs)

    def _match_syscall_args(self, arg, **kwargs):
        syscall_arg = self.args[arg]
        res = True
        name = kwargs.get('name')
        if name is not None:
            res &= re.search(name, syscall_arg.name) is not None

        typ = kwargs.get('type')
        if typ is not None:
            res &= re.search(typ, syscall_arg.type) is not None

        syscall_name = kwargs.get('syscall_name')
        if syscall_name is not None:
            res &= re.search(syscall_name, self.name) is not None

        negate = kwargs.get('negate')
        if negate is not None and negate is True:
            res = bool(not res)

        return res

    def validate_filter(self, **kwarg):
        """
        Validate that all keys in kwargs are valid values and
        that the arg number won't go out of bounds for this
        syscalls args
        """
        for k, v in kwarg.items():
            if k not in VALID_FILTER_ATTRS:
                return False
            if isinstance(v, int) and (v >= self.argcount or
                                       v < 0):
                # Don't want to throw an error here because that would
                # make only syscalls with 0 args return true
                return False
        return True


class SyscallSearcher:
    def __init__(self, syscall_list=[]):
        self.syscall_list = syscall_list.copy()

    def repr_search(self, pattern):
        """
        Search the repr of syscalls for the presence of the given pattern
        """
        return [i for i in self.syscall_list
                if re.search(pattern, i._repr) is not None]

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


if __name__ == "__main__":
    description = """
    Search through Linux syscalls by name, argument name/position/type
    to help build constrained ROP chains (usually while bypassing seccomp).
    You must first run syscall_sigs.sh on the linux source code to generate the
    necessary signatures for this script.
    """
    epilog = """
    Example:
        ./syscall_searcher.py -a 0 -n '^fd$' -x
        <-- prints all syscalls that do not have 'fd' as the name of their
        first parameter
    """
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument("-f", "--syscall-sigs-file", default="~/.syscall_sigs",
                        type=os.path.expanduser,
                        help="file to read sigs from")
    parser.add_argument("-s", "--syscall-name", type=str, default=None,
                        help="syscall name")
    parser.add_argument("-a", "--arg-no", type=int, default=None,
                        help="Position of argument, starting at 0. "
                        "If not specified, checks all arguments for match")
    parser.add_argument("-n", "--arg-name", type=str, default=None,
                        help="Name of argument")
    parser.add_argument("-t", "--arg-type", type=str, default=None,
                        help="Name of argument's C type. e.g. 'unsigned long'")
    parser.add_argument("-x", "--negate", action="store_true", default=False,
                        help="Negate all other conditions for filter")
    args = parser.parse_args()
    if not os.path.exists(args.syscall_sigs_file):
        print("You must first run 'syscall_sigs.sh' to generate the syscall "
              "signatures to search. Use '-h' for help")
        sys.exit(-1)
    ss = SyscallSearcher.from_sigs_file(args.syscall_sigs_file)
    filter_dict = {"arg": args.arg_no,
                   "name": args.arg_name,
                   "type": args.arg_type,
                   "syscall_name": args.syscall_name,
                   "negate": args.negate}
    matched = ss.match_args(**filter_dict)
    for i in matched:
        print(i)

