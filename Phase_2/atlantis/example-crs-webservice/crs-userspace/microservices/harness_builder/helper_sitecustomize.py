import shlex
import sys
from textwrap import indent
import traceback
from typing import Any


import os
ATLANTIS_OSSFUZZ_DOCKER_MOUNT_SRC = os.environ.get('ATLANTIS_OSSFUZZ_DOCKER_MOUNT_SRC')
ATLANTIS_OSSFUZZ_DOCKER_MOUNT_OUT = os.environ.get('ATLANTIS_OSSFUZZ_DOCKER_MOUNT_OUT')
ATLANTIS_OSSFUZZ_DOCKER_MOUNT_WORK = os.environ.get('ATLANTIS_OSSFUZZ_DOCKER_MOUNT_WORK')
del os


def args_kwargs_to_str(*args, **kwargs) -> str:
    arg_strs = [repr(a) for a in args]
    arg_strs.extend(f'{k}={v!r}' for k, v in kwargs.items())
    return ', '.join(arg_strs)


class MockModule:
    NAME: str
    wrapped: Any

    def __getattr__(self, name: str):
        # https://stackoverflow.com/a/12163576
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            pass

        if hasattr(self.wrapped, name):
            return getattr(self.wrapped, name)

        raise AttributeError(f"module '{self.NAME}' has no attribute '{name}'")


class NewOs(MockModule):
    NAME = 'os'
    import os as wrapped

    def mkdir(self, *args, **kwargs):
        print(f'[sitecustomize.py] [os] Skipping os.mkdir({args_kwargs_to_str(*args, **kwargs)})')

    def makedirs(self, *args, **kwargs):
        print(f'[sitecustomize.py] [os] Skipping os.makedirs({args_kwargs_to_str(*args, **kwargs)})')


class NewSubprocess(MockModule):
    NAME = 'subprocess'
    import subprocess as wrapped

    def run(self, args_arg, *args, **kwargs):
        self._check_subprocess_cli(args_arg)
        return self.wrapped.run(args_arg, *args, **kwargs)

    def Popen(self, args_arg, *args, **kwargs):
        self._check_subprocess_cli(args_arg)
        return self.wrapped.Popen(args_arg, *args, **kwargs)

    def call(self, args_arg, *args, **kwargs):
        self._check_subprocess_cli(args_arg)
        return self.wrapped.call(args_arg, *args, **kwargs)

    def check_call(self, args_arg, *args, **kwargs):
        self._check_subprocess_cli(args_arg)
        try:
            return self.wrapped.check_call(args_arg, *args, **kwargs)
        except self.wrapped.CalledProcessError:
            prefix = '[sitecustomize.py] [subprocess.check_call()] '
            print(f'{prefix}Error:')
            print(indent(traceback.format_exc(), prefix))
            raise

    def check_output(self, args_arg, *args, **kwargs):
        self._check_subprocess_cli(args_arg)
        return self.wrapped.check_output(args_arg, *args, **kwargs)

    def _check_subprocess_cli(self, args: list[str]) -> None:
        print(f'[sitecustomize.py] [subprocess] Checking call: {shlex.join(args)}')

        next_is_v = False
        for i, arg in enumerate(args):
            new_arg = None
            if arg in {'-v', '--volume'}:
                next_is_v = True
                continue
            elif next_is_v:
                next_is_v = False

                # This argument follows "-v"
                if arg.endswith(':/out'):
                    if ATLANTIS_OSSFUZZ_DOCKER_MOUNT_OUT is not None:
                        new_arg = f'{ATLANTIS_OSSFUZZ_DOCKER_MOUNT_OUT}:/out'
                elif arg.endswith(':/work'):
                    if ATLANTIS_OSSFUZZ_DOCKER_MOUNT_WORK is not None:
                        new_arg = f'{ATLANTIS_OSSFUZZ_DOCKER_MOUNT_WORK}:/work'
                elif arg.startswith(ATLANTIS_OSSFUZZ_DOCKER_MOUNT_SRC + ':'):
                    # helper.py uses some somewhat complex logic to
                    # decide where to mount the CP source directory to.
                    # Knowing the name of the directory it picks is
                    # helpful elsewhere, so here, we auto-detect it and
                    # print a specific message to stdout that Harness
                    # Builder can search for to retrieve it.

                    # Harness Builder searches for the specific string
                    # "CP_SRC_MOUNT_PATH" -- don't change it without
                    # updating that too!
                    print(f'[sitecustomize.py] [subprocess] CP_SRC_MOUNT_PATH {arg[arg.find(":") + 1:]}')

            if new_arg is not None:
                print(f'[sitecustomize.py] [subprocess] Replacing {arg!r} with {new_arg!r}')
                args[i] = new_arg


sys.modules['os'] = NewOs()
sys.modules['subprocess'] = NewSubprocess()
