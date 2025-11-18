import os
import pty
import signal
import subprocess
import time
import warnings
from multiprocessing import Process, Queue
from multiprocessing.queues import Queue as GenericQueue
from pathlib import Path
from queue import Empty
from typing import Any, Callable, Optional, Sequence

import psutil

from crete.commons.interaction.exceptions import CommandInteractionError, TimeoutExpired
from crete.commons.utils import remove_ansi_escape_codes

_Command = tuple[str | Sequence[str], Path]


def run_command(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input: bytes | None = None,
    isatty: bool = False,
    no_color: bool = False,
) -> tuple[str, str]:
    if no_color:
        return _run_command_without_color(command, timeout, env, input, isatty)
    else:
        return _run_command(command, timeout, env, input, isatty)


def _run_command_without_color(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input: bytes | None = None,
    isatty: bool = False,
) -> tuple[str, str]:
    try:
        stdout, stderr = _run_command(command, timeout, env, input, isatty)
        return remove_ansi_escape_codes(stdout), remove_ansi_escape_codes(stderr)
    except CommandInteractionError as e:
        raise CommandInteractionError(
            stdout=remove_ansi_escape_codes(e.stdout),
            stderr=remove_ansi_escape_codes(e.stderr),
            return_code=e.return_code,
        ) from e
    except TimeoutExpired as e:
        raise TimeoutExpired(
            stdout=remove_ansi_escape_codes(e.stdout),
            stderr=remove_ansi_escape_codes(e.stderr),
        ) from e


def _run_command(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input: bytes | None = None,
    isatty: bool = False,
) -> tuple[str, str]:
    warnings.warn(
        "run_command is deprecated and will be removed in the future. Please use python_process.process.functions.shell instead.",
        DeprecationWarning,
    )

    if isatty:
        return _run_command_with_pty(command, timeout, env, input)

    line, cwd = command

    process = subprocess.Popen(
        line,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=isinstance(line, str),
        env=env,
    )

    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)

        return_code = process.returncode

        match return_code:
            case 0:
                return (stdout.decode(errors="ignore"), stderr.decode(errors="ignore"))
            case _:
                raise (
                    CommandInteractionError(
                        stdout=stdout, stderr=stderr, return_code=return_code
                    )
                )
    except subprocess.TimeoutExpired as error:
        os.kill(process.pid, signal.SIGINT)
        time.sleep(5)
        _kill_process_tree(process.pid)
        stdout, stderr = process.communicate()

        raise TimeoutExpired(stdout=stdout, stderr=stderr) from error


def execute_in_process(
    function: Callable[..., Any],
    args: tuple[Any, ...],
    timeout: Optional[int] = None,
) -> Any:
    def _(args: tuple[Any, ...], queue: GenericQueue[Any]):
        try:
            queue.put(function(*args))
        except Exception as e:
            queue.put(e)

    result_queue: GenericQueue[Any] = Queue()
    process = Process(
        target=_,
        args=(
            args,
            result_queue,
        ),
    )
    process.start()
    try:
        result = result_queue.get(timeout=timeout)
    except Empty:
        raise TimeoutError(f"Timed out after {timeout} seconds")
    finally:
        if process.is_alive() and process.pid is not None:
            _kill_process_tree(process.pid)
        process.join()

    match result:
        case Exception() as e:
            raise e
        case _:
            return result


def _kill_process_tree(pid: int):
    try:
        psutil_process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    children = psutil_process.children(recursive=True)
    for child in children[::-1]:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass

    try:
        psutil_process.kill()
    except psutil.NoSuchProcess:
        pass


def _run_command_with_pty(
    command: _Command,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    input: bytes | None = None,
) -> tuple[str, str]:
    line, cwd = command

    main, sub = pty.openpty()
    process = subprocess.Popen(
        line,
        cwd=cwd,
        stdin=sub,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        env=env,
    )
    os.close(sub)

    try:
        if input:
            os.write(main, input + b"\n")
        stdout, stderr = process.communicate(timeout=timeout)

        return_code = process.returncode

        match return_code:
            case 0:
                return (stdout.decode(errors="ignore"), stderr.decode(errors="ignore"))
            case _:
                raise (
                    CommandInteractionError(
                        stdout=stdout, stderr=stderr, return_code=return_code
                    )
                )
    except subprocess.TimeoutExpired as error:
        os.kill(process.pid, signal.SIGINT)
        time.sleep(5)
        _kill_process_tree(process.pid)
        stdout, stderr = process.communicate()

        raise TimeoutExpired(stdout=stdout, stderr=stderr) from error
