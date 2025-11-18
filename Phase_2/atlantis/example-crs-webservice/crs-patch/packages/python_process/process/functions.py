import os
import pty
import signal
import subprocess
import time
from multiprocessing import Process, Queue
from multiprocessing.queues import Queue as GenericQueue
from pathlib import Path
from queue import Empty
from typing import Callable, ParamSpec, TypeVar

import psutil

from .exceptions import ProcessError, TimeoutExpired

_T = TypeVar("_T")
_P = ParamSpec("_P")


def with_retry(
    n: int,
    interval_seconds: float = 1,
    when: Callable[[Exception], bool] = lambda _: True,
):
    def runner(code: Callable[[], _T]) -> _T:
        last_caught_error: Exception | None = None

        for _ in range(n):
            try:
                return code()
            except Exception as error:
                if when(error):
                    last_caught_error = error
                    time.sleep(interval_seconds)
                else:
                    raise error

        assert last_caught_error is not None, "Unreachable code"

        raise last_caught_error

    return runner


def lazy_shell(
    command: str,
    timeout: float | None = None,
    environment: dict[str, str] | None = None,
    current_working_directory: Path | None = None,
):
    def _():
        return shell(
            command,
            timeout=timeout,
            environment=environment,
            current_working_directory=current_working_directory,
        )

    return _


# TODO: make recording-compatible
def shell(
    command: str,
    timeout: float | None = None,
    environment: dict[str, str] | None = None,
    current_working_directory: Path | None = None,
) -> tuple[bytes, bytes]:
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=current_working_directory,
    )

    try:
        stdout, stderr = process.communicate(timeout=timeout)

        match return_code := process.returncode:
            case 0:
                return (stdout, stderr)
            case _:
                raise ProcessError(stdout, stderr, return_code)
    except subprocess.TimeoutExpired as error:
        os.kill(process.pid, signal.SIGINT)
        time.sleep(3)
        _kill_process_tree(process.pid)

        stdout, stderr = process.communicate()

        raise TimeoutExpired(stdout=stdout, stderr=stderr) from error


def shell_with_pty(
    command: str,
    input: bytes | None = None,
    timeout: float | None = None,
    environment: dict[str, str] | None = None,
    current_working_directory: Path | None = None,
):
    main_fd, sub_fd = pty.openpty()
    process = subprocess.Popen(
        command,
        cwd=current_working_directory,
        stdin=sub_fd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        env=environment,
    )

    os.close(sub_fd)

    try:
        if input:
            os.write(main_fd, input + b"\n")

        stdout, stderr = process.communicate(timeout=timeout)

        return_code = process.returncode

        match return_code:
            case 0:
                return (stdout, stderr)
            case _:
                raise ProcessError(stdout, stderr, return_code)
    except subprocess.TimeoutExpired as error:
        os.kill(process.pid, signal.SIGINT)
        time.sleep(3)
        _kill_process_tree(process.pid)
        stdout, stderr = process.communicate()

        raise TimeoutExpired(stdout=stdout, stderr=stderr) from error


def execute_in_process(
    function: Callable[_P, _T],
    timeout: float | None = None,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _T:
    def _(
        queue: GenericQueue[_T | Exception], *args: _P.args, **kwargs: _P.kwargs
    ) -> None:
        try:
            queue.put(function(*args, **kwargs))
        except Exception as e:
            queue.put(e)

    result_queue: Queue[_T | Exception] = Queue()

    process = Process(target=_, args=(result_queue, *args), kwargs=kwargs)

    process.start()

    try:
        result = result_queue.get(timeout=timeout)
    except Empty:
        raise TimeoutError(f"Function execution timed out after {timeout} seconds")
    finally:
        if process.is_alive() and process.pid is not None:
            _kill_process_tree(process.pid)
        process.join()

    match result:
        case Exception() as error:
            raise error
        case _:
            return result


def _kill_process_tree(pid: int) -> None:
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    for child in process.children(recursive=True)[::-1]:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass

    try:
        process.send_signal(signal.SIGKILL)
    except psutil.NoSuchProcess:
        pass
