import sys
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from multiprocessing import Process, Queue
from multiprocessing.queues import Queue as GenericQueue
from pathlib import Path
from queue import Empty
from typing import Any, Callable, Optional, TextIO

import litellm
import psutil


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


class Tee(TextIO):
    def __init__(self, *files: TextIO):
        self.files = files

    def write(self, obj: str) -> int:
        num_written = 0
        for file in self.files:
            num_written = file.write(obj)

        self.flush()
        return num_written

    def flush(self):
        for file in self.files:
            file.flush()


@contextmanager
def logging_standard_output(stdout_path: Path, stderr_path: Path):
    with open(stdout_path, "a") as stdout_file, open(stderr_path, "a") as stderr_file:
        with (
            redirect_stdout(Tee(sys.stdout, stdout_file)),
            redirect_stderr(Tee(sys.stderr, stderr_file)),
        ):
            yield


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


@contextmanager
def tracking_llm_cost(on_update_cost: Callable[[float], None]):
    original_completion = (  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        litellm.completion
    )

    def _completion(*args: Any, **kwargs: Any):
        response = original_completion(*args, **kwargs)
        try:
            on_update_cost(response._hidden_params["response_cost"])  # pyright: ignore
        except Exception:
            pass
        return response

    litellm.completion = _completion
    try:
        yield
    finally:
        litellm.completion = original_completion
