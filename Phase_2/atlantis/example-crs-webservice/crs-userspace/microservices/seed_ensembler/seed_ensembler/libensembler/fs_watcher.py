from __future__ import annotations

import os
from pathlib import Path
import re
import time
from typing import Callable, NoReturn, TypeAlias
from uuid import UUID

from watchdog.events import FileSystemEventHandler, DirCreatedEvent, FileCreatedEvent
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from .logger_wrapper import LoggerWrapper
from .models import Configuration


DIRECTORY_NAME_REGEX = re.compile(r'(?P<harness_id>.+)-(?P<script_id>\d+)-{(?P<uuid>.+)}')
DONE_FILE_NAME = 'DONE'
POLLING_TIMEOUT = 0.25  # seconds

# test case, trying to strain the harness_id in particular relatively hard
assert (DIRECTORY_NAME_REGEX.match('pov harness-123-123-{8e458e93-689c-468b-ba30-49cf54ab3878}').groupdict()  # type: ignore
    == {'harness_id': 'pov harness-123', 'script_id': '123', 'uuid': '8e458e93-689c-468b-ba30-49cf54ab3878'})


DirectoryReadyCallback: TypeAlias = Callable[[Path, str, int, UUID], None]


logger = LoggerWrapper.getLogger(__name__)


class FolderHandler(FileSystemEventHandler):
    root_path: Path
    callback: DirectoryReadyCallback

    def __init__(self, root_path: Path, callback: DirectoryReadyCallback, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.root_path = root_path.resolve()
        self.callback = callback

    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        """Handle file- and folder-creation events"""
        if event.is_directory:
            return

        path = Path(os.fsdecode(event.src_path))

        if (path.name == DONE_FILE_NAME
            and DIRECTORY_NAME_REGEX.fullmatch(path.parent.name)
            and path.parent.parent.resolve() == self.root_path
        ):
            self.handle_folder_done(path.parent)

    def handle_folder_done(self, path: Path) -> None:
        """
        This is called once we see a DONE file created in a subdirectory
        """
        match = DIRECTORY_NAME_REGEX.fullmatch(path.name)
        if not match:
            logger.error(f'{path} is "done", but doesn\'t fit the correct directory naming scheme')
            return

        harness_id = match['harness_id']
        script_id = int(match['script_id'])
        uuid = UUID(match['uuid'])

        # Remove the DONE file so it doesn't get passed to libfuzzer
        # (yes, missing_ok=True is important, because this line
        # sometimes raised FileNotFoundError during testing. no, I have
        # no idea how that could possibly happen)
        (path / DONE_FILE_NAME).unlink(missing_ok=True)

        self.callback(path, harness_id, script_id, uuid)


def watch_directory(config: Configuration, callback: DirectoryReadyCallback, *, blocking: bool = True) -> NoReturn | None:
    watch_type = 'inotify' if config.use_inotify else 'simple polling'
    logger.info(f'Setting up {watch_type} watch on {config.seeds_input_dir}')

    handler = FolderHandler(config.seeds_input_dir, callback)
    observer = Observer() if config.use_inotify else PollingObserver(timeout=POLLING_TIMEOUT)
    observer.schedule(handler, str(config.seeds_input_dir), recursive=True)

    observer.start()

    if blocking:
        try:
            while True:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()

    else:
        # (makes mypy happy)
        return None
