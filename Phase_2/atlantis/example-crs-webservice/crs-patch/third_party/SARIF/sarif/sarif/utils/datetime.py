import os
import platform
from datetime import datetime, timezone
from pathlib import Path


def creation_date(path_to_file: Path) -> datetime:
    if platform.system() == "Windows":
        # Get creation time on Windows
        timestamp = os.path.getctime(path_to_file.as_posix())
    else:
        # Get birth time or modification time on other platforms
        stat = os.stat(path_to_file.as_posix())
        try:
            timestamp = stat.st_birthtime
        except AttributeError:
            timestamp = stat.st_mtime

    # Convert timestamp to UTC datetime
    utc_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return utc_time
