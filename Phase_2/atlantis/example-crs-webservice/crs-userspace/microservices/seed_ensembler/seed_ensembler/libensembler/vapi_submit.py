import os
from pathlib import Path
import shlex
import subprocess
import sys

from .logger_wrapper import LoggerWrapper


logger = LoggerWrapper.getLogger(__name__)


def is_vapi_enabled() -> bool:
    return 'VAPI_HOST' in os.environ


class VapiSubmitter:
    submitted_crashes: set[bytes]

    def __init__(self):
        super().__init__()
        self.submitted_crashes = set()

    def submit_crash(self, cp_name: str, harness_id: str, seed_path: Path, sanitizer_output: bytes, *, is_timeout: bool) -> None:
        if sanitizer_output in self.submitted_crashes:
            logger.info(f'Duplicate crash: {sanitizer_output!r}')
            return

        self.submitted_crashes.add(sanitizer_output)

        if not is_vapi_enabled():
            logger.info(f'VAPI_HOST not defined, skipping submission of {seed_path} for {cp_name}/{harness_id} ({sanitizer_output!r})')
            return

        env = dict(os.environ)
        env['TARGET_CP'] = cp_name

        cmd = [
            sys.executable,
            '-m',
            'libCRS.submit',
            'submit_vd',
            '--harness',
            harness_id,
            '--pov',
            str(seed_path.resolve()),
            '--sanitizer-output',
            sanitizer_output.decode('utf-8', errors='replace'),
            '--finder',
            'crs-userspace',
        ]

        logger.info(f'Submitting crash for {harness_id} ({sanitizer_output!r}): TARGET_CP={cp_name} {shlex.join(cmd)}')

        res = subprocess.run(cmd, env=env, capture_output=True)
        if res.returncode != 0:
            msg = f'Failed to submit crash to libCRS: {res.stderr!r}'
            logger.error(msg)
            raise Exception(msg)
