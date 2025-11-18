from base64 import b64encode
from pathlib import Path
import re
import subprocess
import traceback
import zlib

from .logger_wrapper import LoggerWrapper


LIBFUZZER_SECTION_REGEX = re.compile(r'^\s*\[\s*libfuzzer\s*\]', re.IGNORECASE)
OTHER_SECTION_REGEX = re.compile(r'^\s*\[')
TIMEOUT_EXITCODE_REGEX = re.compile(r'^\s*timeout_exitcode\s*=\s*0', re.IGNORECASE)


logger = LoggerWrapper.getLogger(__name__)


def check_if_timeouts_scorable_in_options_file(options_file_path: Path) -> bool:
    try:
        if not options_file_path.is_file():
            return True

        in_libfuzzer_section = False
        for line in options_file_path.open('r', encoding='utf-8'):
            if LIBFUZZER_SECTION_REGEX.match(line):
                in_libfuzzer_section = True
                continue
            elif in_libfuzzer_section and OTHER_SECTION_REGEX.match(line):
                break

            if in_libfuzzer_section and TIMEOUT_EXITCODE_REGEX.match(line):
                return False

        return True

    except Exception:
        logger.warning(f'Error while reading {options_file_path}: {traceback.format_exc()}')
        return True


def fs_copy(src: Path, dst: Path) -> None:
    """Logic mostly duplicated from libCRS"""
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
        src = f'{src}/.'  # type: ignore
    elif src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
    else:
        raise FileNotFoundError(f'{src} does not exist')

    subprocess.run(['rsync', '-a', str(src), str(dst)])


def compress_str(s: bytes | bytearray | str) -> str:
    if isinstance(s, str):
        s = s.encode('utf-8')
    s = zlib.compress(s, wbits=-15)
    return b64encode(s).decode('ascii')


def run_all_tests():
    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        options_file = temp_dir / 'example.options'

        assert check_if_timeouts_scorable_in_options_file(options_file)

        options_file.write_text('[libfuzzer]\ntimeout_exitcode=0')
        assert not check_if_timeouts_scorable_in_options_file(options_file)

        options_file.write_text("""
        [test]
        timeout_exitcode=0

        [libfuzzer]
        """)
        assert check_if_timeouts_scorable_in_options_file(options_file)

        options_file.write_text("""
        [test]
        timeout_exitcode=0

        [  LiBfUzZeR  ]
        more
        lines
        timeout_exitcode  =  0

        [another]
        hi
        """)
        assert not check_if_timeouts_scorable_in_options_file(options_file)

    print('all tests passed')


if __name__ == '__main__':
    run_all_tests()
