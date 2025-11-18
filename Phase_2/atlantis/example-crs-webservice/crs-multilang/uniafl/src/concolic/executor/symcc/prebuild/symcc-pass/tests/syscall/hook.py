from typing import List, Dict, Callable, Tuple
from ctypes import CDLL, c_void_p
from symcc_interfaces import *

libc = CDLL(None)

class SymCCFile:
    def __init__(self):
        self.offset = 0
        self.file_data_ptr: int = 0
        self.file_size = 0

    def write(self, buf: int, count: int):
        if self.offset + count > self.file_size:
            new_size = self.offset + count
            new_data_ptr: int = libc.realloc(self.file_data_ptr, new_size)
            if new_data_ptr == 0:
                return
            self.file_data_ptr = new_data_ptr
            self.file_size = new_size
            self.offset = new_size
            _sym_memcpy(self.file_data_ptr + self.offset - count, buf, count)
        else:
            _sym_memcpy(self.file_data_ptr + self.offset, buf, count)
            self.offset += count

    def read(self, buf: int, count: int):
        if self.offset + count > self.file_size:
            # technically, this should never happen, but we handle anyway
            count = self.file_size - self.offset
        _sym_memcpy(buf, self.file_data_ptr + self.offset, count)
        self.offset += count

    def __del__(self):
        if self.file_data_ptr:
            libc.free(self.file_data_ptr)


fd_to_file: Dict[int, SymCCFile] = {}


def sym_open_symbolized(return_value: int, _args: List[int]) -> int:
    global fd_to_file
    if return_value != -1:
        fd = return_value
        fd_to_file[fd] = SymCCFile()
        return 0
    else:
        return 0


def sym_lseek_symbolized(return_value: int, args: List[int]) -> int:
    global fd_to_file
    if return_value != -1:
        fd = args[0]
        offset = args[1]
        whence = args[2]
        if fd in fd_to_file:
            if whence == 0:
                fd_to_file[fd].offset = offset
            elif whence == 1:
                fd_to_file[fd].offset += offset
            elif whence == 2:
                fd_to_file[fd].offset = fd_to_file[fd].file_size + offset
        return 0
    else:
        return 0


def sym_write_symbolized(return_value: int, args: List[int]) -> int:
    global fd_to_file
    if return_value != -1:
        fd = args[0]
        buf = args[1]
        count = return_value
        """
        instead of args[2], we use return_value because it is the
        actual number of bytes written
        """
        if fd in fd_to_file:
            fd_to_file[fd].write(buf, count)
            return 0
        else:
            return 0
    else:
        return 0


def sym_read_symbolized(return_value: int, args: List[int]) -> int:
    global fd_to_file
    if return_value != -1:
        fd = args[0]
        buf = args[1]
        """
        instead of args[2], we use return_value because it is the
        actual number of bytes read
        """
        count = return_value 
        if fd in fd_to_file:
            fd_to_file[fd].read(buf, count)
            return 0
        else:
            return 0
    else:
        return 0


dispatch: Dict[str, Dict[str, Callable]] = {}
dispatch["libc.so.6"] = {
    "mkstemp64": sym_open_symbolized,
    "__write": sym_write_symbolized,
    "read": sym_read_symbolized,
    "open": sym_open_symbolized,
}


def main(
    library_name: str, function_name: str, return_value: int, args: List[int]
) -> Tuple[int, int, str]:
    if not library_name in dispatch:
        return 0, 0, ""
    if not function_name in dispatch[library_name]:
        return 0, 1, ""
    return dispatch[library_name][function_name](return_value, args)
