from typing import List, Dict, Callable, Optional, Tuple
from ctypes import (
    CDLL,
    Structure,
    c_char_p,
    c_void_p,
    c_char,
    c_int,
    cast,
    POINTER,
    byref,
    util as ctypes_util,
)
from symcc_interfaces import (
    _sym_build_data_length,
    _sym_build_integer,
    _sym_build_signed_less_equal,
    _sym_build_equal,
    _sym_push_path_constraint,
    _sym_build_extract_element,
    _sym_build_float_to_bits,
    _sym_memcpy,
    _sym_build_bool_and,
    _sym_extract_helper,
    _sym_concat_helper,
    _sym_build_zext,
    _sym_build_sext,
    _sym_build_trunc,
    _sym_build_int_to_float,
    _sym_build_float_to_float,
    _sym_build_float_to_signed_integer,
    _sym_build_float_to_unsigned_integer,
    _sym_build_insert_element,
    _sym_build_symbolic_array_int,
    _sym_build_symbolic_array_fp,
    _sym_build_ite,
    _sym_read_memory,
)
import os
from addr_to_symbols import ADDR_TO_SYMBOLS


RUNTIME_SITE_ID = (1 << 63) | (0x13371337133C00)
POINTER_WIDTH = 64

def print(x):
    if os.getenv("SYMCC_HOOK_VERBOSE", False):
        with open("/work/hook-log.txt", "a") as f:
            f.write(f"{x}\n")
    return


def model_error():
    print("model error")
    return 0


def assert_int(maybe_int: Optional[int]) -> int:
    if isinstance(maybe_int, int):
        return maybe_int
    else:
        raise Exception("None")


def read_int(addr: int) -> int:
    """Read an integer from the given memory address."""
    return cast(addr, POINTER(c_int)).contents.value


def read_char(addr: int) -> int:
    """Read an integer from the given memory address."""
    return cast(addr, POINTER(c_char)).contents.value[0]


def symexpr_to_rsymexpr(symexpr: int) -> int:
    return symexpr >> 16


def _load_memory_map():
    """Parses /proc/self/maps and returns a list of (start, end, perms) tuples."""
    mappings = []
    with open("/proc/self/maps", "r") as maps:
        for line in maps:
            parts = line.split()
            addr_range, perms = parts[0], parts[1]
            start_str, end_str = addr_range.split("-")
            start = int(start_str, 16)
            end = int(end_str, 16)
            mappings.append((start, end, perms))
    return mappings


def is_read_only_address(addr: int) -> bool:
    """
    Return True if the memory page containing `addr` is mapped readable but not writable.
    Uses a cached view of /proc/self/maps.
    """
    for start, end, perms in _memory_map_cache:
        if start <= addr < end:
            return perms[0] == "r" and perms[1] == "-"
    return False


class SymCCFile:
    """Base class for symbolic file descriptors."""

    def __init__(self):
        self.offset = 0
        self.file_data_ptr: int = 0
        self.file_size = 0

    def write(self, buf: int, count: int):
        """Write data to the file."""
        raise NotImplementedError("Subclasses must implement write()")

    def read(self, buf: int, count: int):
        """Read data from the file."""
        raise NotImplementedError("Subclasses must implement read()")

    def __del__(self):
        if self.file_data_ptr:
            # libc.free(self.file_data_ptr)
            self.file_data_ptr = 0


class SymCCRegularFile(SymCCFile):
    """Regular file implementation."""

    def write(self, buf: int, count: int):
        if self.offset + count > self.file_size:
            new_size = self.offset + count
            new_data_ptr: int = libc.realloc(self.file_data_ptr, new_size)
            if new_data_ptr == 0:
                raise MemoryError("Failed to allocate memory for file buffer")
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


class SymCCPipeFd(SymCCFile):
    """Pipe file descriptor implementation."""

    def __init__(self, is_read_end=True):
        super().__init__()
        self.is_read_end = is_read_end
        self.paired_fd = None

    def set_pair(self, paired_fd):
        """Set the paired file descriptor (read or write end)."""
        self.paired_fd = paired_fd

    def write(self, buf: int, count: int):
        if self.is_read_end:
            model_error()
            return

        if self.offset + count > self.file_size:
            new_size = self.offset + count
            new_data_ptr: int = libc.realloc(self.file_data_ptr, new_size)
            if new_data_ptr == 0:
                raise MemoryError("Failed to allocate memory for pipe buffer")
            self.file_data_ptr = new_data_ptr
            self.file_size = new_size
            _sym_memcpy(self.file_data_ptr + self.offset, buf, count)
            self.offset += count
        else:
            _sym_memcpy(self.file_data_ptr + self.offset, buf, count)
            self.offset += count

    def read(self, buf: int, count: int):
        if not self.is_read_end:
            model_error()
            return
        other = self.paired_fd
        if other is None:
            model_error()
            return
        if self.offset + count > other.file_size:
            # For pipes, we only read what's available
            # you should use your own offset instead of the other's,
            # because the other's offset is incremented in the write
            count = other.file_size - self.offset

        if count > 0:
            _sym_memcpy(buf, other.file_data_ptr + self.offset, count)
            self.offset += count


class SymCCSocketPairFd(SymCCFile):
    """socketpair file descriptor implementation."""

    def __init__(self):
        super().__init__()
        self.paired_fd = None

    def set_pair(self, paired_fd):
        """Set the paired file descriptor (read or write end)."""
        self.paired_fd = paired_fd

    def write(self, buf: int, count: int):
        if self.offset + count > self.file_size:
            new_size = self.offset + count
            new_data_ptr: int = libc.realloc(self.file_data_ptr, new_size)
            if new_data_ptr == 0:
                raise MemoryError("Failed to allocate memory for pipe buffer")
            self.file_data_ptr = new_data_ptr
            self.file_size = new_size
            _sym_memcpy(self.file_data_ptr + self.offset, buf, count)
            self.offset += count
        else:
            _sym_memcpy(self.file_data_ptr + self.offset, buf, count)
            self.offset += count

    def read(self, buf: int, count: int):
        other = self.paired_fd
        if other is None:
            model_error()
            return
        if self.offset + count > other.file_size:
            # For socketfds, we only read what's available
            # you should use your own offset instead of the other's,
            # because the other's offset is incremented in the write
            count = other.file_size - self.offset

        if count > 0:
            _sym_memcpy(buf, other.file_data_ptr + self.offset, count)
            self.offset += count


fd_to_file: Dict[int, SymCCFile] = {}
libc = CDLL(None)


def sym_open_symbolized(
    return_value: Optional[int], _args: List[int], _concrete_args: List[Optional[int]]
) -> int:
    global fd_to_file
    if return_value is not None and return_value != -1:
        fd = return_value
        fd_to_file[fd] = SymCCRegularFile()
        return 0
    else:
        return 0


def sym_lseek_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    global fd_to_file
    assert all(
        x is not None for x in concrete_args
    ), "All concrete arguments must be non-None for lseek"
    assert len(concrete_args) >= 3, "lseek requires at least 3 arguments"
    if return_value is not None and return_value != -1:
        fd = assert_int(concrete_args[0])
        offset = assert_int(concrete_args[1])
        whence = assert_int(concrete_args[2])
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


def sym_write_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    global fd_to_file
    if return_value is not None and return_value != -1:
        fd = assert_int(concrete_args[0])
        buf = assert_int(concrete_args[1])
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


def sym_read_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    global fd_to_file
    if return_value is not None and return_value != -1:
        fd = assert_int(concrete_args[0])
        buf = assert_int(concrete_args[1])
        nbytes = assert_int(concrete_args[2])
        """
        instead of args[2], we use return_value because it is the
        actual number of bytes read
        """
        count = return_value
        if count == 0xFFFFFFFFFFFFFFFF or count < nbytes:
            data_length = _sym_build_data_length(0)
            if data_length != 0:
                data_length_max = _sym_build_integer(10000, 64)
                length_constraint = _sym_build_signed_less_equal(
                    data_length, data_length_max
                )
                _sym_push_path_constraint(length_constraint, True, RUNTIME_SITE_ID)
        if fd in fd_to_file:
            fd_to_file[fd].read(buf, count)
            return 0
        else:
            return 0
    else:
        return 0


def sym_pipe_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    global fd_to_file
    assert all(
        x is not None for x in concrete_args
    ), "All concrete arguments must be non-None for pipe"
    assert len(concrete_args) >= 1, "pipe requires at least 1 argument"
    if return_value is not None and return_value != -1:
        pipefd_ptr = assert_int(concrete_args[0])

        # Get the file descriptors from the pipefd array
        # We need to read the two integers from the memory pointed to by pipefd_ptr
        read_fd = read_int(pipefd_ptr)
        write_fd = read_int(pipefd_ptr + 4)  # Assuming 4 bytes per int

        # Create symbolic pipe file objects
        read_end = SymCCPipeFd(is_read_end=True)
        write_end = SymCCPipeFd(is_read_end=False)

        # Set up the paired relationship
        read_end.set_pair(write_end)
        write_end.set_pair(read_end)
        fd_to_file[read_fd] = read_end
        fd_to_file[write_fd] = write_end
        return 0
    else:
        return 0


def sym_fcntl_symbolized(
    return_value: Optional[int], _args: List[int], _concrete_args: List[Optional[int]]
) -> int:
    return 0


def sym_dup2_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    global fd_to_file
    if return_value is not None and return_value != -1:
        oldfd = assert_int(concrete_args[0])
        newfd = assert_int(concrete_args[1])

        if oldfd in fd_to_file:
            fd_to_file[newfd] = fd_to_file[oldfd]
            return 0
        else:
            model_error()
            return 0
    return 0


def sym_socketpair_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    if return_value != 0:
        return 0
    sv_ptr = assert_int(concrete_args[3])
    # Get the file descriptors from the pipefd array
    # We need to read the two integers from the memory pointed to by pipefd_ptr
    fd0_ = read_int(sv_ptr)
    fd1_ = read_int(sv_ptr + 4)  # Assuming 4 bytes per int
    fd0 = SymCCSocketPairFd()
    fd1 = SymCCSocketPairFd()
    fd0.set_pair(fd1)
    fd1.set_pair(fd0)
    fd_to_file[fd0_] = fd0
    fd_to_file[fd1_] = fd1
    return 0


def compare_bytes(ptr0: int, ptr1: int, length: int) -> int:
    res = 0
    for i in range(length):
        a0 = _sym_read_memory(ptr0 + i, 1, False)
        a1 = _sym_read_memory(ptr1 + i, 1, False)
        equals = _sym_build_equal(a0, a1)
        if res == 0:
            res = equals
        else:
            res = _sym_build_bool_and(res, equals)
    return res


def compare_bytes_against_constant(sym_ptr: int, const_ptr: int, length: int) -> int:
    res = 0
    for i in range(length):
        a0 = _sym_read_memory(sym_ptr + i, 1, False)
        a1 = _sym_build_integer(read_char(const_ptr + i), 8)
        equals = _sym_build_equal(a0, a1)
        if res == 0:
            res = equals
        else:
            res = _sym_build_bool_and(res, equals)
    return res


def _strlen(ptr: int) -> int:
    i = 0
    while True:
        ch = read_char(ptr + i)
        if ch == 0:
            break
        i += 1
    return i


def sym_strcmp_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    ptr0 = assert_int(concrete_args[0])
    ptr1 = assert_int(concrete_args[1])
    # Easy case: one of the strings is a constant string
    if is_read_only_address(ptr0) and not is_read_only_address(ptr1):
        res = compare_bytes_against_constant(ptr0, ptr1, _strlen(ptr0))
    elif is_read_only_address(ptr1) and not is_read_only_address(ptr0):
        res = compare_bytes_against_constant(ptr0, ptr1, _strlen(ptr1))
    else:
        # Hard case: it's hard, but let's compromise
        res = compare_bytes(ptr0, ptr1, min(_strlen(ptr0), _strlen(ptr1)))
    res = _sym_build_ite(
        res,
        _sym_build_integer(0, 32),
        _sym_build_integer(assert_int(return_value), 32),
    )
    return symexpr_to_rsymexpr(res)


def sym_strdup_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    dst_ptr = assert_int(return_value)
    src_ptr = assert_int(concrete_args[0])
    _sym_memcpy(src_ptr, dst_ptr, _strlen(src_ptr))
    return 0


def sym_strlen_symbolized(
    return_value: Optional[int], _args: List[int], concrete_args: List[Optional[int]]
) -> int:
    return 0


def generic_movmsk(
    vector: int,
    vector_num_elems: int,
    vector_elem_size: int,
    is_fp: bool,
    output_size: int,
) -> int:
    mask = 0
    for i in range(vector_num_elems):
        elem = _sym_build_extract_element(vector, i)
        if is_fp:
            elem = _sym_build_float_to_bits(elem)
        bit = _sym_extract_helper(elem, 0, 0)
        if mask == 0:
            mask = bit
        else:
            mask = _sym_concat_helper(mask, bit)
    mask = _sym_build_zext(mask, output_size - vector_num_elems)
    return symexpr_to_rsymexpr(mask)


class VectorType:
    def __init__(
        self, is_fp: bool, element_cnt: int, element_nbits: int, is_signed: bool
    ):
        if is_fp and not is_signed:
            raise Exception("is_signed is only for integers")
        self.is_fp = is_fp
        self.element_cnt = element_cnt
        self.element_nbits = element_nbits
        self.is_signed = is_signed


def build_array(vector_type: VectorType):
    if vector_type.is_fp:
        return _sym_build_symbolic_array_fp(
            vector_type.element_nbits, vector_type.element_nbits == 64
        )
    else:
        return _sym_build_symbolic_array_int(
            vector_type.element_cnt, vector_type.element_nbits
        )


def generic_convert_element(
    elem_in: int, input_type: VectorType, output_type: VectorType
) -> int:
    if input_type.is_fp:
        if output_type.is_fp:
            return _sym_build_float_to_float(elem_in, output_type.element_nbits == 64)
        else:
            if input_type.is_signed:
                return _sym_build_float_to_signed_integer(
                    elem_in, output_type.element_nbits
                )
            else:
                return _sym_build_float_to_unsigned_integer(
                    elem_in, output_type.element_nbits
                )
    else:
        if output_type.is_fp:
            return _sym_build_int_to_float(
                elem_in, output_type.element_nbits == 64, input_type.is_signed
            )
        else:
            if output_type.is_signed:
                if output_type.element_nbits > input_type.element_nbits:
                    return _sym_build_sext(
                        elem_in, output_type.element_nbits - input_type.element_nbits
                    )
                else:
                    return _sym_build_trunc(
                        elem_in, input_type.element_nbits - output_type.element_nbits
                    )
            else:
                if output_type.element_nbits > input_type.element_nbits:
                    return _sym_build_zext(
                        elem_in, output_type.element_nbits - input_type.element_nbits
                    )
                else:
                    return _sym_build_trunc(
                        elem_in, input_type.element_nbits - output_type.element_nbits
                    )


def generic_cvt(
    vector: int,
    input_type: VectorType,
    output_type: VectorType,
) -> int:
    if input_type.element_cnt != input_type.element_cnt:
        raise Exception("cvt operates on two different vector sizes")
    output_vector = build_array(output_type)
    for i in range(input_type.element_cnt):
        elem_in = _sym_build_extract_element(vector, i)
        elem_out = generic_convert_element(elem_in, input_type, output_type)
        output_vector = _sym_build_insert_element(output_vector, elem_out, i)
    return symexpr_to_rsymexpr(output_vector)


def sym_x86_sse2_movmsk_ps(
    _concrete_return_value: Optional[int],
    args: List[int],
    _concrete_args: List[Optional[int]],
) -> int:
    vector = args[0]
    mask = generic_movmsk(vector, 4, 32, True, 32)
    return mask


def sym_x86_sse2_cvttps2dq(
    _concrete_return_value: Optional[int],
    args: List[int],
    _concrete_args: List[Optional[int]],
) -> int:
    vector = args[0]
    input_type = VectorType(True, 4, 32, True)
    output_type = VectorType(False, 4, 32, True)
    return generic_cvt(vector, input_type, output_type)


DISPATCH_FUNCTION: Dict[str, Callable] = {
    "mkstemp64": sym_open_symbolized,  # mkstemp64 uses the same handler as open
    "__write": sym_write_symbolized,
    "write": sym_write_symbolized,
    "read": sym_read_symbolized,
    "__read": sym_read_symbolized,
    "open": sym_open_symbolized,
    "lseek": sym_lseek_symbolized,
    "fcntl": sym_fcntl_symbolized,
    "__fcntl": sym_fcntl_symbolized,
    "dup2": sym_dup2_symbolized,
    "__dup2": sym_dup2_symbolized,
    "pipe": sym_pipe_symbolized,
    "__pipe": sym_pipe_symbolized,
    "socketpair": sym_socketpair_symbolized,
    "recv": sym_read_symbolized,
    "recvfrom": sym_read_symbolized,
    "strcasecmp": sym_strcmp_symbolized,
    "strcmp": sym_strcmp_symbolized,
    "__strcmp_avx": sym_strcmp_symbolized,
    "__strcasecmp_avx": sym_strcmp_symbolized,
    "strdup": sym_strdup_symbolized,
    "__strlen_avx": sym_strlen_symbolized,
}

DISPATCH_INTRINSIC: Dict[int, Callable] = {
    13303: sym_x86_sse2_movmsk_ps,
    13333: sym_x86_sse2_cvttps2dq,
}


def run_intrinsic(
    intrinsic_id: int,
    return_value: Optional[int],
    args: List[int],
    concrete_args: List[Optional[int]],
) -> Tuple[int, int, str]:
    try:
        if intrinsic_id not in DISPATCH_INTRINSIC:
            return (0, 1, "")
        else:
            return (
                DISPATCH_INTRINSIC[intrinsic_id](return_value, args, concrete_args),
                0,
                "",
            )
    except Exception as e:
        return (0, 2, str(e))


libdl = CDLL(ctypes_util.find_library("dl"))
_memory_map_cache = _load_memory_map()


# Define Dl_info structure
class Dl_info(Structure):
    _fields_ = [
        ("dli_fname", c_char_p),  # Pathname of shared object
        ("dli_fbase", c_void_p),  # Base address at which shared object is loaded
        ("dli_sname", c_char_p),  # Name of nearest symbol
        ("dli_saddr", c_void_p),  # Address of that symbol
    ]


# Configure dladdr function prototype
dladdr = libdl.dladdr
dladdr.argtypes = [c_void_p, POINTER(Dl_info)]
dladdr.restype = c_int


def resolve_function_addr(function_addr: int) -> Optional[str]:
    if function_addr in ADDR_TO_SYMBOLS:
        return ADDR_TO_SYMBOLS[function_addr]
    info = Dl_info()
    res = dladdr(c_void_p(function_addr), byref(info))
    if res == 0:
        return None
    return info.dli_sname.decode() if info.dli_sname else None


def run_function(
    function_addr: int,
    return_value: Optional[int],
    args: List[int],
    concrete_args: List[Optional[int]],
) -> Tuple[int, int, str]:
    try:
        function_name = resolve_function_addr(function_addr)
        print(f"resolved function 0x{function_addr:x} to {function_name}")
        if function_name is None or function_name not in DISPATCH_FUNCTION:
            return (0, 1, "")
        else:
            return (
                DISPATCH_FUNCTION[function_name](return_value, args, concrete_args),
                0,
                "",
            )
    except Exception as e:
        print(f"exception occurred while dealing with 0x{function_addr:x}") 
        return (0, 2, str(e))
