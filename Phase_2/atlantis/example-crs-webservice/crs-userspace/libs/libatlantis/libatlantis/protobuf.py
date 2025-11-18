from google.protobuf.message import Message

from .bootstrap_pb2 import *
from .c_llm_pb2 import *
from .coverage_service_pb2 import *
from .custom_fuzzer_pb2 import *
from .deep_browser_pb2 import *
from .fuzzer_corpus_pb2 import *
from .fuzzer_manager_pb2 import *
from .harness_builder_pb2 import *
from .llm_mutator_pb2 import *
from .osv_analyzer_pb2 import *
from .harness_reachability_pb2 import *
from .deep_gen_pb2 import *
from .directed_fuzzer_pb2 import *


def protobuf_repr(msg: Message) -> str:
    """
    protobuf's str()/repr() formatting is terrible, so let's try to
    improve it a bit
    also show default values
    """
    lines = [f'libatlantis.protobuf.{type(msg).__name__}(']
    all_fields = msg.DESCRIPTOR.fields_by_name
    for field_name, field_desc in all_fields.items():
        field_value = getattr(msg, field_name)
        lines.append(f'    {field_name}: {field_value},')
    lines.append(')')
    return '\n'.join(lines)


def string_to_mode(mode_str: str) -> Mode:
    if mode_str == "libafl":
        return LIBAFL
    elif mode_str == "custom":
        return CUSTOM
    elif mode_str == "symcc":
        return SYMCC
    elif mode_str == "symcc_clang_cov":
        return SYMCC_CLANG_COV
    elif mode_str == "single_input":
        return SINGLE_INPUT
    elif mode_str == "single_input_sbcc":
        return SINGLE_INPUT_SBCC
    elif mode_str == "libfuzzer":
        return LIBFUZZER
    elif mode_str == "directed":
        return DIRECTED
    elif mode_str == "libfuzzer_sbcc":
        return LIBFUZZER_SBCC
    elif mode_str == "afl":
        return AFL
    elif mode_str == "honggfuzz":
        return HONGGFUZZ
    elif mode_str == "config_gen":
        return CONFIG_GEN
    elif mode_str == "ubsan":
        return UBSAN
    elif mode_str == "msan":
        return MSAN
    elif mode_str == "sans":
        return SANS
    elif mode_str == "optimized":
        return OPTIMIZED
    else:
        raise ValueError(f"Unknown mode: {mode_str}")


def mode_to_string(mode: Mode) -> str:
    if mode == LIBAFL:
        return "libafl"
    elif mode == CUSTOM:
        return "custom"
    elif mode == SYMCC:
        return "symcc"
    elif mode == SYMCC_CLANG_COV:
        return "symcc_clang_cov"
    elif mode == SINGLE_INPUT:
        return "single_input"
    elif mode == SINGLE_INPUT_SBCC:
        return "single_input_sbcc"
    elif mode == LIBFUZZER:
        return "libfuzzer"
    elif mode == DIRECTED:
        return "directed"
    elif mode == LIBFUZZER_SBCC:
        return "libfuzzer_sbcc"
    elif mode == AFL:
        return "afl"
    elif mode == HONGGFUZZ:
        return "honggfuzz"
    elif mode == CONFIG_GEN:
        return "config_gen"
    elif mode == UBSAN:
        return "ubsan"
    elif mode == MSAN:
        return "msan"
    elif mode == SANS:
        return "sans"
    elif mode == OPTIMIZED:
        return "optimized"
    else:
        raise ValueError(f"Unknown mode: {mode}")
