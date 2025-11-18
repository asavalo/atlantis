from clang.cindex import Index, CursorKind, TypeKind
from pathlib import Path
import argparse
import tempfile
import subprocess

ALLOWLIST = [
    "_sym_read_memory",
    "_sym_write_memory",
    "_sym_memcpy",
    "_sym_concat_helper",
    "_sym_extract_helper",
    "_sym_push_path_constraint",
    "_sym_bits_helper"
]


def map_type_to_ctypes(clang_type):
    kind = clang_type.kind
    if kind == TypeKind.VOID:
        return "None"
    if kind == TypeKind.BOOL:
        return "ctypes.c_bool"
    if kind == TypeKind.INT:
        return "ctypes.c_int"
    if kind == TypeKind.UINT:
        return "ctypes.c_uint"
    if kind == TypeKind.ULONG:
        return "ctypes.c_ulong"
    if kind == TypeKind.ULONGLONG:
        return "ctypes.c_ulonglong"
    if kind == TypeKind.UCHAR:
        return "ctypes.c_ubyte"
    if kind == TypeKind.FLOAT:
        return "ctypes.c_float"
    if kind == TypeKind.DOUBLE:
        return "ctypes.c_double"
    if kind == TypeKind.POINTER:
        pointee = clang_type.get_pointee()
        if pointee.spelling in ("char", "const char"):
            return "ctypes.c_char_p"
        return "ctypes.c_void_p"
    if clang_type.spelling == "SymExpr":
        return "SymExpr"
    return "ctypes.c_void_p"


def extract_functions(runtime_dir: Path):
    runtime_cpp = runtime_dir / "rust_backend/Runtime.cpp"
    index = Index.create()
    if not runtime_cpp.exists():
        raise FileNotFoundError(f"Runtime.cpp file not found: {runtime_cpp}")
    with tempfile.NamedTemporaryFile(suffix=".cpp", delete=False) as temp_file:
        clang_args = [
            "clang++",
            "-o",
            temp_file.name,
            "-E",
            "-P",
            "-x",
            "c++",
            "-I",
            str(runtime_dir),
            "-I",
            str(runtime_cpp.parent),
            "-std=c++17",
            runtime_cpp,
        ]
        subprocess.run(clang_args, check=True)
        print(f"✅ Preprocessed {runtime_cpp} to {temp_file.name}")
        tu = index.parse(temp_file.name)

    funcs = []

    def add_funcs(cursor):
        nonlocal funcs
        for cursor in cursor.get_children():
            if cursor.kind == CursorKind.LINKAGE_SPEC:
                add_funcs(cursor)
            if cursor.kind == CursorKind.FUNCTION_DECL:
                name = cursor.spelling
                if name.startswith("_sym_build") or name in ALLOWLIST:
                    ret = map_type_to_ctypes(cursor.result_type)
                    args = [map_type_to_ctypes(a.type) for a in cursor.get_arguments()]
                    ret_orig = cursor.result_type.spelling
                    args_orig = ", ".join([a.type.spelling for a in cursor.get_arguments()])
                    funcs.append((f"{ret_orig} {name}({args_orig})", name, ret, args))

    add_funcs(tu.cursor)
    return funcs


def generate_ctypes_wrapper(funcs):
    lines = [
        "import ctypes",
        "",
        "SymExpr = ctypes.c_void_p",
        "",
        "lib = ctypes.CDLL(None)",
        "",
    ]
    for func_decl, name, restype, argtypes in funcs:
        lines.append(f"# {func_decl}")
        lines.append(f"{name} = lib.{name}")
        lines.append(f"{name}.argtypes = [{', '.join(argtypes)}]")
        lines.append(f"{name}.restype = {restype}")
        lines.append("")
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate ctypes wrapper for C functions."
    )
    parser.add_argument(
        "symcc_src_path", type=Path, help="Path to the SymCC runtime directory."
    )
    parser.add_argument("output_py", type=Path, help="Output Python file.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    funcs = extract_functions(args.symcc_src_path)
    wrapper = generate_ctypes_wrapper(funcs)
    with open(args.output_py, "w") as f:
        f.write(wrapper)
    print(f"✅ Generated {args.output_py}")
