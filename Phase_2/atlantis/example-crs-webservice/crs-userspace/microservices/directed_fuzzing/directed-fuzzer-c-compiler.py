#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path
import shlex
import shutil
import json

OUTPUT_DIR = Path("/out/directed-fuzzing/")

def is_linking(args: list[str]) -> bool:
    # Linking is usually indicated by absence of -c, -S, or -E
    return not any(opt in args for opt in ['-c', '-S', '-E'])

def determine_compiler_name(argv0: str, cc: str, cxx: str) -> str:
    base = Path(argv0).name
    return cxx if '++' in base else cc

def get_output_binary(args):
    if '-o' in args:
        idx = args.index('-o')
        if idx + 1 < len(args):
            return args[idx + 1]
    return None

def get_all_harness_binaries():
    harness_env = os.environ.get('HARNESS_BINARIES', '')
    harness_binaries = [Path(bin).name for bin in shlex.split(harness_env)]
    if not harness_binaries:
        print("HARNESS_BINARIES is not set or empty", file=sys.stderr)
        exit(1)

    return harness_binaries

def built_harness(args):
    if is_linking(args):
        output_binary = get_output_binary(args)
        if output_binary:
            output_binary_path = Path(output_binary)
            output_binary_base = output_binary_path.name
            if any(output_binary_base == Path(bin).name for bin in get_all_harness_binaries()):
                return output_binary_path

    return None


def get_default_compiler_lib_paths(compiler):
    try:
        output = subprocess.check_output([compiler, "-print-search-dirs"], text=True)
        for line in output.splitlines():
            if line.startswith("libraries: ="):
                paths = line.split("=", 1)[1].split(":")
                return [Path(p) for p in paths if p]

    except Exception as e:
        print(f"Warning: Failed to get search dirs from {compiler}: {e}")
    return []

def get_harness_sanitizer():
    return os.environ.get("DF_HARNESS_SAN", "")

def collect_harness_build_config(harness_binary, arg0, args):
    is_cpp = "++" in arg0
    compiler_type = "cpp" if is_cpp else "c"

    lib_dest_dir = OUTPUT_DIR/ f"{harness_binary.name}-shared-libs"
    lib_dest_dir.mkdir(exist_ok=True)

    link_flags = []
    unresolved_libs = []
    lib_paths = get_default_compiler_lib_paths(arg0)

    # Add LIBRARY_PATH from env
    env_libs = os.environ.get("LIBRARY_PATH", "")
    if env_libs:
        lib_paths.extend([Path(p) for p in env_libs.split(os.pathsep) if p])

    i = 0
    while i < len(args):
        arg = args[i]

        # this adds to the search dirs
        if arg.startswith("-L"):
            path = arg[2:] if len(arg) > 2 else args[i + 1]
            lib_path = Path(path)
            lib_paths.append(lib_path)
            if len(arg) == 2:
                i += 1  # skip next arg if it was the path

        elif arg.startswith("-std"):
            link_flags.append(arg)

        # keep linker flags
        elif arg.startswith("-Wl"):
            link_flags.append(arg)

        elif arg.startswith("-l:"):
            # full library file like -l:libXYZ.a
            lib_file = arg[3:]
            resolved = False
            for lib_dir in lib_paths:
                full_path = lib_dir / lib_file
                if full_path.is_file():
                    dest = lib_dest_dir / full_path.name
                    shutil.copy2(full_path, dest)
                    resolved = True
                    break
            if not resolved:
                unresolved_libs.append(arg)
            link_flags.append(arg)

        elif arg.startswith("-l"):
            lib_short = arg[2:]
            libname_base = f"lib{lib_short}"
            resolved = False

            for suffix in [".so", ".a"]:  # prefer .so
                for lib_dir in lib_paths:
                    candidate = lib_dir / (libname_base + suffix)
                    if candidate.is_file():
                        dest = lib_dest_dir / candidate.name
                        shutil.copy2(candidate, dest)
                        resolved = True
                        break
                if resolved:
                    break

            if not resolved:
                unresolved_libs.append(arg)
            link_flags.append(arg)

        elif arg.endswith((".a", ".so")):
            path = Path(arg)
            if path.is_file():

                shutil.copy2(path, lib_dest_dir / path.name)
                linker_flag = f"{{shared-lib-dir}}/{path.name}"
                link_flags.append(linker_flag)
            else:
                unresolved_libs.append(arg)

        i += 1

    return {
        "cmd": " ".join([arg0] + args),
        "compiler": compiler_type,
        "link_flags": " ".join(link_flags),
        "sanitizer": get_harness_sanitizer(),
        "unresolved_libs": unresolved_libs,
    }

def filter_sanitizer_args(args):
    filtered = []

    sanitizer_flags = {
        '-fsanitize=fuzzer',
        '-fsanitize=fuzzer-no-link',
        '-fsanitize=address',
        '-fsanitize=undefined',
        '-fsanitize=memory',
        '-fsanitize=thread',
        '-fsanitize=safe-stack',
        '-fsanitize=leak',
    }

    for arg in args:
        if any(arg.startswith(flag) for flag in sanitizer_flags):
            continue

        filtered.append(arg)

    return filtered

def main():
    argv0 = sys.argv[0]
    args = sys.argv[1:]

    cc = "wllvm"
    cxx = "wllvm++"
    compiler = determine_compiler_name(argv0, cc, cxx)

    args = filter_sanitizer_args(args)

    args.append("-fno-inline")
    args.append("-fno-inline-functions")

    cmd = [compiler] + args

    # do the actual building..
    result = subprocess.run(cmd, check=False)

    # now analyze and export the build config
    harness_binary = built_harness(args)
    if harness_binary:
        harness_build_config = collect_harness_build_config(harness_binary, compiler, args)
        with open(OUTPUT_DIR/ f"{harness_binary.name}-build-config.json", "w") as build_config_file:
            json.dump(harness_build_config, build_config_file)

    sys.exit(result.returncode)

if __name__ == '__main__':
    main()
