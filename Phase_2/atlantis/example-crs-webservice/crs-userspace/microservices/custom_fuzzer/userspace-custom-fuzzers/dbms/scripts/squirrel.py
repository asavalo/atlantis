#### Reference ####
# https://github.com/s3team/Squirrel

#### Targets ####
# sqlite3
# postgresql
# mysql
# mariadb

#!/usr/bin/env python3

import os
import subprocess
from pathlib import Path
import logging
import argparse
import shutil


TARGETS = {
    "sqlite": {"repo": "https://github.com/sqlite/sqlite.git", "install_path": ""} ,
    "postgresql": {"repo": "https://github.com/postgres/postgres.git", "install_path": "/usr/local/pgsql"},
    "mysql": {"repo": "https://github.com/mysql/mysql-server.git", "install_path": "/usr/local/mysql"},
    "mariadb": {"repo": "https://github.com/MariaDB/server.git", "install_path": "/usr/local/mysql"},
}
USERNAME = "fuzzuser"
SQUIRREL_DIR = Path.home() / "Squirrel"
SQUIRREL_DATA_DIR = SQUIRREL_DIR / "data"
DATA_DIR = Path.home() / "data"
SRC_DIR = Path(os.getenv("SRC_DIR", str(Path.home() / "target")))
BUILD_DIR = Path(os.getenv("BUILD_DIR", str(Path.home() / "build")))
OUTPUT_DIR = Path.home() / "output"
SCRIPT_DIR = Path(__file__).parent


def main():
    parser = argparse.ArgumentParser(description="dbms fuzzer Squirrel wrapper for unknown target")

    parser.add_argument("target_name", type=str, help="name of the target, sqlite, postgresql, mysql, mariadb, etc")
    parser.add_argument("--src", type=str, default=str(SRC_DIR), help="src directory of target if exists")
    parser.add_argument("-c", "--clone", action="store_true", help="clone src (for testing)")
    parser.add_argument("-b", "--build", action="store_true", help="build src (for testing, TODO: use prebuilt)")

    args = parser.parse_args()

    match args.target_name:
        case "sqlite" | "sqlite3":
            target_name = "sqlite"
        case "postgresql" | "pgsql":
            target_name = "postgresql"
        case "mysql":
            target_name = "mysql"
        case "mariadb":
            target_name = "mariadb"
        case _:
            logging.error("Unsupported target")
            return
    
    src_path = Path(args.src)
    
    if args.clone:
        clone_src(target_name, src_path)

    if args.build:
        BUILD_DIR.mkdir(exist_ok = True)

    match target_name:
        case "sqlite":
            sqlite_setup(src_path, args.build)
            sqlite_run()
            return
        case "postgresql":
            postgresql_setup(src_path, args.build)
        case "mysql":
            mysql_setup(src_path, args.build)
        case "mariadb":
            mariadb_setup(src_path, args.build)

    db_run(target_name)

# clone src for testing
def clone_src(target_name, src_path):
    if src_path.exists():
        shutil.rmtree(src_path)
    subprocess.run(["git", "clone", "--depth=1", TARGETS[target_name]["repo"], str(src_path)])

def set_fuzzing_env(target_name, env):
    env["SQUIRREL_CONFIG"] = str(SQUIRREL_DATA_DIR / f"config_{target_name}.yml")
    env["AFL_CUSTOM_MUTATOR_ONLY"] = "1"
    env["AFL_DISABLE_TRIM"] = "1"
    env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(SQUIRREL_DIR / f"build/lib{target_name}_mutator.so")
    return env

def set_afl_env(env, clang = True):
    if clang:
        env["CC"] = "afl-clang-fast"
        env["CXX"] = "afl-clang-fast++"
    else:
        env["CC"] = "afl-gcc-fast"
        env["CXX"] = "afl-g++-fast"
    return env

def sqlite_setup(src_path: Path, build: bool):
    # TODO: replace with just receiving afl harness
    env = set_afl_env(os.environ.copy())
    # CFLAGS = "$CFLAG -DSQLITE_MAX_LENGTH=128000000 \
    #           -DSQLITE_MAX_SQL_LENGTH=128000000 \
    #           -DSQLITE_MAX_MEMORY=25000000 \
    #           -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
    #           -DSQLITE_DEBUG=1 \
    #           -DSQLITE_MAX_PAGE_COUNT=16384""
    if build:
        subprocess.run([str(src_path / "configure"), "--shared=0"], cwd = str(BUILD_DIR), env = env, check = True)
        subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
        subprocess.run(["make", "sqlite3.c"], cwd = str(BUILD_DIR), check = True)
        logging.info("Built sqlite with afl++.")
        subprocess.run(["afl-clang-fast", env.get("CFLAGS", ""), "-I.", "-c", str(src_path / "test/ossfuzz.c"), "-o", str(src_path / "test/ossfuzz.o")], cwd = str(BUILD_DIR), env = env, check = True)
        subprocess.run(["afl-clang-fast", env.get("CFLAGS", ""), "-I.", "-c", str(src_path / "test/ossshell.c"), "-o", str(src_path / "test/ossshell.o")], cwd = str(BUILD_DIR), env = env, check = True)
        subprocess.run(["afl-clang-fast++", env.get("CXXFLAGS", ""), str(src_path / "test/ossfuzz.o"), str(src_path / "test/ossshell.o"), "-o", str(BUILD_DIR / "ossfuzz"), "./sqlite3.o", "-ldl", "-pthread"], cwd = str(BUILD_DIR), env = env, check = True)

def sqlite_run():
    harness = BUILD_DIR / "ossfuzz"
    env = set_fuzzing_env("sqlite", os.environ.copy())
    subprocess.run(["afl-fuzz", "-i", "input", "-o", str(OUTPUT_DIR), "--", str(harness), "@@"], cwd = str(SQUIRREL_DATA_DIR / "fuzz_root"), env = env, check = True)

def postgresql_setup(src_path: Path, build: bool):
    if build:
        env = set_afl_env(os.environ.copy())
        subprocess.run([str(src_path / "configure")], cwd = str(BUILD_DIR), env = env, check = True)
        subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)

    subprocess.run(["make", "install"], cwd = str(BUILD_DIR), check = True)

    env = os.environ.copy()
    env["AFL_IGNORE_PROBLEMS"] = "1"
    DATA_DIR.mkdir(exist_ok=True)
    subprocess.run(["/usr/local/pgsql/bin/initdb", "-D", str(DATA_DIR)], env = env, check = True)

def mysql_setup(src_path: Path, build: bool):
    if build:
        env = set_afl_env(os.environ.copy(), False)
        cmd = ["cmake", str(src_path), "-DWITH_DEBUG=1", "-DCPACK_MONOLITHIC_INSTALL=1", "-DWITH_UNIT_TESTS=OFF", "-DDOWNLOAD_BOOST=1", "-DWITH_BOOST=../boost"] # from Squirrel
        #cmd += ["-Dprotobuf_BUILD_SHARED_LIBS=OFF", "-DWITH_BOOST=.", "-DWITH_SSL=system", "-DWITH_UBSAN=1"] # from oss-fuzz
        subprocess.run(cmd, cwd = str(BUILD_DIR), env = env, check = True)

        # TODO: workaround for install build
        subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
    subprocess.run(["cmake", "--install", ".", "--prefix=/usr/local/mysql/"], cwd = str(BUILD_DIR), check = True)
    
    env = os.environ.copy()
    env["AFL_IGNORE_PROBLEMS"] = "1"
    subprocess.run(["/usr/local/mysql/bin/mysqld", "--initialize-insecure", f"--user={USERNAME}", f"--datadir={str(DATA_DIR)}"], env = env, check = True)
    subprocess.run(["/usr/local/mysql/bin/mysql_ssl_rsa_setup"], check = True)

def mariadb_setup(src_path: Path, build: bool):
    if build:
        env = set_afl_env(os.environ.copy())
        subprocess.run(["cmake", str(src_path)], cwd = str(BUILD_DIR), env = env, check = True)

        # TODO: workaround for install build
        subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
    subprocess.run(["cmake", "--install", ".", "--prefix=/usr/local/mysql/"], cwd = str(BUILD_DIR), check = True)

def db_run(target_name):
    if target_name == "mariadb":
        target_name = "mysql"
    env = set_fuzzing_env(target_name, os.environ.copy())
    subprocess.run(["afl-fuzz", "-i", f"{target_name}_input", "-o", str(OUTPUT_DIR), "-t", "60000", "--", str(SQUIRREL_DIR / "build/db_driver")], cwd = str(SQUIRREL_DATA_DIR / "fuzz_root"), env = env, check = True)

if __name__ == "__main__":
    main()
