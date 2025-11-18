#### Reference ####
# https://github.com/s3team/S

#### Targets ####
# sqlite3
# postgresql
# mysql

import os
import subprocess
from pathlib import Path
import logging
import argparse


logger = logging.Logger(__file__)

TARGETS = {
    "sqlite": {"repo": "https://github.com/sqlite/sqlite.git", "install_path": ""} ,
    "postgresql": {"repo": "https://github.com/postgres/postgres.git", "install_path": "/usr/local/pgsql"},
    "mysql": {"repo": "https://github.com/mysql/mysql-server.git", "install_path": "/usr/local/mysql"},
}
USERNAME = "fuzzuser"
FUZZER_DIR = Path.home() / "sqlright"
DATA_DIR = Path.home() / "data"
SRC_DIR = Path(os.getenv("SRC_DIR", str(Path.home() / "target")))
BUILD_DIR = Path(os.getenv("BUILD_DIR", str(Path.home() / "build")))
OUTPUT_DIR = Path.home() / "output"
SCRIPT_DIR = Path(__file__).parent


def main():
    parser = argparse.ArgumentParser(description="dbms fuzzer sqlright wrapper for unknown target")

    parser.add_argument("target_name", type=str, help="name of the target, sqlite, postgresql, mysql, mariadb, etc")
    parser.add_argument("--src", type=str, default=str(SRC_DIR), help="src directory of target if exists")
    parser.add_argument("--build", type=str, default=str(BUILD_DIR), help="build directory of target if exists")
    parser.add_argument("-t", "--test", action="store_true", help="if its a test, clone, build and run")

    args = parser.parse_args()

    match args.target_name:
        case "sqlite" | "sqlite3":
            target_name = "sqlite"
        case "postgresql" | "pgsql":
            target_name = "postgresql"
        case "mysql":
            target_name = "mysql"
        case _:
            logger.error("Unsupported target")
            return
    
    src_path = Path(args.src)
    build_path = Path(args.build)
    
    # TODO: divide setup stage into building and setup
    if args.test:
        clone_src(target_name)
        build_path.mkdir()

    match target_name:
        case "sqlite":
            sqlite_setup(src_path)
            sqlite_run()
            return
        case "postgresql":
            postgresql_setup(src_path)
        case "mysql":
            mysql_setup(src_path)
        case "mariadb":
            mariadb_setup(src_path)

    db_run(target_name)

# clone src for testing
def clone_src(target_name):
    subprocess.run(["git", "clone", "--depth=1", TARGETS[target_name]["repo"], str(SRC_DIR)])

def set_afl_env(env):
    env["CC"] = "afl-clang-fast"
    env["CXX"] = "afl-clang-fast++"
    return env

def sqlite_setup(src_path: Path):
    # TODO: replace with just receiving oss-fuzz harness with afl
    env = set_afl_env(os.environ.copy())
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    #CFLAGS = "$CFLAG -DSQLITE_MAX_LENGTH=128000000 \
    #           -DSQLITE_MAX_SQL_LENGTH=128000000 \
    #           -DSQLITE_MAX_MEMORY=25000000 \
    #           -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
    #           -DSQLITE_DEBUG=1 \
    #           -DSQLITE_MAX_PAGE_COUNT=16384"
    subprocess.run([str(src_path / "configure"), "--shared=0"], cwd = str(BUILD_DIR), env = env, check = True)

    subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
    subprocess.run(["make", "sqlite3.c"], cwd = str(BUILD_DIR), check = True)
    logger.info("Built sqlite with afl++.")

def sqlite_run():
    oracle = "NOREC"
    subprocess.run(["python3", "run_parallel.py", "-o", str(OUTPUT_DIR), "--start-core", "1", "--num-concurrent", "1", "-O", oracle], cwd = str(FUZZER_DIR / "SQLite/fuzz_root"))

def postgresql_setup(src_path: Path):
    env = set_afl_env(os.environ.copy())
    subprocess.run([str(src_path / "configure")], cwd = str(BUILD_DIR), env = env, check = True)

    # TODO: workaround for install build? maybe assume it is in /usr/local/pgsql?
    subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
    subprocess.run(["make", "install"], cwd = str(BUILD_DIR), check = True)

    env = os.environ.copy()
    env["AFL_IGNORE_PROBLEMS"] = "1"
    DATA_DIR.mkdir(exist_ok=True)
    subprocess.run(["/usr/local/pgsql/bin/initdb", "-D", str(DATA_DIR)], env = env, check = True)
    subprocess.run(["/usr/local/pgsql/bin/pg_ctl", "-D", str(DATA_DIR), "start"], env = env, check = True)
    subprocess.run(["/usr/local/pgsql/bin/createdb", "x"], env = env, check = True)
    subprocess.run(["/usr/local/pgsql/bin/pg_ctl", "-D", str(DATA_DIR), "stop"], env = env, check = True)

def mysql_setup(src_path: Path):
    env = set_afl_env(os.environ.copy())
    cmd = ["cmake", str(src_path), "-DWITH_DEBUG=1", "-DCPACK_MONOLITHIC_INSTALL=1", "-DWITH_UNIT_TESTS=OFF"] # from Squirrel
    cmd += ["-Dprotobuf_BUILD_SHARED_LIBS=OFF", "-DWITH_BOOST=.", "-DWITH_SSL=system", "-DWITH_UBSAN=1"] # from oss-fuzz
    subprocess.run(cmd, cwd = str(BUILD_DIR), env = env, check = True)

    # TODO: workaround for install build? maybe assume it is in /usr/local/mysql?
    subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
    subprocess.run(["cmake", "--install", ".", "--prefix=/usr/local/mysql/"], cwd = str(BUILD_DIR), check = True)
    
    env = os.environ.copy()
    env["AFL_IGNORE_PROBLEMS"] = "1"
    subprocess.run(["/usr/local/mysql/bin/mysqld", "--initialize-insecure", f"--user={USERNAME}", f"--datadir={str(DATA_DIR)}"], env = env, check = True)
    subprocess.run(["/usr/local/mysql/bin/mysql_ssl_rsa_setup"], check = True)

def db_run(target_name):
    if target_name == "postgresql":
        target_name = "PostgreSQL"
    if target_name == "mysql":
        target_name = "MySQL"
    subprocess.run(["python3", "run_parallel.py", "-o", str(OUTPUT_DIR), "--start-core", "0", "--num-concurrent", "1", "-O", "NOREC"], cwd = str(FUZZER_DIR / target_name / "fuzz_root"), check = True)

if __name__ == "__main__":
    main()
