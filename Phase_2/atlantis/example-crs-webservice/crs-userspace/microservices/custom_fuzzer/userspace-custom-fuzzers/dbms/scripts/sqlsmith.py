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
}
# TODO: monetdb
USERNAME = "fuzzuser"
SQUIRREL_DIR = Path.home() / "sqlsmith"
DATA_DIR = Path.home() / "data"
SRC_DIR = Path(os.getenv("SRC_DIR", str(Path.home() / "target")))
BUILD_DIR = Path(os.getenv("BUILD_DIR", str(Path.home() / "build")))
OUTPUT_DIR = Path.home() / "output"
SCRIPT_DIR = Path(__file__).parent


def main():
    parser = argparse.ArgumentParser(description="dbms fuzzer sqlsmith wrapper for unknown target")

    parser.add_argument("target_name", type=str, help="name of the target, sqlite, postgresql, etc")
    parser.add_argument("--src", type=str, default=str(SRC_DIR), help="src directory of target if exists")
    parser.add_argument("-c", "--clone", action="store_true", help="clone src (for testing)")
    parser.add_argument("-b", "--build", action="store_true", help="build src")

    args = parser.parse_args()

    match args.target_name:
        case "sqlite" | "sqlite3":
            target_name = "sqlite"
        case "postgresql" | "pgsql":
            target_name = "postgresql"
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

    db_run(target_name)


def sqlite_setup(src_path: Path, build: bool):
    # TODO: replace with using the prebuilt image
    if build:
        subprocess.run([str(src_path / "configure"), "--shared=0"], cwd = str(BUILD_DIR), env = env, check = True)
        subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)
        subprocess.run(["make", "sqlite3.c"], cwd = str(BUILD_DIR), check = True)

def sqlite_run():
    env = os.environ.copy()
    

def postgresql_setup(src_path: Path, build: bool):
    env = os.environ.copy()
    if build:
        subprocess.run([str(src_path / "configure")], cwd = str(BUILD_DIR), env = env, check = True)
        subprocess.run(["make", "-j"], cwd = str(BUILD_DIR), check = True)

    subprocess.run(["make", "install"], cwd = str(BUILD_DIR), check = True)

    port_num = 5432
    db_name = "regression"
    DATA_DIR.mkdir(exist_ok=True)
    subprocess.run(["/usr/local/bin/initdb", "-D", str(DATA_DIR)])
    subprocess.run(["/usr/local/pgsql/bin/pg_ctl", "start", "-D", str(DATA_DIR), "-o", f"\"-p {str(port_num)}\""], env = env, check = True)
    subprocess.run(["/usr/local/pgsql/bin/createdb", db_name, "-p", str(port_num)])

def setup_logdb():
    pass
    # TODO: add running log.sql to setup loggin
