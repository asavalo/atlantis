import os
import yaml
import time
import subprocess
from pathlib import Path
import signal

from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()
signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def run(cmd: list, cwd=None):
    cmd = list(map(str, cmd))
    logger.info(" ".join(cmd))
    if cwd == None:
        cwd = os.getcwd()
    try:
        return subprocess.run(
            cmd,
            check=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
        )
    except:
        pass


def rsync(src: Path, dst: Path):
    if src.is_dir():
        src = f"{src}/."
    cmd = ["rsync", "-a", src, dst]
    return run(cmd)


def untar(tar: Path, dst: Path):
    if not dst.exists():
        os.makedirs(dst, exist_ok=True)
    cmd = ["tar", "--use-compress-program=pigz"]
    cmd += ["-xf", tar]
    cmd += ["-C", dst]
    run(cmd)


def patch(cwd, diff):
    run(["git", "init"], cwd=cwd)
    run(["git", "apply", "--reject", diff], cwd=cwd)
    run(["rm", "-rf", ".git"], cwd=cwd)


class CP:
    def __init__(self, proj_name: str, workdir: Path, apply_diff=True):
        self.proj_name = proj_name
        self.workdir = workdir
        self.apply_diff = apply_diff
        os.makedirs(self.workdir, exist_ok=True)

    def info(self, msg):
        logger.info(f"[CP] {msg}")

    def prepare_from_tarball(self, tarball_dir: Path, focus: str):
        self.__untar_ossfuzz(tarball_dir)
        self.__untar_repo(tarball_dir, focus)

    def __untar_ossfuzz(self, tarball_dir: Path):
        ossfuzz_tar = tarball_dir / "oss-fuzz.tar.gz"
        ossfuzz_untar = self.workdir / "oss-fuzz-untar"
        os.makedirs(ossfuzz_untar, exist_ok=True)
        untar(ossfuzz_tar, ossfuzz_untar)
        ossfuzz = list(ossfuzz_untar.iterdir())[0]
        run(["mv", ossfuzz, self.workdir / "oss-fuzz"])

    def __untar_repo(self, tarball_dir: Path, focus: str):
        repo_tar = tarball_dir / "repo.tar.gz"
        repo = self.workdir / "repo"
        untar(repo_tar, repo)
        src_dir = repo / focus
        diff_tar = tarball_dir / "diff.tar.gz"
        diff_path = None
        if diff_tar.exists():
            untar(diff_tar, self.workdir)
            diff_path = self.workdir / "diff/ref.diff"
            if self.apply_diff:
                patch(src_dir, diff_path)

    def __get_conf(self):
        proj_dir = self.workdir / "oss-fuzz/projects" / self.proj_name
        conf = proj_dir / "project.yaml"
        if conf.exists():
            with open(conf) as f:
                return yaml.safe_load(f)
        return None

    def get_sanitizers(self):
        # Only support address sanitizer
        return ["address"]
        '''
        conf = self.__get_conf()
        if conf != None and "sanitizers" in conf:
            return conf["sanitizers"]
        return ["address"]
        '''

    def get_language(self):
        conf = self.__get_conf()
        if conf != None and "language" in conf:
            return conf["language"]
        return "c++"

    def prepare_from_base(self, base_dir: Path):
        for name in ["repo", "oss-fuzz"]:
            src = base_dir / name
            dst = self.workdir / name
            if dst.exists():
                continue
            rsync(src, dst)

    def __get_dirs(self):
        repo = self.workdir / "repo"
        ossfuzz = self.workdir / "oss-fuzz"
        src_dir = list(repo.iterdir())[0]
        return src_dir, ossfuzz

    def build(self, sanitizer: str):
        src_dir, ossfuzz = self.__get_dirs()
        helper = ossfuzz / "infra/helper.py"
        cmd = ["python3", helper, "build_fuzzers", self.proj_name, src_dir]
        cmd += ["--sanitizer", sanitizer]
        for _ in range(10):
            ret = run(cmd)
            if ret == None:
                continue
            if ret.returncode == 0:
                break
            logger.info("Retrying build...")
            time.sleep(5)
        self.__write_done()
        proj_dir = ossfuzz / "projects" / self.proj_name
        build_dir = ossfuzz / "build/out" / self.proj_name
        return src_dir, proj_dir, build_dir

    def __write_done(self):
        (self.workdir / "DONE").write_text("DONE")

    def __wait_done(self):
        self.info("Wait build process is done")
        done = self.workdir / "DONE"
        while not done.exists():
            time.sleep(5)

    def reproduce(self, harness_name: str, blob_path: Path) -> (int, bytes):
        # Return return code, crash_log
        self.__wait_done()
        self.info(f"Reproduce {blob_path}")
        src_dir, ossfuzz = self.__get_dirs()
        helper = ossfuzz / "infra/helper.py"
        log_path = Path(str(blob_path) + ".log")
        cmd = [
            "python3",
            helper,
            "reproduce",
            "--propagate_exit_codes",
            "--err_result",
            "201",
            "--timeout",
            "300",  # 5min
        ]
        cmd += [self.proj_name, harness_name, blob_path]
        ret = run(cmd)
        return ret.returncode, ret.stdout

    def pull_runner(self):
        tmp = Path("/tmp/dummy")
        tmp.write_text("\n")
        self.reproduce("test", tmp)
