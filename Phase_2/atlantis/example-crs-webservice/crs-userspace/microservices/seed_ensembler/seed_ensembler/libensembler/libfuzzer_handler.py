from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
from typing import Iterator

from .libfuzzer_result import LibfuzzerSingleExecResult, LibfuzzerMergeResult
from .logger_wrapper import LoggerWrapper
from .util import fs_copy, compress_str


logger = LoggerWrapper.getLogger(__name__)


@dataclass
class LibfuzzerMounts:
    out_dir_host: Path
    out_dir_guest: Path
    work_dir_host: Path
    work_dir_guest: Path
    artifact_prefix_host: Path
    artifact_prefix_guest: Path
    seed_dirs_host: list[Path]
    seed_dirs_guest: list[Path]
    other_mount_dirs_host: list[Path]
    other_mount_dirs_guest: list[Path]

    def iter_all_pairs(self) -> Iterator[tuple[Path, Path]]:
        yield self.out_dir_host, self.out_dir_guest
        yield self.work_dir_host, self.work_dir_guest
        yield self.artifact_prefix_host, self.artifact_prefix_guest

        for host, guest in zip(self.seed_dirs_host, self.seed_dirs_guest):
            yield host, guest
        for host, guest in zip(self.other_mount_dirs_host, self.other_mount_dirs_guest):
            yield host, guest

    def host_to_guest(self, path: Path) -> Path:
        for host, guest in self.iter_all_pairs():
            if path.is_relative_to(host):
                return guest / path.relative_to(host)
        return path

    def guest_to_host(self, path: Path) -> Path:
        for host, guest in self.iter_all_pairs():
            if path.is_relative_to(guest):
                return host / path.relative_to(guest)
        return path


@dataclass
class Timeouts:
    overall: float | None
    per_seed: float | None


class AbstractLibfuzzerInvocation:
    environment: AbstractLibfuzzerEnvironment
    timeouts: Timeouts
    mounts: LibfuzzerMounts
    harness_filename: str

    def __init__(self,
        environment: AbstractLibfuzzerEnvironment,
        timeouts: Timeouts,
        mounts: LibfuzzerMounts,
        harness_filename: str,
    ):
        super().__init__()

        self.environment = environment
        self.timeouts = timeouts
        self.mounts = mounts
        self.harness_filename = harness_filename

    def create_libfuzzer_merge_cmd(self) -> list[str]:
        cmd = [
            '-merge=1',
            f'-artifact_prefix={self.mounts.artifact_prefix_guest}/',
        ]

        if self.timeouts.per_seed is not None:
            cmd.append(f'-timeout={round(self.timeouts.per_seed)}')

        for d in self.mounts.seed_dirs_guest:
            cmd.append(str(d))

        return cmd

    def create_libfuzzer_single_exec_cmd(self, seed: Path) -> list[str]:
        cmd = [f'-artifact_prefix={self.mounts.artifact_prefix_guest}/']

        if self.timeouts.per_seed is not None:
            cmd.append(f'-timeout={round(self.timeouts.per_seed)}')

        cmd.append(str(seed))

        return cmd

    def set_up_and_create_command_prefix(self) -> list[str]:
        raise NotImplementedError

    def run_merge(self) -> LibfuzzerMergeResult:
        if len(self.mounts.seed_dirs_guest) < 2:
            # Not sure why libfuzzer can't just deduplicate within a
            # single directory, but it errors out ("INFO: Merge requires
            # two or more corpus seed_dirs")
            raise RuntimeError('Need at least two directories for libfuzzer merge')

        cmd = self.set_up_and_create_command_prefix()

        cmd += self.create_libfuzzer_merge_cmd()

        if self.environment.verbose:
            logger.info(f'docker cmd: {shlex.join(cmd)}')
        else:
            logger.info(f'docker cmd: {compress_str(shlex.join(cmd))}')

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd,
                timeout=self.timeouts.overall,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            total_time = time.time() - start_time

            if self.environment.verbose:
                logger.info(f'libfuzzer output: {proc.stderr!r}')

            result = LibfuzzerMergeResult.from_stderr(
                proc.stderr,
                return_code=proc.returncode,
                execution_time=total_time,
            )

        except subprocess.TimeoutExpired as e:
            total_time = time.time() - start_time

            if self.environment.verbose:
                logger.info(f'libfuzzer output (timeout): {e.stderr!r}')

            result = LibfuzzerMergeResult.from_stderr(
                e.stderr or b'',
                execution_time=total_time,
                was_aborted=True,
            )

        # To reduce the amount of traffic put through the queue, do some
        # quick initial intra-batch deduplication
        result.deduplicate()

        # Map the crash seed paths from guest to host
        for failure in result.failures:
            if failure.input_path is not None:
                failure.input_path = self.mounts.guest_to_host(failure.input_path)
            if failure.output_path is not None:
                failure.output_path = self.mounts.guest_to_host(failure.output_path)

        self.tear_down()

        return result

    def run_single_exec(self, seed: Path) -> LibfuzzerSingleExecResult:
        cmd = self.set_up_and_create_command_prefix()

        cmd += self.create_libfuzzer_single_exec_cmd(self.mounts.host_to_guest(seed))

        logger.info(shlex.join(cmd))

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd,
                timeout=self.timeouts.overall,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            total_time = time.time() - start_time

            if self.environment.verbose:
                logger.info(f'libfuzzer output: {proc.stderr!r}')

            result = LibfuzzerSingleExecResult.from_path_and_stderr(
                seed,
                proc.stderr,
                return_code=proc.returncode,
                execution_time=total_time,
            )

        except subprocess.TimeoutExpired as e:
            total_time = time.time() - start_time

            if self.environment.verbose:
                logger.info(f'libfuzzer output (timeout): {e.stderr!r}')

            result = LibfuzzerSingleExecResult.from_path_and_stderr(
                seed,
                e.stderr or b'',
                execution_time=total_time,
                was_aborted=True,
            )

        # Map the crash seed paths from guest to host
        if result.failure is not None:
            if result.failure.input_path is not None:
                result.failure.input_path = self.mounts.guest_to_host(result.failure.input_path)
            if result.failure.output_path is not None:
                result.failure.output_path = self.mounts.guest_to_host(result.failure.output_path)

        self.tear_down()

        return result

    def tear_down(self) -> None:
        pass


class AbstractLibfuzzerEnvironment:
    guest_root_dir: Path
    guest_artifact_prefix_dir: Path
    verbose: bool
    INVOCATION_CLS: type

    def __init__(self,
        guest_root_dir: Path,
        guest_artifact_prefix_dir: Path,
        *,
        verbose: bool = False,
    ):
        super().__init__()

        self.guest_root_dir = guest_root_dir
        self.guest_artifact_prefix_dir = guest_artifact_prefix_dir
        self.verbose = verbose

    def set_up(self) -> None:
        self.guest_root_dir.mkdir(exist_ok=True)

    def prepare_invocation(self,
        harness_path_in_out_dir: Path,
        seed_dirs: list[Path],
        other_mount_dirs: list[Path],
        *,
        per_seed_timeout: float | None = None,
        overall_timeout: float | None = None,
    ) -> AbstractLibfuzzerInvocation:

        # Pick all the host and guest paths to be mounted

        # Note: I don't believe we need to mount the /artifacts
        # directory, since we're using completely vanilla libfuzzer
        # for this, and all shared libraries it needs should already
        # be available in the runner image.

        # Note 2: we *do* need to make a temporary
        # current-working-directory that the harness can play with
        # (e.g., nginx creates a bunch of folders when you run it)

        mounts = LibfuzzerMounts(
            self.guest_root_dir / 'out',
            Path('/out'),
            self.guest_root_dir / 'work',
            Path('/work'),
            self.guest_artifact_prefix_dir,
            Path('/artifact_prefix'),
            seed_dirs,
            [Path(f'/seeds_{i+1:03d}') for i in range(len(seed_dirs))],
            other_mount_dirs,
            [Path(f'/other_{i+1:03d}') for i in range(len(other_mount_dirs))],
        )

        # Prepare /out dir
        if mounts.out_dir_host.is_dir():
            shutil.rmtree(mounts.out_dir_host)
        fs_copy(harness_path_in_out_dir.parent, mounts.out_dir_host)

        # Prepare /work dir
        if mounts.work_dir_host.is_dir():
            shutil.rmtree(mounts.work_dir_host)
        mounts.work_dir_host.mkdir()

        timeouts = Timeouts(overall_timeout, per_seed_timeout)
        return self.INVOCATION_CLS(self, timeouts, mounts, harness_path_in_out_dir.name)


class DockerLibfuzzerInvocation(AbstractLibfuzzerInvocation):
    def set_up_and_create_command_prefix(self) -> list[str]:
        cmd = [
            'docker',
            'run',
            '--rm',
        ]

        for dir_host, dir_guest in self.mounts.iter_all_pairs():
            cmd += ['-v', f'{dir_host}:{dir_guest}']

        cmd += [
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--shm-size=2g',
            '--privileged',
            '--workdir', str(self.mounts.out_dir_guest),  # this NEEDS to be "/out"
            self.environment.docker_image,
            str(self.mounts.out_dir_guest / self.harness_filename),
        ]

        return cmd


class DockerLibfuzzerEnvironment(AbstractLibfuzzerEnvironment):
    INVOCATION_CLS = DockerLibfuzzerInvocation
    docker_image: str

    def __init__(self,
        guest_root_dir: Path,
        guest_artifact_prefix_dir: Path,
        docker_image: str,
        *,
        verbose: bool = False,
    ):
        super().__init__(
            guest_root_dir,
            guest_artifact_prefix_dir,
            verbose=verbose,
        )

        self.docker_image = docker_image


class ChrootLibfuzzerInvocation(AbstractLibfuzzerInvocation):
    def sudoify(self, cmd: list[str]) -> list[str]:
        return self.environment.sudoify(cmd)

    def set_up_and_create_command_prefix(self) -> list[str]:
        self.to_unmount = []
        for host, guest in self.mounts.iter_all_pairs():
            if guest == Path('/out') or guest == Path('/work'):
                continue

            new_path_on_host = self.environment.guest_root_dir / guest.relative_to('/')
            new_path_on_host.mkdir()

            subprocess.run(
                self.sudoify(
                    [
                        'mount',
                        '--rbind',
                        str(host),
                        str(guest.relative_to('/')) + '/',
                    ],
                ),
                cwd=self.environment.guest_root_dir,
            )
            self.to_unmount.append(new_path_on_host)

        return self.sudoify([
            'chroot',
            str(self.environment.guest_root_dir),
            str(self.mounts.out_dir_guest / self.harness_filename),
        ])

    def tear_down(self) -> None:
        for path in self.to_unmount:
            subprocess.run(self.sudoify(['umount', str(path)]))
            path.rmdir()


class ChrootLibfuzzerEnvironment(AbstractLibfuzzerEnvironment):
    INVOCATION_CLS = ChrootLibfuzzerInvocation
    use_sudo: bool

    def __init__(self,
        guest_root_dir: Path,
        guest_artifact_prefix_dir: Path,
        use_sudo: bool,
        *,
        verbose: bool = False,
    ):
        super().__init__(
            guest_root_dir,
            guest_artifact_prefix_dir,
            verbose=verbose,
        )

        self.use_sudo = use_sudo

    def sudoify(self, cmd: list[str]) -> list[str]:
        if self.use_sudo:
            return ['sudo'] + cmd
        else:
            return cmd

    def set_up(self) -> None:
        super().set_up()

        # If the guest-root-dir is in a subdirectory of (say) /tmpfs,
        # the goal here is to identify the string "tmpfs" so we can
        # avoid adding a binding for it, which would create a loop
        parts = list(self.guest_root_dir.resolve().parts)
        if len(parts) < 2:
            guest_root_dir_root_subdir_name = None
        else:
            guest_root_dir_root_subdir_name = parts[1]

        for dir in Path('/').iterdir():
            if not dir.is_dir():
                continue

            name = dir.name

            if name in {'out', 'work', guest_root_dir_root_subdir_name}:
                continue

            (self.guest_root_dir / name).mkdir()

            cmd = self.sudoify(['mount'])
            if name == 'proc':
                cmd += ['-t', 'proc']
            elif name == 'sys':
                cmd += ['-t', 'sysfs']
            else:
                cmd += ['--rbind']
            cmd += [f'/{name}', f'{name}/']

            subprocess.run(cmd, cwd=self.guest_root_dir)
