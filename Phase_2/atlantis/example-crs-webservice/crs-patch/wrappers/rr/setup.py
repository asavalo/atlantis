import os
import tarfile
import urllib.request
from pathlib import Path
from shutil import rmtree
from setuptools import find_packages, setup
from setuptools.command.install import install
from subprocess import run
from python_rr import RR_BACKTRACER_REPO_PATH

# Define RR's version you wish to download.
RR_VERSION = "5.8.0"

# The URL for the RR's tar.gz archive.
RR_URL = f"https://github.com/rr-debugger/rr/releases/download/{RR_VERSION}/rr-{RR_VERSION}-Linux-x86_64.tar.gz"
RR_BACKTRACER_URL = "git@github.com:Team-Atlanta/rr-backtracer.git"

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def download_and_extract_rr(target_directory: str):
    archive_path = os.path.join(CACHE_DIRECTORY, f"rr-{RR_VERSION}-Linux-x86_64.tar.gz")
    rr_install_path = os.path.join(target_directory, "rr")

    if not os.path.exists(archive_path):
        urllib.request.urlretrieve(RR_URL, archive_path)

    # Open the tar.gz archive and extract all files.
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(target_directory)

    if os.path.exists(rr_install_path):
        rmtree(rr_install_path)

    # rename the directory "rr-5.8.0-Linux-x86_64" to just "rr" for its simplicity.
    os.rename(
        os.path.join(target_directory, f"rr-{RR_VERSION}-Linux-x86_64"),
        os.path.join(target_directory, "rr"),
    )


def clone_rr_backtracer():
    # make sure it's removed
    if RR_BACKTRACER_REPO_PATH.exists():
        rmtree(RR_BACKTRACER_REPO_PATH)

    # @TODO: better way to download rr-backtracer tool? Registering it in `pyproject.toml` might be an answer.
    # Unlike other git repos, however, rr-backtracer is not a tool or library directly used by crete.
    proc = run(["git", "clone", RR_BACKTRACER_URL, RR_BACKTRACER_REPO_PATH])

    assert proc.returncode == 0


class CustomInstallCommand(install):
    def run(self):
        # Run the standard installation.
        install.run(self)  # pyright: ignore[reportUnknownMemberType]

        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_rr", "bin")
        os.makedirs(package_directory, exist_ok=True)

        download_and_extract_rr(package_directory)
        clone_rr_backtracer()


setup(
    name="rr",  # You may wish to change the package name accordingly.
    version=RR_VERSION,
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
