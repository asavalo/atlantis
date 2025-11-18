import os
import tarfile
import urllib.request
from pathlib import Path
from shutil import copy
from setuptools import find_packages, setup
from setuptools.command.install import install

# CTAGS_VERSION = "6.1.0"

# The URL for the RR's tar.gz archive.
# ctags version is quite dirty to use for URL downloads, which complicates making `CTAGS_VERSION` dependent string.
CTAGS_URL = "https://github.com/universal-ctags/ctags-nightly-build/releases/download/2025.03.30%2Bae6145e05b0441c3aa0726709049195789dfdc82/uctags-2025.03.30-1-x86_64.pkg.tar.xz"

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def _copy_ctags_executables(target_directory: str):
    copy(
        os.path.join(target_directory, "usr/local/bin/ctags"),
        os.path.join(target_directory, "ctags"),
    )

    copy(
        os.path.join(target_directory, "usr/local/bin/readtags"),
        os.path.join(target_directory, "readtags"),
    )


def _download_and_extract_ctags(target_directory: str):
    archive_path = os.path.join(
        CACHE_DIRECTORY, "uctags-2025.03.30-1-x86_64.pkg.tar.xz"
    )

    if not os.path.exists(archive_path):
        urllib.request.urlretrieve(CTAGS_URL, archive_path)

    # Open the tar.gz archive and extract all files.
    with tarfile.open(archive_path, "r:xz") as tar:
        tar.extractall(target_directory)

    _copy_ctags_executables(target_directory)


class CustomInstallCommand(install):
    def run(self):
        # Run the standard installation.
        install.run(self)  # pyright: ignore[reportUnknownMemberType]

        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_ctags", "bin")
        os.makedirs(package_directory, exist_ok=True)

        _download_and_extract_ctags(package_directory)


setup(
    name="python_ctags",
    version="6.1.0",
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
