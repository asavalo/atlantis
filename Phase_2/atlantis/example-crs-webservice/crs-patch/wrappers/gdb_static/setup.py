import os
import tarfile
import urllib.request
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.install import install

# Define the JDT LS version you wish to download.
GDB_VERSION = "v15.2-static-4"

# The URL for the JDT LS tar.gz archive.
GDB_URL = f"https://github.com/guyush1/gdb-static/releases/download/{GDB_VERSION}/gdb-static-with-python-x86_64.tar.gz"

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def download_and_extract_gdb_static(target_directory: str):
    archive_path = os.path.join(CACHE_DIRECTORY, "gdb-static.tar.gz")

    if not os.path.exists(archive_path):
        urllib.request.urlretrieve(GDB_URL, archive_path)

    # Open the tar.gz archive and extract all files.
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(target_directory)

    return target_directory


class CustomInstallCommand(install):
    def run(self):
        # Run the standard installation.
        install.run(self)  # pyright: ignore[reportUnknownMemberType]

        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_gdb_static", "bin")
        os.makedirs(package_directory, exist_ok=True)

        download_and_extract_gdb_static(package_directory)


setup(
    name="python_gdb_static",  # You may wish to change the package name accordingly.
    version="15.2",
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
