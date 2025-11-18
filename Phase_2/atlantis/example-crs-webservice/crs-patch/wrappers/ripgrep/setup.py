import os
import tarfile
import urllib.request
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.install import install

RIPGREP_VERSION = "14.1.1"
RIPGREP_LINUX_TAR_GZ = f"ripgrep-{RIPGREP_VERSION}-x86_64-unknown-linux-musl.tar.gz"
RIPGREP_BINARY_URL = f"https://github.com/BurntSushi/ripgrep/releases/download/{RIPGREP_VERSION}/{RIPGREP_LINUX_TAR_GZ}"

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def download_and_extract_ripgrep(target_directory: str):
    archive_path = os.path.join(CACHE_DIRECTORY, "ripgrep.tar.gz")

    if not os.path.exists(archive_path):
        urllib.request.urlretrieve(RIPGREP_BINARY_URL, archive_path)

    # Open the tar.gz archive and extract all files.
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(target_directory)

    os.rename(
        os.path.join(target_directory, RIPGREP_LINUX_TAR_GZ.replace(".tar.gz", "")),
        os.path.join(target_directory, "bin"),
    )

    return target_directory


class CustomInstallCommand(install):
    def run(self):
        # Run the standard installation.
        install.run(self)  # pyright: ignore[reportUnknownMemberType]

        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_ripgrep")
        os.makedirs(package_directory, exist_ok=True)

        download_and_extract_ripgrep(package_directory)


setup(
    name="python_ripgrep",
    version=RIPGREP_VERSION,
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
