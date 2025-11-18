import os
import sys
import tarfile
import urllib.request
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.install import install

# Define the JDT LS version you wish to download.
JDTLS_VERSION = "1.34.0-202404031240"

# The URL for the JDT LS tar.gz archive.
JDTLS_URL = (
    "https://www.eclipse.org/downloads/download.php?file=/jdtls/milestones/1.34.0/"
    f"jdt-language-server-{JDTLS_VERSION}.tar.gz"
)

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def download_and_extract_jdtls(target_directory: str):
    archive_path = os.path.join(CACHE_DIRECTORY, "jdtls.tar.gz")

    if not os.path.exists(archive_path):
        urllib.request.urlretrieve(JDTLS_URL, archive_path)

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

        # For this example we assume that our package (named "python_jdtls")
        # contains a subdirectory "bin" where we want to install the jdtls script.
        package_directory = os.path.join(self.install_lib, "python_jdtls")
        os.makedirs(package_directory, exist_ok=True)

        # Download and extract jdtls into the designated directory.
        jdtls_directory = download_and_extract_jdtls(package_directory)
        jdtls_binary = os.path.join(jdtls_directory, "bin/jdtls")

        # On Unix-like systems, set executable permissions.
        if os.path.exists(jdtls_binary) and not sys.platform.startswith("win"):
            os.chmod(jdtls_binary, 0o755)
            print(f"Set executable permissions on {jdtls_binary}")


setup(
    name="python_jdtls",  # You may wish to change the package name accordingly.
    version=JDTLS_VERSION,
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
