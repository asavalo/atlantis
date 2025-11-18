import os
import sys
import urllib.request
import zipfile
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.install import install

# Define the clangd version you wish to download.
CLANGD_VERSION = "19.1.2"

# Determine the platform-specific string.
if sys.platform.startswith("linux"):
    platform_str = "linux"
elif sys.platform == "darwin":
    platform_str = "mac"
elif sys.platform.startswith("win"):
    platform_str = "windows"
else:
    raise RuntimeError("Unsupported platform for clangd.")

# Build the URL based on the version and platform.
CLANGD_URL = (
    f"https://github.com/clangd/clangd/releases/download/{CLANGD_VERSION}/"
    f"clangd-{platform_str}-{CLANGD_VERSION}.zip"
)

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def download_and_extract_clangd(target_directory: str):
    archive_path = os.path.join(CACHE_DIRECTORY, "clangd.zip")

    if not os.path.exists(archive_path):
        urllib.request.urlretrieve(CLANGD_URL, archive_path)

    with zipfile.ZipFile(archive_path, "r") as zip_ref:
        zip_ref.extract(f"clangd_{CLANGD_VERSION}/bin/clangd", target_directory)

    # move the clangd binary to the target directory
    os.rename(
        os.path.join(target_directory, f"clangd_{CLANGD_VERSION}/bin/clangd"),
        os.path.join(target_directory, "clangd"),
    )

    return os.path.join(target_directory, "clangd")


class CustomInstallCommand(install):
    def run(self):
        # Run the standard install first.
        install.run(self)  # pyright: ignore[reportUnknownMemberType]

        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_clangd")
        clangd_directory = os.path.join(package_directory, "bin")
        os.makedirs(clangd_directory, exist_ok=True)

        # Download and extract clangd into the designated directory.
        clangd_binary = download_and_extract_clangd(clangd_directory)

        # Determine the expected name of the binary.
        if sys.platform.startswith("win"):
            binary_name = f"{clangd_binary}.exe"
        else:
            binary_name = clangd_binary

        # Set executable permissions on Unix-like systems.
        if os.path.exists(binary_name):
            if not sys.platform.startswith("win"):
                os.chmod(binary_name, 0o755)


setup(
    name="python_clangd",
    version=CLANGD_VERSION,
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
