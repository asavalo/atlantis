import os
import shutil
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.install import install

CACHE_DIRECTORY = Path.home() / ".cache" / "crete"
CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
CRS_ARCHITECTURE_DIRECTORY = ROOT_DIRECTORY / "third_party" / "crs-architecture"


def _copy_crs_architecture(source_directory: Path, target_directory: Path):
    shutil.copytree(
        source_directory / "example-challenge-evaluation" / "action-build-cr",
        target_directory / "challenge-evaluation" / "action-build-cr",
    )
    shutil.copytree(
        source_directory / "example-challenge-evaluation" / "action-run-pov",
        target_directory / "challenge-evaluation" / "action-run-pov",
    )
    shutil.copytree(
        source_directory / "example-challenge-evaluation" / "action-run-tests",
        target_directory / "challenge-evaluation" / "action-run-tests",
    )

    shutil.copy(
        source_directory
        / "docs"
        / "source_language_determination"
        / "dist"
        / "identifier_linux_amd64_v1"
        / "identifier",
        target_directory / "identifier",
    )


class CustomInstallCommand(install):
    description = "Install the CRS architecture repository"
    user_options = []

    def run(self):
        install.run(self)  # pyright: ignore[reportUnknownMemberType]

        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_crs_architecture")
        os.makedirs(package_directory, exist_ok=True)

        # _download_crs_architecture(
        #     "git@github.com:Team-Atlanta/example-crs-architecture.git",
        #     CRS_ARCHITECTURE_DIRECTORY,
        # )

        _copy_crs_architecture(CRS_ARCHITECTURE_DIRECTORY, Path(package_directory))


setup(
    name="python_crs_architecture",
    version="0.2.0",
    packages=find_packages(),
    description="CRS Architecture Repository",
    author="Team Atlanta",
    cmdclass={
        "install": CustomInstallCommand,
    },
)
