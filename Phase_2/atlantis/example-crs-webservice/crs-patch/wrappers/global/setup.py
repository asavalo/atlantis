import os
from subprocess import check_call

from setuptools import find_packages, setup
from setuptools.command.install import install


class CustomInstallCommand(install):
    def run(self):
        install.run(self)  # pyright: ignore[reportUnknownMemberType]
        if self.install_lib is None:
            raise RuntimeError("install_lib is not set")

        package_directory = os.path.join(self.install_lib, "python_global")
        os.makedirs(package_directory, exist_ok=True)

        check_call(["apt-get", "download", "global"], cwd=package_directory)
        check_call(
            [
                "sh",
                "-c",
                "dpkg -x global*.deb .local",
            ],
            cwd=package_directory,
        )


setup(
    name="global",
    version="6.6.3",
    packages=find_packages(),
    cmdclass={
        "install": CustomInstallCommand,
    },
)
