from pathlib import Path
from setuptools import setup

libmsa_uri = (Path(__file__).parent / "../libs/libMSA/python").as_uri()
libcrs_uri = (Path(__file__).parent / "../libs/libCRS").as_uri()
libatlantis_uri = (Path(__file__).parent / "../libs/libatlantis").as_uri()

NAME = "deepgen_service"

setup(
    name=NAME,
    version="0.0.1",
    packages=[NAME],
    package_dir={NAME: "."},
    python_requires=">=3.10",
    install_requires=[
        f"libCRS @ {libcrs_uri}",
        f"libMSA @ {libmsa_uri}",
        f"libatlantis @ {libatlantis_uri}",
    ],
    entry_points={
        "console_scripts": [
            f"{NAME}={NAME}:run",
        ],
    },
)
