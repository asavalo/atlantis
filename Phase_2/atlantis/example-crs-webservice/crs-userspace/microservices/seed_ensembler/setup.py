from pathlib import Path
from setuptools import setup, find_packages

libmsa_uri = (Path(__file__).parent / "../../libs/libMSA/python").as_uri()
libcrs_uri = (Path(__file__).parent / "../../libs/libCRS").as_uri()
libatlantis_uri = (Path(__file__).parent / "../../libs/libatlantis").as_uri()

def _read_content(path: str) -> str:
    return (Path(__file__).parent / path).read_text(encoding="utf-8")


requirements = _read_content("requirements.txt").splitlines()

NAME = "seed_ensembler"

setup(
    name=NAME,
    version="0.0.1",
    packages=[NAME],
    package_dir={
        NAME: "."
    },
    python_requires=">=3.10",
    install_requires=[f"libCRS @ {libcrs_uri}", f"libMSA @ {libmsa_uri}", f"libatlantis @ {libatlantis_uri}"] + requirements,
    entry_points={
        "console_scripts": [
            f"{NAME}={NAME}:run",
        ],
    },
)
