from pathlib import Path
from setuptools import setup, find_packages

def _read_content(path: str) -> str:
    return (Path(__file__).parent / path).read_text(encoding="utf-8")


requirements = _read_content("requirements.txt").splitlines()

NAME = "crash_collector"

setup(
    name=NAME,
    version="0.0.1",
    packages=[NAME],
    package_dir={
        NAME: "."
    },
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            f"{NAME}={NAME}:run",
        ],
    },
)