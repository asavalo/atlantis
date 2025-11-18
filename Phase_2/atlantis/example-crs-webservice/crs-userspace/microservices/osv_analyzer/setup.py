from pathlib import Path
from setuptools import setup, find_packages

NAME = "osv_analyzer"

setup(
    name=NAME,
    version="0.0.1",
    packages=[NAME],
    package_dir={
        NAME: "."
    },
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            f"{NAME}={NAME}:run",
        ],
    },
)
