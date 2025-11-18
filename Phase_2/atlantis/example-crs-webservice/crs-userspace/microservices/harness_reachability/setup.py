from pathlib import Path
from setuptools import setup, find_packages

NAME = "harness_reachability"

setup(
    name=NAME,
    version="0.0.1",
    packages=[NAME, f"{NAME}.diff_analysis"],
    package_dir={
        NAME: "."
    },
    install_requires=[
        "openai==1.78.1",
        "tree-sitter==0.24.0",
        "tree-sitter-cpp==0.23.4",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            f"{NAME}={NAME}:run",
        ],
    },
)
