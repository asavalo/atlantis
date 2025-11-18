from pathlib import Path

from setuptools import find_packages, setup


def _read_content(path: str) -> str:
    return (Path(__file__).parent / path).read_text(encoding="utf-8")


requirements = _read_content("requirements.txt").splitlines()

setup(
    name="libMSA",
    packages=find_packages(exclude=["test", "test.*"]),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
