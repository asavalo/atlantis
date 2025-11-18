from setuptools import setup, find_packages

setup(
    name="libSarif",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "networkx==3.1.0",
        "loguru>=0.7.3",
        "pydantic>=2.11.5",
        "pydantic_core>=2.33.2",
    ],
    author="atlanta",
    author_email="atlanta@mail.com",
    description="A Python library for analyzing crs-sarif results",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Team-Atlanta/libSarif",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)
