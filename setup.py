"""Setup configuration for kubexhunt."""

from setuptools import setup, find_packages

setup(
    name="kubexhunt",
    version="2.0",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "kubexhunt=kubexhunt.cli.main:main",
        ],
    },
)
