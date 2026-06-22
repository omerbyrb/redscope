from setuptools import setup, find_packages

setup(
    name="redscope",
    version="1.0.0",
    description="Modular Penetration Testing Framework",
    author="omerbayirbasi",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "click>=8.1",
        "rich>=13.0",
        "requests>=2.31",
        "dnspython>=2.4",
        "python-nmap>=0.7",
    ],
    entry_points={
        "console_scripts": [
            "redscope=cli:cli",
        ],
    },
)
