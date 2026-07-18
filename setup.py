from setuptools import find_packages, setup

setup(
    name="wifisentinel",
    version="0.1.0",
    description="Modern orchestration framework around aircrack-ng / hcxtools / hashcat for authorized wireless security auditing.",
    author="Shridhar Vinayak Kirtane",
    url="https://github.com/shridhar3902/wifisentinel",
    packages=find_packages(),
    install_requires=[
        "PyYAML>=6.0",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "wifisentinel=wifisentinel.cli:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
