#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="jira-security-scanner",
    version="2.1.0",
    author="sevbandonmez",
    description="Advanced Jira Security Assessment Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sevbandonmez/jira-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "jira-scanner=jira_scanner:main",
        ],
    },
    keywords="security, jira, vulnerability, scanner, assessment, penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/sevbandonmez/jira-scanner/issues",
        "Source": "https://github.com/sevbandonmez/jira-scanner",
    },
)
