#!/usr/bin/env python3
"""
MEDUSA - AI-Powered Penetration Testing CLI
Setup configuration for pip installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="medusa-pentest",
    version="1.0.0",
    author="Project Medusa Team",
    author_email="security@medusa.dev",
    description="AI-powered autonomous penetration testing CLI for security professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hidaroz/project-medusa",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Environment :: Console",
        "Operating System :: OS Independent",
    ],
    keywords="security penetration-testing ai llm red-team offensive-security",
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "medusa=medusa.cli:app",
        ],
    },
    include_package_data=True,
    package_data={
        "medusa": ["templates/*.html", "templates/*.css"],
    },
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/hidaroz/project-medusa/issues",
        "Documentation": "https://docs.medusa.dev",
        "Source": "https://github.com/hidaroz/project-medusa",
    },
)
