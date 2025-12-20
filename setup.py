from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="threat-hunting-playbook",
    version="1.0.0",
    author="Threat Hunting Team",
    author_email="security@example.com",
    description="AI-powered CLI tool for managing threat hunting playbooks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/threat-hunting-playbook",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1.7",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "openai>=1.12.0",
        "python-dotenv>=1.0.0",
        "jsonschema>=4.21.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "hunt=src.cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["playbooks/**/*"],
    },
)
