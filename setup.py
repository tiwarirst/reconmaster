"""ReconAI - Modular AI-Assisted Reconnaissance Platform."""
from setuptools import setup, find_packages

setup(
    name="reconai",
    version="1.0.0",
    description="Modular AI-Assisted Reconnaissance & Attack-Surface Intelligence Platform",
    author="ReconAI Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "httpx[http2]>=0.27.0",
        "dnspython>=2.6.0",
        "rich>=13.7.0",
        "pydantic>=2.7.0",
        "pyyaml>=6.0.1",
        "click>=8.1.7",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.2.0",
        "aiosqlite>=0.20.0",
    ],
    extras_require={
        "browser": ["playwright>=1.44.0"],
        "dev": ["pytest>=8.2.0", "pytest-asyncio>=0.23.0", "ruff>=0.4.0", "mypy>=1.10.0"],
    },
    entry_points={
        "console_scripts": [
            "reconai=reconai.cli.main:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
