from setuptools import setup, find_packages

setup(
    name="roboenum",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "httpx",
        "colorama",
    ],
    entry_points={
        'console_scripts': [
            'roboenum=roboenum.cli:main',
        ],
    },
    author="QTShade",
    description="A robots.txt network enumeration and fingerprinting tool",
    license="MIT",
    license_files=["LICENSE"],
    url="https://github.com/QTShade/roboenum",
    keywords="roboenum, enum, recon, tools, pentest",
    python_requires='>=3.8',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)