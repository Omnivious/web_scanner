from setuptools import setup, find_packages

setup(
    name="web_scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "argparse",
        "concurrent.futures",
        "colorama",
    ],
    entry_points={
        "console_scripts": [
            "web_scanner=scanner.scanner:main",
        ],
    },
)
