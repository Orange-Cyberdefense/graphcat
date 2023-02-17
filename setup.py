from setuptools import setup

setup(
    name="graphcat.py",
    version="1.0.0",
    author="zblurx",
    author_email="seigneuret.thomas@protonmail.com",
    description="Generate graphs and charts on password cracking",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/Orange-Cyberdefense/graphcat",
    license="MIT",
    install_requires=[
        "matplotlib==3.6.2",
        "Jinja2==3.1.2",
        "weasyprint==57.2"
    ],
    python_requires='>=3.6',
    scripts=["graphcat.py"]
)