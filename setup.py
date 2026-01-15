from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hairest",
    version="2.1.0",
    author="Callum",
    author_email="callumdev2292@gmail.com",
    description="Discord Clipboard System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/callummill/hairest",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Utilities",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests==2.31.0",
        "pycryptodome==3.23.0",
    ],
    keywords="discord, clipboard, utility, productivity",
    project_urls={
        "Bug Reports": "https://github.com/callummill/hairest/issues",
        "Source": "https://github.com/callummill/hairest",
    },
)