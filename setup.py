import setuptools

# load long description directly from the include markdown README
with open("README.md", "r") as fd:
    long_description = fd.read()

setuptools.setup(
    name="ulexecve",
    version="1.0a",
    author="Anvil Secure Inc.",
    author_email="gvb@anvilsecure.com",
    description="Userland execve utility",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anvilventures/ulexecve",
    py_modules=["ulexecve"],
    keywords="userland execve",
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Development Status :: 5 - Production/Stable",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
    ],
    python_requires='>=2.7',
    entry_points={
        "console_scripts": ["ulexecve=ulexecve:main"],
    },
    install_requires=[
    ],
    extras_require={
        "test": ["tox", "flake8"]
    }
)
