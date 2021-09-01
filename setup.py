import re

import setuptools
NAME = "ulexecve"

# We could use import obviously but we parse it as some python build systems
# otherwise pollute namespaces and we might end up with some annoying issues.
# See https://stackoverflow.com/a/7071358 for a discussion.
with open("%s.py" % NAME, "rt") as fd:
    verstrline = fd.read()
    regex = r"^__version__ = ['\"]([^'\"]*)['\"]"
    mo = re.search(regex, verstrline, re.M)
    if mo:
        version = mo.group(1)
    else:
        raise RuntimeError("Unable to find version string")

# load long description directly from the include markdown README
with open("README.md", "r") as fd:
    long_description = fd.read()

setuptools.setup(
    name=NAME,
    version=version,
    author="Anvil Secure Inc.",
    author_email="gvb@anvilsecure.com",
    description="Userland execve utility",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anvilsecure/ulexecve",
    keywords="userland execve",
    py_modules=[NAME],
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
        "console_scripts": ["%s=%s:main" % (NAME, NAME)],
    },
    install_requires=[
    ],
    extras_require={
        "test": ["tox", "flake8"]
    }
)
