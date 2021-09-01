# Introduction

This Python tool helps you execute arbitrary ELF binaries on Linux systems without ever calling *execve()*. You can stealthily execute arbitrary binaries directly from memory without ever having to write the binaries to disk which is useful from an anti-forensic and red-teaming perspective. The tool works on CPython 3.x as well as CPython 2.7 (and possibly earlier) installations. Please note that right now it only supports `x86`, `x86-64` and `aarch64` (ARM-64, little endian, default Linux ABI) CPUs. All the common ELF parsing logic, setting up the stack, mapping the ELF segments and setting up the jump buffers is abstracted away so it is fairly easy (in the order of a couple of hours) to port to another platform. For more information on how to do so just check `ulexecve.py` in the git repository.


## Background

Linux userland execve tools have a history that goes back roughly two decades. The first solid writeups on this were made by *the grugq* in *The Design and Implementation of Userland Exec* [1] as well another article in Phrack 62 [2]. Anti-forensic techniques to execute binaries directly from memory are farely standard. Rapid7's *mettle* for example has a library named `libreflect` which includes a utility `noexec` which also attempts to execute an ELF via reflection only. However this tool is written in C and it has the implicit requirement that you need to transfer the `noexec` binary on the target system as well being able to execute this binary. In modern container environments this is definitely not always possible anymore. However a lot of container environments do contain a Python installation. Having the ability to simply download a Python script via `curl` or so on a target machine and then being able to execute this script to then stealthily execute arbitrary binaries is very useful from an anti-forensics perspective.

This is also the reason the tool is all implemented in just one file. This should make it easier to download it on target systems and not have to worry about installing any other dependencies before being able to run it. The tool is tested with Python 2.7 even though this Python version is deprecated. There are s


## Usage



## To install via pip

Although this makes little sense from an anti-forensics perspective the tool is installable via `pip`.

```
pip install ulexecve
```

## To build and install as a Python package

```
python setup.py sdist
python -m pip install --upgrade dist/ulexecve-<version>.tar.gz
```

# References

1. ["The Design and Implementation of Userland Exec"](https://github.com/grugq/grugq.github.com/blob/master/docs/ul_exec.txt), by the grugq. 

2. ["FIST! FIST! FIST! Its all in the wrist: Remote Exec"](http://phrack.org/issues/62/8.html), by grugq, Phrack 62-0x08, 2004-07-13.

3. [Implementation of SELF in Python](https://github.com/mak/pyself), by Maciej Kotowicz (mak).