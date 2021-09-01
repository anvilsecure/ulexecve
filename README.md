# Quick Start

Execute dynamic or statically compiled ELF Linux binaries without ever calling execve().

```
cat /bin/echo | ulexecve - hello
hello
```

# Introduction

This Python tool is called `ulexecve` and it stands for *userland execve*. It helps you execute arbitrary ELF binaries on Linux systems from userland without ever calling the *execve()* systemcall. In other words: you can execute arbitrary binaries directly from memory without ever having to write them to storage. This is very useful from an anti-forensic or red-teaming perspective and enables you to move around more stealthily while still dropping compiled binaries on target machines. The tool works on CPython 3.x as well as CPython 2.7 (and possibly earlier) on the supported Linux platforms (`x86`, `x86-64` and `aarch64`). Both static and dynamically compiled ELF binaries are supported. Of course there will always be a small subset of binaries which may not work or result in a crash and for these a 100% reliable fallback method is implemented on top of the modern `memfd_create()` system call.

## Background

Linux userland execve tools have a history that goes back roughly two decades. The first solid writeups on this were made by *the grugq* in *The Design and Implementation of Userland Exec* [1] as well another article in Phrack 62 [2]. Anti-forensic techniques to execute binaries directly from memory are farely standard. Rapid7's *mettle* for example has a library named `libreflect` which includes a utility `noexec` which also attempts to execute an ELF via reflection only. However this tool is written in C and it has the implicit requirement that you need to transfer the `noexec` binary on the target system as well being able to execute this binary.

In modern container environments this is definitely not always possible anymore. However a lot of container environments do contain a Python installation. Having the ability to simply download a Python script via `curl` or so on a target machine and then being able to execute this script to then stealthily execute arbitrary binaries is very useful from an anti-forensics perspective.

This is also the reason the tool is all implemented in just one file. This should make it easier to download it on target systems and not have to worry about installing any other dependencies before being able to run it. The tool is tested with Python 2.7 even though this Python version is deprecated. There are many systems still out there with 2.x versions so this is useful.

No good other implementations of a Python userland *execve()* existed. There is *SELF* [3] which was not extensively documented, lacked easy debugging options but more importantly didn't work at all. The `ulexecve` implementation was written from scratch. It parses the ELF file, loads and parses the dynamic linker as well (if needed), maps all segments into memory and ultimately constructs a jump buffer containing CPU instructions to ultimately transfer control from the Python process directly to the newly loaded binary.

All the common ELF parsing logic, setting up the stack, mapping the ELF segments and setting up the jump buffers is abstracted away so it is fairly easy (in the order of a couple of hours) to port to another CPU. Porting it to other ELF based platforms such as the BSDs might be a bit more involved but should still be fairly straightforward. For more information on to do so just check the comments in the code.

Please note that it is an explicit design goal to have no external dependencies and to have everything implemented in a single source code file. If you need to make smaller payloads it should be fairly trivial to remove support for cetain CPU types or rip out all the debug information and other options.

# Installation

## To install via pip

Although this makes little sense from an anti-forensics perspective the tool is installable via `pip`.

```
pip install ulexecve
ulexecve --help
```

## To build and install as a Python package

```
python setup.py sdist
python -m pip install --upgrade dist/ulexecve-<version>.tar.gz
ulexecve --help
```

## To download and run via curl
```
curl -o ulexecve.py https://raw.githubusercontent.com/anvilventures/ulexecve/docs/ulexecve.py
./ulexecve.py --help
```

# Usage

The tool fully supports static and dynamically compiled executables. Simply pass the filename of the binary to `ulexecve` and any arguments you want to supply to the binary. The environment will be directly copied over from the environment in which you execute `ulexecve`.

```
ulexecve /bin/ls -lha
```

You can have it read a binary from `stdin` if you specify `-` as the filename.

```
cat /bin/ls | ulexecve - -lha
```

To debug several options are available. If you get a crash you can show debug information via `--debug`, the built up stack via `--show-stack` as well as the generated jump buffer `--show-jumpbuf`. The `--jump-delay` option is very useful if you want to parse and map an ELF properly and then attach a debugger to step through the jump buffer and the ultimate executing binary to find the cause of the crash.


```
cat /bin/echo | ulexecve --debug --show-stack --show-jumpbuf - hello
...
PT_LOAD at offset 0x0002c520: flags=0x6, vaddr=0x2d520, filesz=0x1ad8, memsz=0x1c70
Loaded interpreter successfully
Stack allocated at: 0x7fddf630e000
vDSO loaded at 0x7ffd8952e000 (Auxv entry AT_SYSINFO_EHDR), AT_SYSINFO: 0x00000000
Auxv entries: HWCAP=0x00000002, HWCAP2=0x00000002, AT_CLKTCK=0x00000064
stack contents:
 argv
   00000000:   0x0000000000000002
   00000008:   0x00007fddf6312410
...
Generated mmap call (addr=0x00000000, length=0x00030000, prot=0x7, flags=0x22)
Generated memcpy call (dst=%r11 + 0x00000000, src=0x02534650, size=0x00000fc8)
Generated memcpy call (dst=%r11 + 0x0002d520, src=0x0253d720, size=0x00001ad8)
Generating jumpcode with entry_point=0x00001100 and stack=0x7fddf630e000
Jumpbuf with entry %r11+0x1100 and stack: 0x00007fddf630e000
Written jumpbuf to /tmp/tmphsiaygna.jumpbuf.bin (#592 bytes)
Executing: objdump -m i386:x86-64 -b binary -D /tmp/tmphsiaygna.jumpbuf.bin
...
245:   00 00 00
248:   4c 01 d9                add    %r11,%rcx
24b:   48 31 d2                xor    %rdx,%rdx
24e:   ff e1                   jmpq   *%rcx
...
Memmove(0x7fddf6f0e000, 0x0254d7f0, 0x00000250)
hello
```

There is always the `--fallback` option. It is not as stealthy as parsing and mapping in the binaries in userland ourselves. The fallback method uses `memfd_create()` and `fexecve()` but it should work 100% of time for executing arbitrary static or dynamic binaries. Provided the supplied binaries are the right binaries for the platform you are on obviously.

# Limitations

Obviously you can always end up with binaries which will not be executed properly. However this implementation is pretty clean and well tested (it includes unit-tests for static and dynamic binaries, PIE-compiled executables and executables with different runtimes such as Rust or Go). For most tools and binaries on the mentioned platforms it should do the trick. But your mileage may vary.

# Porting

When porting to a different platform make sure that the small amount of unit-tests all work. Simply run the included `./test.py` on the target platform and fix up everything up until all these tests succeed again.

# Bugs, comments, suggestions

Shoot in a pull-request via github, post an issue in the issue tracker or simply shoot an email to *gvb@anvilsecure.com*.

# References

1. ["The Design and Implementation of Userland Exec"](https://github.com/grugq/grugq.github.com/blob/master/docs/ul_exec.txt), by the grugq. 

2. ["FIST! FIST! FIST! Its all in the wrist: Remote Exec"](http://phrack.org/issues/62/8.html), by grugq, Phrack 62-0x08, 2004-07-13.

3. [Implementation of SELF in Python](https://github.com/mak/pyself), by Maciej Kotowicz (mak).
