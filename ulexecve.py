#!/usr/bin/env python
# Copyright (c) 2021, Anvil Secure Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
"""

import argparse
import ctypes
import errno
import logging
import os
import struct
import subprocess
import sys
import tempfile
from ctypes import (POINTER, c_char_p, c_int, c_long, c_size_t, c_uint,
                    c_ulong, c_void_p, memmove, sizeof)
from ctypes.util import find_library

__version__ = "0.7"

libc = ctypes.CDLL(find_library('c'), use_errno=True)

PAGE_SIZE = ctypes.pythonapi.getpagesize()


def PAGE_FLOOR(addr):
    return (addr) & (-PAGE_SIZE)


def PAGE_CEIL(addr):
    return (PAGE_FLOOR((addr) + PAGE_SIZE - 1))


def _emulate_getauxval(ltype):
    with open("/proc/self/auxv", "rb") as fd:
        data = fd.read()

        isize = sizeof(c_size_t)
        fmt = "QQ" if isize == 8 else "LL"
        data = [data[x: x + (isize << 1)] for x in range(0, len(data), (isize << 1))]
        for d in data:
            key, val = struct.unpack("<%s" % fmt, d)
            if key == ltype:
                return val
    return 0x0


# Need to use this wrapper as there are no good backwards compatible options
# that yield a seekable byte stream for both major Python versions
def _readbytes_from_stdin():
    if sys.version_info.major == 2:
        import StringIO
        sio = StringIO.StringIO()
        sio.write(sys.stdin.read())
        sio.seek(0)
        return sio
    elif sys.version_info.major == 3:
        import io
        bio = io.BytesIO()
        bio.write(sys.stdin.buffer.read())
        bio.seek(0)
        return bio
    else:
        raise Exception("unexpected Python version found")


# If we run on glibc older than 2.16 we would not have getauxval(), we could
# then try to emulate it by reading from /proc/<pid>/auxv. That glibc version
# was released in late 2012 though but let's try and support older or different
# libcs anyway.
try:
    getauxval = libc.getauxval
    getauxval.argtypes = [c_ulong]
    getauxval.restype = c_ulong
except AttributeError:
    getauxval = _emulate_getauxval

mmap = libc.mmap
mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]
mmap.restype = c_void_p

mprotect = libc.mprotect
mprotect.argtypes = [c_void_p, c_size_t, c_int]
mprotect.restype = c_int

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
MAP_PRIVATE = 0X02
MAP_ANONYMOUS = 0x20
MAP_GROWSDOWN = 0x0100
MAP_FIXED = 0x10

PT_LOAD = 0x1
PT_INTERP = 0x3
EM_X86_64 = 0x3e
EM_386 = 0x3


def display_jumpbuf(machine, buf):

    machines = {EM_386: "i386", EM_X86_64: "i386:x86-64"}
    assert(machine in machines)

    with tempfile.NamedTemporaryFile(suffix=".jumpbuf.bin", mode="wb") as tmp:
        tmp.write(buf)
        tmp.seek(0)
        logging.debug("Written jumpbuf to %s (#%u bytes)" % (tmp.name, len(buf)))
        # To disassemble run the following command with temp filename appended to it
        cmd = "objdump -m %s -b binary -D %s" % (machines[machine], tmp.name)
        logging.debug("Executing: %s" % cmd)
        try:
            output = subprocess.check_output(cmd.split(" "))
        except OSError:
            logging.error("Error while trying to disassemble: objdump not found in $PATH")
            sys.exit(1)

        logging.info(output.decode("utf-8", errors="ignore"))


def prepare_jumpbuf(buf):
    dst = mmap(0, PAGE_CEIL(len(buf)), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    src = ctypes.create_string_buffer(buf)
    logging.debug("Memmove(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, ctypes.addressof(src), len(buf)))
    memmove(dst, src, len(buf))
    ret = mprotect(PAGE_FLOOR(dst), PAGE_CEIL(len(buf)), PROT_READ | PROT_EXEC)
    if ret == -1:
        logging.error("Calling mprotect() on jumpbuffer failed")

    return ctypes.cast(dst, ctypes.CFUNCTYPE(c_void_p))


class ELFParsingError(Exception):
    pass


class ELFParser:

    ET_EXEC = 0x2
    ET_DYN = 0x3

    def __init__(self, stream):
        self.stream = stream
        self.ph_entries = []
        self.interp = None
        self.is_pie = None
        self.parse()

    def log(self, logline):
        logging.debug("%s" % (logline))

    def unpack(self, fmt):
        sz = struct.calcsize(fmt)
        buf = self.stream.read(sz)
        return (struct.unpack("%c%s" % ("<" if self.is_little_endian else ">", fmt), buf), buf)

    def unpack_ehdr(self):
        fmt = "HHIIIIIHHHHHH" if self.is_32bit else "HHIQQQIHHHHHH"
        return self.unpack(fmt)

    def unpack_phdr(self):
        # Unpack as the order of the values is different for 32-bit or 64-bit
        # program headers so we can return the values in a consistent order
        if self.is_32bit:
            fmt = "IIIIIIII"
            values, buf = self.unpack(fmt)
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = values
        else:
            fmt = "IIQQQQQQ"
            values, buf = self.unpack(fmt)
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = values
        return ((p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align), buf)

    def parse(self):
        self.parse_head()
        self.parse_ehdr()
        self.parse_pentries()

    def parse_head(self):
        self.stream.seek(0)
        magic = self.stream.read(4)
        if magic != b"\x7fELF":
            raise ELFParsingError("Not an ELF file")

        bittype = self.stream.read(1)
        if bittype not in (b"\x01", b"\x02"):
            raise ELFParsingError("Unknown EI class specified")

        self.is_32bit = True if bittype == b"\x01" else False

        b = self.stream.read(1)
        if b == b"\x01":
            self.is_little_endian = True
        elif b == b"\x02":
            self.is_little_endian = False
        else:
            raise ELFParsingError("Unknown endiannes specified")

        self.log("Parsed ELF header successfully")

    def parse_ehdr(self):
        self.stream.seek(16)
        values, buf = self.unpack_ehdr()
        self.e_type, self.e_machine, self.e_version, self.e_entry, \
            self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, \
            self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx = values
        self.ehdr = buf

        if self.e_type != ELFParser.ET_EXEC and self.e_type != ELFParser.ET_DYN:
            raise ELFParsingError("ELF is not an executable or shared object file")

        if self.e_phnum == 0:
            raise ELFParsingError("No program headers found in ELF")

        if self.e_machine not in (EM_X86_64, EM_386):
            raise ELFParsingError("ELF machine type is not x86-64")

    def parse_pentries(self):
        self.stream.seek(self.e_phoff)
        for _ in range(self.e_phnum):
            self.parse_pentry()

    def parse_pentry(self):
        values, _ = self.unpack_phdr()
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, \
            p_align = values

        if p_type not in (PT_LOAD, PT_INTERP):
            return

        off = self.stream.tell()
        self.stream.seek(p_offset)

        if p_type == PT_LOAD:
            self.log("PT_LOAD at offset 0x%.8x: flags=0x%.x, vaddr=0x%.x, filesz=0x%.x, memsz=0x%.x" % (p_offset, p_flags, p_vaddr, p_filesz, p_memsz))

            # if p_align is 0 or 1 no alignment is necessary
            needs_alignment = p_align not in (0x0, 0x1)
            if needs_alignment:
                # this is a sanity check more than anything
                if p_vaddr % p_align != p_offset % p_align:
                    raise ELFParsingError("Sanity check failed as p_vaddr should equal p_offset, modulo p_align")
            else:
                raise ELFParsingError("Non-alignment specified by p_align is not supported")

            # read program header data which should be p_filesz long
            buf = self.stream.read(p_filesz)
            if len(buf) != p_filesz:
                raise ELFParsingError("Read less than expected p_filesz bytes")

            # first PT_LOAD section we use to identifie PIE status
            if len(self.ph_entries) == 0:
                if p_vaddr != 0x0:
                    self.log("Identified as a non-PIE executable")
                    self.is_pie = False
                else:
                    self.log("Identified as a PIE executable")
                    self.is_pie = True

            # store extracted program header data
            data = ctypes.create_string_buffer(buf)
            pentry = {"flags": p_flags, "memsz": p_memsz, "vaddr": p_vaddr, "filesz": p_filesz, "offset": p_offset, "data": data}
            self.ph_entries.append(pentry)

        elif p_type == PT_INTERP:
            # strip off the last byte as that is a 0-byte and it will cause
            # pathname encoding problems later otherwise
            self.interp = self.stream.read(p_filesz)
            self.interp = self.interp[:-1]

            self.log("PT_INTERP at offset 0x%.x: interpreter set as %s" % (p_offset, self.interp.decode("utf-8", errors="ignore")))

        self.stream.seek(off)

    def map_size(self):
        sz = 0
        for entry in self.ph_entries:
            vaddr, memsz = entry["vaddr"], entry["memsz"]
            sz = vaddr + memsz if (vaddr + memsz) > sz else sz
        if not self.is_pie:
            assert(len(self.ph_entries) > 0)
            adjust = self.ph_entries[0]["vaddr"]
            self.log("Not a PIE binary so adjusting size down with 0x%.8x" % adjust)
            sz -= adjust
        self.log("Total calculated map size for executable is: 0x%.8x" % sz)
        return sz


class Stack:

    # Taken from /usr/include/x86_64-linux-gnu/bits/auxv.h
    AT_NULL = 0
    AT_PHDR = 3
    AT_PHENT = 4
    AT_PHNUM = 5
    AT_PAGESZ = 6
    AT_BASE = 7
    AT_ENTRY = 9
    AT_UID = 11
    AT_EUID = 12
    AT_GID = 13
    AT_EGID = 14
    AT_PLATFORM = 15
    AT_HWCAP = 16
    AT_CLKTCK = 17
    AT_SECURE = 23
    AT_RANDOM = 25
    AT_HWCAP2 = 26
    AT_EXECFN = 31
    AT_SYSINFO = 32
    AT_SYSINFO_EHDR = 33
    AT_MINSIGSTKSZ = 51  # stack needed for signal delivery (AArch64)

    # Offsets so that we can fixup the auxv header values later on from the jumpcode
    # The users of these offset need to multiple them by the size of c_size_t for the
    # platform they're used
    OFFSET_AT_BASE = 1
    OFFSET_AT_PHDR = 3
    OFFSET_AT_ENTRY = 5

    def __init__(self, num_pages, is_32bit=False):
        self.size = 2048 * PAGE_SIZE
        self.base = mmap(0, self.size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0)
        ctypes.memset(self.base, 0, self.size)

        # stack grows down so start of stack needs to be adjusted
        self.base += (self.size - PAGE_SIZE)
        self.stack = (ctypes.c_size_t * PAGE_SIZE).from_address(self.base)
        logging.debug("Stack allocated at: 0x%.8x" % (self.base))
        self.refs = []

        self.auxv_start = 0
        self.is_32bit = is_32bit

    def add_ref(self, obj):
        # we simply add the object to the list so that the garbage collector
        # cannot throw havoc on us here; this way the ctypes object will stay
        # in memory properly as there will be a reference to it
        self.refs.append(obj)

    def setup(self, argv, envp, exe, show_stack=False):
        assert(len(self.refs) == 0)
        stack = self.stack
        # argv starts with amount of args and is ultimately NULL terminated
        stack[0] = c_size_t(len(argv))
        i = 1
        for arg in argv:
            enc = arg.encode("utf-8", errors="ignore")
            buf = ctypes.create_string_buffer(enc)
            self.add_ref(buf)
            stack[i] = ctypes.addressof(buf)
            i = i + 1
        stack[i + 1] = c_size_t(0)
        env_off = i + 1

        # envp does not have a preceding count and is ultimately NULL terminated
        i = 0
        for env in envp:
            enc = env.encode("utf-8", errors="ignore")
            buf = ctypes.create_string_buffer(enc)
            self.add_ref(buf)
            stack[i + env_off] = ctypes.addressof(buf)
            i = i + 1
        stack[i + env_off] = c_size_t(0)
        i = i + 1

        aux_off = i + env_off
        self.auxv_start = aux_off << (2 if self.is_32bit else 3)

        end_off = self.setup_auxv(aux_off, exe)

        self.setup_debug(env_off, aux_off, end_off, show_stack)

    def setup_auxv(self, off, exe):
        auxv_ptr = self.base + off

        at_sysinfo_ehdr = getauxval(Stack.AT_SYSINFO_EHDR)
        at_sysinfo = getauxval(Stack.AT_SYSINFO)
        logging.debug("vDSO loaded at 0x%.8x (Auxv entry AT_SYSINFO_EHDR), AT_SYSINFO: 0x%.8x" % (at_sysinfo_ehdr, at_sysinfo))

        at_clktck = getauxval(Stack.AT_CLKTCK)
        at_hwcap = getauxval(Stack.AT_HWCAP)
        at_hwcap2 = getauxval(Stack.AT_HWCAP2)
        logging.debug("Auxv entries: HWCAP=0x%.8x, HWCAP2=0x%.8x, AT_CLKTCK=0x%.8x" %
                      (at_hwcap, at_hwcap2, at_clktck))

        platform_str = ctypes.create_string_buffer(b"x86_64")
        self.add_ref(platform_str)
        at_platform = ctypes.addressof(platform_str)

        # the first reference is argv[0] which is the pathname used to execute the binary
        at_execfn = ctypes.addressof(self.refs[0])

        # AT_BASE, AT_PHDR, AT_ENTRY will be fixed up later by the jumpcode as
        # at this point in time we don't know yet where everything will be
        # loaded in memory. Please note that they should remain at their
        # current positions in the auxv vector or else the offsets used when
        # fixing up auxv in the jumpcode need to be changed as well. The
        # offsets are defined in OFFSET_AT_BASE, OFFSET_AT_PHDR and
        # OFFSET_AT_ENTRY respectively.
        #
        # We could use collections.OrderedDirect() but that means we would only
        # be able to support Python 2.7. This is also meant to be able to be
        # used on older very out-of-date CPython installations so we just use a
        # list with 2-tuples so we remain ordered. Ordering also needs to be
        # preserved as it seems some versions of ld seem to expect that lest we
        # get a failed assertion `GL(dl_rtld_map).l_libname' failed from the
        # linker when using Python 2.7.
        auxv = []
        auxv.append((Stack.AT_BASE, 0x0))
        auxv.append((Stack.AT_PHDR, 0x0))
        auxv.append((Stack.AT_ENTRY, 0x0))
        auxv.append((Stack.AT_PHNUM, exe.e_phnum))
        auxv.append((Stack.AT_PHENT, exe.e_phentsize))
        auxv.append((Stack.AT_PAGESZ, PAGE_SIZE))
        auxv.append((Stack.AT_SECURE, 0))
        auxv.append((Stack.AT_RANDOM, auxv_ptr))  # XXX now just points to start of auxv
        auxv.append((Stack.AT_SYSINFO, at_sysinfo))
        auxv.append((Stack.AT_SYSINFO_EHDR, at_sysinfo_ehdr))
        auxv.append((Stack.AT_PLATFORM, at_platform))
        auxv.append((Stack.AT_EXECFN, at_execfn))
        auxv.append((Stack.AT_UID, os.getuid()))
        auxv.append((Stack.AT_EUID, os.geteuid()))
        auxv.append((Stack.AT_GID, os.getgid()))
        auxv.append((Stack.AT_EGID, os.getegid()))

        if at_clktck != 0:
            auxv.append((Stack.AT_CLKTCK, at_clktck))
        if at_hwcap != 0:
            auxv.append((Stack.AT_HWCAP, at_hwcap))
        if at_hwcap2 != 0:
            auxv.append((Stack.AT_HWCAP2, at_hwcap2))

        # always end with this
        auxv.append((Stack.AT_NULL, 0))

        stack = self.stack
        for at_type, at_val in auxv:
            stack[off] = at_type
            stack[off + 1] = at_val
            off = off + 2
        off = off - 1
        return off

    def setup_debug(self, env_off, aux_off, end, show_stack=False):
        # stack is shown if user explicitly asks for it or if we are in
        # debugging mode
        if not show_stack:
            return
        log = logging.info
        stack = self.stack
        log("stack contents:")
        log(" argv")

        # create dict with AT_ flags for nicer display of auxv entries below
        at_names = {}
        for name in [x for x in dir(Stack) if x.startswith("AT_")]:
            at_names[getattr(Stack, name)] = name

        for i in range(0, end + 1):
            if i == env_off:
                log(" envp")
            elif i >= aux_off:
                if i == aux_off:
                    log(" auxv")
                if (i - aux_off) % 2 == 1:
                    val = stack[i - 1]
                    name = at_names[val]
                    if self.is_32bit:
                        log("  %.8x:   0x%.8x 0x%.8x (%s)" % ((i - 1) * 4, val, stack[i], name))
                    else:
                        log("  %.8x:   0x%.16x 0x%.16x (%s)" % ((i - 1) * 8, val, stack[i], name))
            else:
                if self.is_32bit:
                    log("  %.8x:   0x%.8x" % (i * 4, stack[i]))
                else:
                    log("  %.8x:   0x%.16x" % (i * 8, stack[i]))


class CodeGenerator:
    def __init__(self, exe, interp=None):
        if interp:
            assert(exe.e_machine == interp.e_machine)
        self.exe = exe
        self.interp = interp

    @staticmethod
    def get_code_generator(exe, interp=None):
        machines = {EM_386: CodeGenX86, EM_X86_64: CodeGenX86_64}
        keys = machines.keys()
        assert(exe.e_machine in keys)
        if interp:
            assert(interp.e_machine in keys)
            assert(exe.e_machine == interp.e_machine)
        return machines[exe.e_machine](exe, interp)

    def log(self, logline):
        logging.debug("%s" % (logline))

    def generate_elf_loader(self, elf):
        PF_R = 0x4
        PF_W = 0x2
        PF_X = 0x1

        ret = []

        # munmap and then generate the mmap call so we have space to write to
        addr = 0x0 if elf.is_pie else elf.ph_entries[0]["vaddr"]
        map_sz = elf.map_size()
        prot = PROT_WRITE | PROT_EXEC | PROT_READ
        flags = MAP_ANONYMOUS | MAP_PRIVATE

        # align values properly
        addr = PAGE_FLOOR(addr)
        map_sz = PAGE_CEIL(map_sz)

        # generate munmap() and mmap() calls
        code = self.munmap(addr, map_sz)
        ret.append(code)
        code = self.mmap(addr, map_sz, prot, flags)
        ret.append(code)

        # loop over the program header entries, generate the copy code as well
        # as the mprotect() call to set the page protection flags correctly
        for e in elf.ph_entries:
            src = ctypes.addressof(e["data"])
            sz, vaddr, flags = e["filesz"], e["vaddr"], e["flags"]

            if not elf.is_pie:
                vaddr -= elf.ph_entries[0]["vaddr"]

            code = self.memcpy_from_offset(vaddr, src, sz)
            ret.append(code)

            prot = PROT_READ if (flags & PF_R) != 0 else 0
            prot |= (PROT_WRITE if (flags & PF_W) != 0 else 0)
            prot |= (PROT_EXEC if (flags & PF_X) != 0 else 0)

            # TODO: implement mprotect() call to properly setup protection
            # flags againfor memory segments
            # code = self.mprotect(dst, PAGE_CEIL(memsz), prot)
            # ret.append(code)

        return b"".join(ret)

    def generate(self, stack, jump_delay=None):
        # generate jump buffer with the CPU instructions which copy all
        # segments to the right locations in memory, set the correct protection
        # flags on those memory segments and then prepare for the actual jump
        # into hail mary land.

        # generate ELF loading code for the executable as well as the
        # interpreter if necessary
        ret = []
        code = self.generate_elf_loader(self.exe)
        ret.append(code)

        # fix up the auxv vector with the proper relative addresses too
        code = self.generate_auxv_fixup(stack, Stack.OFFSET_AT_PHDR, self.exe.e_phoff)
        ret.append(code)

        # fix up the auxv vector with the proper relative addresses too
        code = self.generate_auxv_fixup(stack, Stack.OFFSET_AT_ENTRY, self.exe.e_entry, self.exe.is_pie)
        ret.append(code)

        if self.interp:
            code = self.generate_elf_loader(self.interp)
            ret.append(code)
            code = self.generate_auxv_fixup(stack, Stack.OFFSET_AT_BASE, 0)
            ret.append(code)
            entry_point = self.interp.e_entry
        else:
            entry_point = self.exe.e_entry
            if not self.exe.is_pie:
                entry_point -= self.exe.ph_entries[0]["vaddr"]

        self.log("Generating jumpcode with entry_point=0x%.8x and stack=0x%.8x" % (entry_point, stack.base))

        code = self.generate_jumpcode(stack.base, entry_point, jump_delay)
        ret.append(code)

        return b"".join(ret)

    def mprotect(self, addr, length, prot):
        raise NotImplementedError

    def munmap(self, addr, length):
        raise NotImplementedError

    def memcpy_from_offset(self, off, src, sz):
        raise NotImplementedError

    def mmap(self, addr, length, prot, flags, fd=0xffffffff, offset=0):
        raise NotImplementedError

    def generate_auxv_fixup(self, stack, auxv_offset, map_offset, relative=True):
        raise NotImplementedError


class CodeGenX86(CodeGenerator):
    def __init__(self, exe, interp=None):
        assert(exe.e_machine == EM_386)
        if interp:
            assert(interp.e_machine == EM_386)
        CodeGenerator.__init__(self, exe, interp)

    def mprotect(self, addr, length, prot):
        raise NotImplementedError

    def munmap(self, addr, length):
        """
        b8 0b 00 00 00       	mov    $0xb,%eax
        bb 66 66 00 00       	mov    $0x6666,%ebx
        51                   	push   %ecx
        b9 42 42 00 00       	mov    $0x4242,%ecx
        cd 80                	int    $0x80
        59                      pop    %ecx
        """
        buf = b"\xb8\x5b\x00\x00\x00\xbb%s\x51\xb9%s\xcd\x80\x59" % (
            struct.pack("<L", addr),
            struct.pack("<L", length)
        )
        return buf

    def memcpy_from_offset(self, off, src, sz):
        """
        be 41 41 41 41       	mov    $0x41414141,%esi
        bf 42 42 42 42       	mov    $0x42424242,%edi
        01 cf                	add    %ecx,%edi
        51                   	push   %ecx
        b9 00 01 00 00       	mov    $0x100,%ecx
        f3 a4                	rep movsb %ds:(%esi),%es:(%edi)
        59                   	pop    %ecx
        """
        buf = b"\xbe%s\xbf%s\x01\xcf\x51\xb9%s\xf3\xa4\x59" % (
            struct.pack("<L", src),
            struct.pack("<L", off),
            struct.pack("<L", sz),
        )
        self.log("Generated memcpy call (dst=%%ecs + 0x%.8x, src=0x%.8x, size=0x%.8x)" % (off, src, sz))
        return buf

    def mmap(self, addr, length, prot, flags, fd=0xffffffff, offset=0):
        """
        b8 5a 00 00 00       	mov    $0x5a,%eax
        68 00 10 00 00          push $0x1000
        89 e3                	mov    %esp,%ebx
        cd 80                	int    $0x80
        89 c1                	mov    %eax,%ecx
        """

        # push eax + save return value to where exactly? what register
        # can we use?

        # for x86 we need to push all arguments on the stack as mmap() gets
        # more arguments than there are registers
        insts = [b"\xb8\x5a\x00\x00\x00"]

        # reverse order the structure onto the stack
        args = (offset, fd, flags, prot, length, addr)
        for arg in args:
            insts.append(b"\x68%s" % struct.pack("<L", arg))

        insts.append(b"\x89\xe3\xcd\x80\x89\xc1")
        self.log("Generated mmap call (addr=0x%.8x, length=0x%.8x, prot=0x%x, flags=0x%x)" % (addr, length, prot, flags))
        return b"".join(insts)

    def generate_auxv_fixup(self, stack, auxv_offset, map_offset, relative=True):
        """
        b8 44 43 42 41       	mov    $0x41424344,%eax
        01 c8                	add    %ecx,%eax
        bb 54 53 52 51       	mov    $0x51525354,%ebx
        89 03                	mov    %eax,(%ebx)
        """
        # write at location within auxv the value %ecx + map_offset
        auxv_ptr = stack.base + stack.auxv_start + (auxv_offset << 2)
        ret = []
        ret.append(b"\xb8%s" % struct.pack("<L", map_offset))
        if relative:
            ret.append(b"\x01\xc8")
        ret.append(b"\xbb%s\x89\x03" % (struct.pack("<L", auxv_ptr)))
        return b"".join(ret)

    def generate_jumpcode(self, stack_ptr, entry_ptr, jump_delay=False):
        buf = []
        if jump_delay:
            """
            51                   	push   %ecx
            6a 00                	push   $0x0
            68 42 41 41 00       	push   $0x414142
            89 e3                	mov    %esp,%ebx
            b9 00 00 00 00       	mov    $0x0,%ecx
            b8 a2 00 00 00       	mov    $0xa2,%eax
            89 e3                	mov    %esp,%ebx
            cd 80                	int    $0x80
            59                   	pop    %ecx
            59                   	pop    %ecx
            59                   	pop    %ecx
            """
            jd = struct.pack("<L", jump_delay)
            buf.append(b"\x51\x6a\x00\x68%s\x89\xe3\xb8\x00\x00\x00\x00" % jd)
            buf.append(b"\xb8\xa2\x00\x00\x00\x89\xe3\xcd\x80\x59\x59\x59")

        # reset main registers (%eax, %ebx, %edx, %ebp, %esp, %esi, %edi) just to be sure and we
        # do not reset %ecx as that will contain the pointer to our entrypoint
        main_regs = [b"\xc0", b"\xdb", b"\xd2", b"\xed", b"\xe4", b"\xf6", b"\xff"]
        for reg in main_regs:
            buf.append(b"\x31%s" % reg)

        """
        bc 44 43 42 41       	mov    $0x41424344,%esp
        81 c1 34 12 00 00    	add    $0x1234,%ecx
        ff e1                	jmp    *%ecx
        """
        buf.append(b"\xbc%s\x81\xc1%s\xff\xe1" % (
            struct.pack("<L", stack_ptr),
            struct.pack("<L", entry_ptr))
        )

        self.log("Jumpbuf with entry %%ecx+0x%x and stack: 0x%.8x" % (entry_ptr, stack_ptr))
        return b"".join(buf)


class CodeGenX86_64(CodeGenerator):

    def __init__(self, exe, interp=None):
        assert(exe.e_machine == EM_X86_64)
        if interp:
            assert(interp.e_machine == EM_X86_64)
        CodeGenerator.__init__(self, exe, interp)

    def generate_auxv_fixup(self, stack, auxv_offset, map_offset, relative=True):
        """
        49 be 48 47 46 45 44    movabs $0x4142434445464748,%r14
        43 42 41
        4d 01 de                add    %r11,%r14
        49 bf 11 11 11 11 11    movabs $0x1111111111111111,%r15
        11 11 11
        4d 89 37                mov    %r14,(%r15)
        """
        # write at location within auxv the value %r11 + map_offset
        auxv_ptr = stack.base + stack.auxv_start + (auxv_offset << 3)
        ret = []
        ret.append(b"\x49\xbe%s" % struct.pack("<Q", map_offset))
        if relative:
            ret.append(b"\x4d\x01\xde")
        ret.append(b"\x49\xbf%s\x4d\x89\x37" % (struct.pack("<Q", auxv_ptr)))
        return b"".join(ret)

    def generate_jumpcode(self, stack_ptr, entry_ptr, jump_delay=False):
        buf = []
        if jump_delay:
            """
            6a 00                   pushq  $0x0
            68 c8 01 00 00          pushq  $0x1c8
            48 89 e7                mov    %rsp,%rdi
            48 c7 c0 23 00 00 00    mov    $0x23,%rax
            41 53                   push %r11
            0f 05                   syscall
            41 5b                   pop %r11
            """
            jd = struct.pack("<L", jump_delay)
            buf.append(b"\x6a\x00\x68%s\x48\x89\xe7\x48\xc7\xc0\x23\x00\x00\x00" % jd)
            buf.append(b"\x41\x53\x0f\x05\x41\x5b")

        # reset main registers (%rax, %rbx, %rcx, %rdx, %rbp, %rsp, %rsi, %rdi) just to be sure
        main_regs = [b"\xc0", b"\xdb", b"\xc9", b"\xd2", b"\xed", b"\xe4", b"\xf6", b"\xff"]
        for reg in main_regs:
            buf.append(b"\x48\x31%s" % reg)

        buf.append(b"\x48\xbc%s\x48\xb9%s\x4c\x01\xd9\x48\x31\xd2\xff\xe1" % (
            struct.pack("<Q", stack_ptr),
            struct.pack("<Q", entry_ptr))
        )
        self.log("Jumpbuf with entry %%r11+0x%x and stack: 0x%.16x" % (entry_ptr, stack_ptr))
        return b"".join(buf)

    def memcpy_from_offset(self, off, src, sz):
        """
        48 bf 48 47 46 45 44    movabs $0x4142434445464748,%rdi
        43 42 41
        4c 01 df                add    %r11,%rdi
        """
        # TODO fix up the comment above
        buf = b"\x48\xbe%s\x48\xbf%s\x4c\x01\xdf\x48\xb9%s\xf3\xa4" % (
            struct.pack("<Q", src),
            struct.pack("<Q", off),
            struct.pack("<Q", sz)
        )
        self.log("Generated memcpy call (dst=%%r11 + 0x%.8x, src=0x%.8x, size=0x%.8x)" % (off, src, sz))
        return buf

    def mmap(self, addr, length, prot, flags, fd=0xffffffff, offset=0):
        """
        48 c7 c0 09 00 00 00    mov    $0x9,%rax
        48 bf 66 66 66 66 66    movabs $0x6666666666666666,%rdi  ; addr
        66 66 66
        48 be 52 52 52 52 42    movabs $0x4242424252525252,%rsi  ; length
        42 42 42
        48 c7 c2 7b 00 00 00    mov    $0x7b,%rdx     ; prot
        49 c7 c2 9a 02 00 00    mov    $0x29a,%r10    ; flags
        49 c7 c0 ff ff ff ff    mov    $0xffffffffffffffff,%r8 ; fd
        49 c7 c1 00 00 00 00    mov    $0x0,%r9  ; offset
        0f 05                   syscall
        50                      push   %rax
        4c 8b 1c 24             mov    (%rsp),%r11
        """
        # we store the mmap() result in %r11
        buf = b"\x48\xc7\xc0\x09\x00\x00\x00\x48\xbf%s\x48\xbe%s\x48\xc7\xc2%s\x49\xc7\xc2%s\x49\xc7\xc0%s\x49\xc7\xc1%s\x0f\x05\x50\x4c\x8b\x1c\x24" % (
            struct.pack("<Q", addr),
            struct.pack("<Q", length),
            struct.pack("<L", prot),
            struct.pack("<L", flags),
            struct.pack("<L", fd),
            struct.pack("<L", offset)
        )
        self.log("Generated mmap call (addr=0x%.8x, length=0x%.8x, prot=0x%x, flags=0x%x)" % (addr, length, prot, flags))
        return buf

    def mprotect(self, addr, length, prot):
        """
        48 c7 c0 0a 00 00 00    mov    $0xa,%rax
        48 bf 41 41 41 41 41    movabs $0x41414141414141,%rdi
        41 41 00
        48 be 42 42 42 42 42    movabs $0x42424242424242,%rsi
        42 42 00
        48 c7 c2 04 00 00 00    mov    $0x4,%rdx
        0f 05                   syscall
        48 31 c0                xor %rax, %rax
        """
        buf = b"\x48\xc7\xc0\x0a\x00\x00\x00\x48\xbf%s\x48\xbe%s\x48\xc7\xc2%s\x0f\x05" % (
            struct.pack("<Q", addr),
            struct.pack("<Q", length),
            struct.pack("<L", prot),
        )
        return buf

    def munmap(self, addr, length):
        """
        48 c7 c0 0b 00 00 00    mov    $0xb,%rax
        48 bf 66 66 66 66 66    movabs $0x6666666666666666,%rdi  ; addr
        66 66 66
        48 be 52 52 52 52 42    movabs $0x4242424252525252,%rsi  ; length
        42 42 42
        0f 05                   syscall
        """
        buf = b"\x48\xc7\xc0\x0b\x00\x00\x00\x48\xbf%s\x48\xbe%s\x0f\x05" % (
            struct.pack("<Q", addr),
            struct.pack("<Q", length)
        )
        return buf


class ELFExecutor:
    def __init__(self, binstream, binname):
        # XXX check if ELF machine type is same as calling code
        # else we will fail due to ctypes size mismatch anyway
        binstream.seek(0)
        try:
            exe = ELFParser(binstream)
        except ELFParsingError as e:
            logging.error("Error while parsing binary: %s" % e)
            raise e

        self.binname = binname
        self.exe = exe
        if not self.exe.interp:
            self.interp = None
            return

        self.log("Dynamic executable so loading interpreter from %s" %
                 self.exe.interp.decode("utf-8", errors="ignore"))
        with open(self.exe.interp, "rb") as fd:
            try:
                interp = ELFParser(fd)
            except ELFParsingError as e:
                self.log("Error while parsing interpreter: %s" % e)
                raise e

        self.log("Loaded interpreter successfully")
        self.interp = interp

    def log(self, logline):
        logging.debug("%s" % (logline))

    def execute(self, args, show_jumpbuf=False, show_stack=False, jump_delay=None):
        # construct a stack with 2k pages, pass argv, envp and build it up
        self.stack = stack = Stack(2048, self.exe.is_32bit)
        argv = [self.binname] + args
        envp = []
        for name in os.environ:
            envp.append("%s=%s" % (name, os.environ[name]))
        stack.setup(argv, envp, self.exe, show_stack=show_stack)

        # run the code generator to build up the jump buffer
        cg = CodeGenerator.get_code_generator(self.exe, self.interp)
        jumpbuf = cg.generate(stack, jump_delay)

        if show_jumpbuf:
            # we just pass in the e_machine from the ELF executable so the display routine
            # can properly set the arguments for the external call to objdump
            display_jumpbuf(self.exe.e_machine, jumpbuf)

        # The full buffer of instructions was setup, now all we need to do is
        # map this to memory and set it such that that segment is executable so
        # we can jump into it: we never return from this as we will either
        # crash and burn with a SIGSEGV or the loaded ELF will simply be
        # properly executed. Let's hope for the latter.
        cfunction = prepare_jumpbuf(jumpbuf)
        cfunction()


class MemFdExecutor:
    def __init__(self, binstream, binname):
        self.binname = binname

        binstream.seek(0)
        self.bindata = binstream.read()

    @staticmethod
    def _get_memfd_create_fn():
        argtypes = [c_char_p, c_uint]
        restype = c_int
        try:
            memfd_create = libc.memfd_create
            memfd_create.argtypes = argtypes
            memfd_create.restype = restype
        except AttributeError:
            sc = libc.syscall
            sc.argtypes = [c_long] + argtypes
            sc.restype = restype

            machine = os.uname().machine
            if machine == "x86_64":
                syscall_no = 319
            elif machine == "x86":
                syscall_no = 356
            else:
                raise ValueError("unsupported machine type returned: %s" % machine)

            def fn(*args):
                return sc(syscall_no, *args)

            memfd_create = fn
        return memfd_create

    @staticmethod
    def _get_fexecve_fn():
        try:
            fexecve = libc.fexecve
            fexecve.argtypes = [c_int, POINTER(c_char_p), POINTER(c_char_p)]
            fexecve.restype = c_int
        except AttributeError:
            logging.error("fexecve() not defined (glibc older than 2.3.2 or non-glibc system?)")
            sys.exit(1)
        return fexecve

    def execute(self, args, *kwargs):
        # setup references to libc functions we need
        memfd_create = MemFdExecutor._get_memfd_create_fn()
        fexecve = MemFdExecutor._get_fexecve_fn()

        # the filename is only for debugging purposes so we won't even bother setting it
        MFD_CLOEXEC = 0x1
        fd = memfd_create(b"", MFD_CLOEXEC)
        if fd == -1:
            raise RuntimeError("memfd_create() failed")
        sz = len(self.bindata)
        ret = libc.write(fd, self.bindata, sz)
        if ret != sz:
            raise RuntimeError("write() failed to write all bytes of binary")

        # setup argv and envp
        argv = [self.binname] + args
        envp = []
        for name in os.environ:
            envp.append("%s=%s" % (name, os.environ[name]))

        # UTF-8 encode to bytes and copy to ctypes managed char * array
        l_argv = [a.encode("utf-8", errors="ignore") for a in argv]
        l_envp = [e.encode("utf-8", errors="ignore") for e in envp]
        c_argv = (c_char_p * (len(l_argv) + 1))(*l_argv)
        c_envp = (c_char_p * (len(l_envp) + 1))(*l_envp)

        # call fexecve() which should not return if the target binary executes successfully
        fexecve(fd, c_argv, c_envp)

        # spit out error if we failed to execute
        no = ctypes.get_errno()
        logging.error("fexecve() failed: %s: %s" % (errno.errorcode[no], os.strerror(no)))
        sys.exit(1)


def main():

    parser = argparse.ArgumentParser(description="Attempt to execute an ELF binary in userland. Supply the path to the binary, any arguments to it and then sit back and pray.",
                                     usage="%(prog)s [options] <binary> [arguments]")

    parser.add_argument("--debug", action="store_true", help="output info useful for debugging a crashing binary")
    parser.add_argument("--fallback", action="store_true", help="use fallback method with memfd_create")
    parser.add_argument("--jump-delay", metavar="N", type=int, help="delay jump with N seconds to f.e. attach debugger")
    parser.add_argument("--show-jumpbuf", action="store_true", help="use objdump to show jumpbuf contents")
    parser.add_argument("--show-stack", action="store_true", help="show stack contents")
    parser.add_argument("--version", action="store_true", help="show version")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="<binary> [arguments] (eg. /bin/ls /tmp)")
    ns = parser.parse_args(sys.argv[1:])

    logging.basicConfig(format="%(message)s", level=logging.DEBUG if ns.debug else logging.INFO)

    if ns.version:
        print("%s v%s" % (os.path.basename(__file__).split(".")[0], __version__))
        sys.exit(1)

    if len(ns.command) == 0:
        parser.print_help()
        sys.exit(1)

    if ns.fallback:
        if ns.jump_delay:
            logging.error("cannot use --jump-delay with --fallback")
            sys.exit(1)
        if ns.show_jumpbuf:
            logging.error("cannot use --show-jumpbuf with --fallback")
            sys.exit(1)
        if ns.show_stack:
            logging.error("cannot use --show-stack with --fallback")
            sys.exit(1)

    if ns.jump_delay:
        if ns.jump_delay < 0:
            logging.error("jump delay cannot be negative")
            sys.exit(1)
        elif ns.jump_delay > 300:
            logging.error("jump delay cannot be bigger than 300")
            sys.exit(1)

    # sanity check where we are being run
    if os.name != "posix" or os.uname().sysname.lower() != "linux":
        logging.error("this only works on Linux-based operating systems")
        sys.exit(1)

    binary = ns.command[0]
    args = ns.command[1:]

    if binary == "-":
        binfd = _readbytes_from_stdin()
        binary = "<stdin>"
    else:
        binfd = open(binary, "rb")

    if ns.fallback:
        executor = MemFdExecutor(binfd, binary)
    else:
        executor = ELFExecutor(binfd, binary)

    binfd.close()
    executor.execute(args, ns.show_jumpbuf, ns.show_stack, ns.jump_delay)


if __name__ == "__main__":
    main()
