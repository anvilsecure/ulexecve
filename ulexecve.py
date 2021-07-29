#!/usr/bin/env python

"""
"""

import argparse
import ctypes
import logging
import os
import struct
import subprocess
import sys
import tempfile
from ctypes import c_int, c_size_t, c_void_p, c_ulong, memmove
from ctypes.util import find_library

libc = ctypes.CDLL(find_library('c'))

PAGE_SIZE = ctypes.pythonapi.getpagesize()


def PAGE_FLOOR(addr):
    return (addr) & (-PAGE_SIZE)


def PAGE_CEIL(addr):
    return (PAGE_FLOOR((addr) + PAGE_SIZE - 1))


# TODO: if we run on glibc older than 2.16 we would not have getauxval(), we
# could then try to emulate it by reading from /proc/<pid>/auxv. That glibc is
# from late 2012 though so do we want to support old glibc as well?
getauxval = libc.getauxval
getauxval.argtypes = [c_ulong]
getauxval.restype = c_ulong

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
ET_EXEC = 0x2
ET_DYN = 0x3
EM_X86_64 = 0x3e


def display_jumpbuf(buf):
    with tempfile.NamedTemporaryFile(suffix=".jumpbuf.bin", mode="wb") as tmp:
        tmp.write(buf)
        tmp.seek(0)
        logging.debug("Written jumpbuf to %s" % tmp.name)
        # To disassemble run the following command with temp filename  appended to it
        cmd = "objdump -m i386:x86-64 -b binary -D %s" % tmp.name
        logging.debug("Executing: %s" % cmd)
        try:
            output = subprocess.check_output(cmd.split(" "))
        except OSError as e:
            logging.error("Error while trying to disassemble: objdump not found in $PATH")
            sys.exit(1)

        logging.info(output.decode("utf-8", errors="ignore"))


def prepare_jumpbuf(buf):
    dst = mmap(0, PAGE_CEIL(len(buf)), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    src = ctypes.create_string_buffer(buf)
    logging.debug("Memmove(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, ctypes.addressof(src), len(buf)))
    ret = memmove(dst, src, len(buf))
    ret = mprotect(PAGE_FLOOR(dst), PAGE_CEIL(len(buf)), PROT_READ | PROT_EXEC)

    return ctypes.cast(dst, ctypes.CFUNCTYPE(c_void_p))


class ELFParsingError(Exception):
    pass


class ELFParser:

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
        if bittype == b"\x01":
            raise ELFParsingError("Not implemented 32-bit ELF parsing")
        elif bittype != b"\x02":
            raise ELFParsingError("Unknown EI class specified")

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
        values, buf = self.unpack("HHIQQQIHHHHHH")
        self.e_type, self.e_machine, self.e_version, self.e_entry, \
            self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, \
            self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx = values
        self.ehdr = buf

        if self.e_type != ET_EXEC and self.e_type != ET_DYN:
            raise ELFParsingError("ELF is not an executable or shared object file")

        if self.e_phnum == 0:
            raise ELFParsingError("No program headers found in ELF")

        if self.e_machine != EM_X86_64:
            raise ELFParsingError("ELF machine type is not x86-64")

    def parse_pentries(self):
        self.stream.seek(self.e_phoff)
        for _ in range(self.e_phnum):
            self.parse_pentry()

    def parse_pentry(self):
        values, _ = self.unpack("IIQQQQQQ")
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
            pentry = {"flags":p_flags, "memsz":p_memsz, "vaddr":p_vaddr, "filesz":p_filesz, "offset":p_offset, "data":data}
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

    AT_NULL = 0
    AT_PHDR = 3
    AT_PHENT = 4
    AT_PHNUM = 5
    AT_PAGESZ = 6
    AT_BASE = 7
    AT_ENTRY = 9
    AT_SECURE = 23
    AT_RANDOM = 25
    AT_SYSINFO = 32
    AT_SYSINFO_EHDR = 33

    def __init__(self, num_pages):
        self.size = 2048 * PAGE_SIZE
        self.base = mmap(0, self.size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0)
        ctypes.memset(self.base, 0, self.size)

        # stack grows down so start of stack needs to be adjusted
        self.base += (self.size - PAGE_SIZE)
        self.stack = (ctypes.c_size_t * PAGE_SIZE).from_address(self.base)
        logging.debug("Stack allocated at: 0x%.8x" % (self.base))
        self.refs = []

        self.auxv_start = 0

    def add_ref(self, obj):
        # we simply add the object to the list so that the garbage collector
        # cannot throw havoc on us here; this way the ctypes object will stay
        # in memory properly as there will be a reference to it
        self.refs.append(obj)

    def setup(self, argv, envp, exe, show_stack=False):
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
        self.auxv_start = aux_off << 3

        end_off = self.setup_auxv(aux_off, exe)

        self.setup_debug(env_off, aux_off, end_off, show_stack)

    def setup_auxv(self, off, exe):
        auxv_ptr = self.base + off

        at_sysinfo_ehdr = getauxval(Stack.AT_SYSINFO_EHDR)
        logging.debug("Auxv entry AT_SYSINFO_EHDR (vDSO) set to: 0x%.8x" % (at_sysinfo_ehdr))

        stack = self.stack
        """
AT_UID:               1000
AT_EUID:              1000
AT_GID:               1000
AT_EGID:              1000
"""
        # TODO:
        # add AT_CLKTCK, AT_HWCAP, AT_HWCAP2 (since glibc 2.18) only if they're non-zero
        # copy AT_PLATFORM as well (which is a string f.e. x86_64)
        # set up AT_EXECFN properly (points to string f.e. /usr/bin/sleep)
        # set up AT_UID, AT_EUID, AT_GID, AT_EGID 

        # AT_BASE, AT_PHDR, AT_ENTRY will be fixed up later by the jumpcode as
        # at this point in time we don't know yet where everything will be
        # loaded in memory
        stack[off] = Stack.AT_BASE
        stack[off + 1] = 0x0
        stack[off + 2] = Stack.AT_PHDR
        stack[off + 3] = 0x0
        stack[off + 4] = Stack.AT_ENTRY
        stack[off + 5] = 0x0
        stack[off + 6] = Stack.AT_PHNUM
        stack[off + 7] = exe.e_phnum
        stack[off + 8] = Stack.AT_PHENT
        stack[off + 9] = exe.e_phentsize
        stack[off + 10] = Stack.AT_PAGESZ
        stack[off + 11] = PAGE_SIZE
        stack[off + 12] = Stack.AT_SECURE
        stack[off + 13] = 0
        stack[off + 14] = Stack.AT_RANDOM
        stack[off + 15] = auxv_ptr  # (should be set to start of auxv for stack cookies)
        stack[off + 16] = Stack.AT_SYSINFO  # should be not present or simply zero on x86-64
        stack[off + 17] = 0
        stack[off + 18] = Stack.AT_SYSINFO_EHDR
        stack[off + 19] = at_sysinfo_ehdr
        stack[off + 20] = Stack.AT_NULL
        stack[off + 21] = 0

        return off + 21

    def setup_debug(self, env_off, aux_off, end, show_stack = False):
        # stack is shown if user explicitly asks for it or if we are in
        # debugging mode
        if not show_stack:
            return
        log = logging.info
        stack = self.stack
        ret = []
        log("stack contents:")
        log(" argv")
        for i in range(0, end):
            if i == env_off:
                log(" envp")
            elif i >= aux_off:
                if i == aux_off:
                    log(" auxv")
                if (i - aux_off) % 2 == 1:
                    log("  %.8x:   0x%.16x 0x%.16x" % ((i-1)*8, stack[i-1], stack[i]))
            else:
                log("  %.8x:   0x%.16x" % (i*8, stack[i]))


class CodeGenerator:
    def __init__(self, exe, interp=None):
        assert(exe.e_machine == EM_X86_64)
        if interp:
            assert(interp.e_machine == EM_X86_64)
        self.exe = exe
        self.interp = interp

    def log(self, logline):
        logging.debug("%s" % (logline))

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
        code = self.generate_auxv_fixup(stack, (3 << 3), self.exe.e_phoff)
        ret.append(code)

        # fix up the auxv vector with the proper relative addresses too
        code = self.generate_auxv_fixup(stack, (5 << 3), self.exe.e_entry, self.exe.is_pie)
        ret.append(code)

        if self.interp:
            code = self.generate_elf_loader(self.interp)
            ret.append(code)
            code = self.generate_auxv_fixup(stack, (1 << 3), 0)
            ret.append(code)
            entry_point = self.interp.e_entry
        else:
            entry_point = self.exe.e_entry
            if not self.exe.is_pie:
                entry_point -= self.exe.ph_entries[0]["vaddr"]

        self.log("Generating jumpcode with entry_point=0x%.16x and stack=0x%.16x" % (entry_point, stack.base))

        code = self.generate_jumpcode(stack.base, entry_point, jump_delay)
        ret.append(code)

        return b"".join(ret)

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
        auxv_ptr = stack.base + stack.auxv_start + auxv_offset
        ret = []
        ret.append(b"\x49\xbe%s" % struct.pack("<Q", map_offset))
        if relative:
            ret.append(b"\x4d\x01\xde")
        ret.append(b"\x49\xbf%s\x4d\x89\x37" % (struct.pack("<Q", auxv_ptr)))
        return b"".join(ret)

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
            sz, memsz, vaddr, flags = e["filesz"], e["memsz"], e["vaddr"], e["flags"]

            if not elf.is_pie:
                vaddr -= elf.ph_entries[0]["vaddr"]

            code = self.memcpy_from_offset(vaddr, src, sz)
            ret.append(code)

            prot = PROT_READ if (flags & PF_R) != 0 else 0
            prot |= (PROT_WRITE if (flags & PF_W) != 0 else 0)
            prot |= (PROT_EXEC if (flags & PF_X) != 0 else 0)

            #code = self.mprotect(dst, PAGE_CEIL(memsz), prot)
            #ret.append(code)

        return b"".join(ret)

    def generate_jumpcode(self, stack_ptr, entry_ptr, jump_delay=False):
        buf = b""
        if jump_delay:
            """
            48 31 f6                xor    %rsi,%rsi
            56                      push   %rsi
            68 55 a0 fc 01          pushq  $0x1fca055
            54                      push   %rsp
            5f                      pop    %rdi
            6a 23                   pushq  $0x23
            58                      pop    %rax
            0f 05                   syscall
            """
            buf += b"\x48\x31\xf6\x56\x68"
            buf += struct.pack("<L", jump_delay)
            buf += b"\x54\x5f\x6a\x23\x58\x0f\x05"

        buf += b"\x48\xbc%s\x48\xb9%s\x4c\x01\xd9\x48\x31\xd2\xff\xe1" % \
                (struct.pack("<Q", stack_ptr),
                 struct.pack("<Q", entry_ptr))
        self.log("Jumpbuf with entry %%r11+0x%x and stack: 0x%.16x" % (entry_ptr, stack_ptr))
        return buf

    def memcpy_from_offset(self, off, src, sz):
        """
        48 bf 48 47 46 45 44    movabs $0x4142434445464748,%rdi
        43 42 41
        4c 01 df                add    %r11,%rdi
        """
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
    def __init__(self, binary):
        with open(binary, "rb") as fd:
            try:
                exe = ELFParser(fd)
            except ELFParsingError as e:
                logging.error("Error while parsing binary: %s" % e)
                raise e

        self.binary = binary
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
        self.stack = stack = Stack(2048)
        argv = [self.binary] + args
        envp = []
        for name in os.environ:
            envp.append("%s=%s" % (name, os.environ[name]))
        stack.setup(argv, envp, self.exe, show_stack=show_stack)

        # run the code generator to build up the jump buffer
        cg = CodeGenerator(self.exe, self.interp)
        jumpbuf = cg.generate(stack, jump_delay)

        if show_jumpbuf:
            display_jumpbuf(jumpbuf)

        # The full buffer of instructions was setup, now all we need to do is
        # map this to memory and set it such that that segment is executable so
        # we can jump into it: we never return from this as we will either
        # crash and burn with a SIGSEGV or the loaded ELF will simply be
        # properly executed. Let's hope for the latter.
        cfunction = prepare_jumpbuf(jumpbuf)
        cfunction()

def main():
    parser = argparse.ArgumentParser(description="Attempt to execute an ELF binary in userland. Supply the path to the binary, any arguments to it and then sit back and pray.",
                                     usage="%(prog)s [options] <binary> [arguments]")

    parser.add_argument("--debug", action="store_true", help="output info useful for debugging a crashing binary")
    parser.add_argument("--show-jumpbuf", action="store_true", help="use objdump to show jumpbuf contents")
    parser.add_argument("--show-stack", action="store_true", help="show stack contents")
    parser.add_argument("--jump-delay", metavar="N", type=int, help="delay jump with N seconds to f.e. attach debugger")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="<binary> [arguments] (eg. /bin/ls /tmp)")
    ns = parser.parse_args(sys.argv[1:])

    logging.basicConfig(format="%(message)s", level=logging.DEBUG if ns.debug else logging.INFO)

    if len(ns.command) == 0:
        parser.print_help()
        sys.exit(1)

    if ns.jump_delay:
        if ns.jump_delay < 0:
            logging.error("jump delay cannot be negative")
            sys.exit(1)
        elif ns.jump_delay > 300:
            logging.error("jump delay cannot be bigger than 300")
            sys.exit(1)

    binary = ns.command[0]
    args = ns.command[1:]

    executor = ELFExecutor(binary)
    executor.execute(args, ns.show_jumpbuf, ns.show_stack, ns.jump_delay)

if __name__ == "__main__":
    main()
