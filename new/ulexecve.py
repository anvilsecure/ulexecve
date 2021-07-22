#!/usr/bin/env python

import argparse
import ctypes
import logging
import os
import struct
import subprocess
import sys
import tempfile
from ctypes import c_int, c_size_t, c_void_p, memmove
from ctypes.util import find_library

libc = ctypes.CDLL(find_library('c'))

mmap = libc.mmap
mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]
mmap.restype = c_void_p

mprotect = libc.mprotect
mprotect.argtypes = [c_void_p, c_size_t, c_int]
mprotect.restype = c_int

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
PROT_SEM = 0x8
MAP_PRIVATE = 0X02
MAP_ANONYMOUS = 0x20
MAP_GROWSDOWN = 0x0100

def bincode_memcpy(dst, src, sz):
    """
48 be 41 41 41 41 41    movabs $0x414141414141,%rsi  ; source
41 00 00
48 bf 61 61 61 61 61    movabs $0x616161616161,%rdi  ; destination
61 00 00
48 b9 90 90 90 90 90    movabs $0x909090909090,%rcx ; length
90 00 00
    """

    buf = b"\x48\xbe%s\x48\xbf%s\x48\xb9%s\xf3\xa4" % ( \
        struct.pack("<Q", src), \
        struct.pack("<Q", dst), \
        struct.pack("<Q", sz) \
    )
    logging.debug("memcpy(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, src, sz))
    return buf

def bincode_mprotect(addr, length, prot):
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
    buf = b"\x48\xc7\xc0\x0a\x00\x00\x00\x48\xbf%s\x48\xbe%s\x48\xc7\xc2%s\x0f\x05" % ( \
		struct.pack("<Q", addr), \
		struct.pack("<Q", length), \
		struct.pack("<L", prot), \
    )
    return buf

PAGE_SIZE = ctypes.pythonapi.getpagesize()

def PAGE_FLOOR(addr):
    return (addr) & (-PAGE_SIZE)

def PAGE_CEIL(addr):
    return (PAGE_FLOOR((addr) + PAGE_SIZE - 1))

class ELFParsingError(Exception):
    pass

class ELFParser:

    PT_LOAD = 0x1
    PT_INTERP = 3

    def __init__(self, stream):
        self.stream = stream
        self.is_pie = False
        self.interp_offset = 0
        self.interp = None
        self.mapping = None
        self.entry_point = 0
        self.ph_entries = []

    def parse(self):
        self.parse_head()
        self.parse_ehdr()
        self.parse_pentries()

    def parse_head(self):
        self.stream.seek(0)
        magic = self.stream.read(4)
        if magic != b"\x7fELF":
            raise ELFParsingError("not an ELF file")

        bittype = self.stream.read(1)
        if bittype == b"\x01":
            raise ELFParsingError("not implemented 32-bit ELF parsing")
        elif bittype != b"\x02":
            raise ELFParsingError("unknown EI class specified")

        b = self.stream.read(1)
        if b == b"\x01":
            self.little_endian = True
        elif b == b"\x02":
            self.little_endian = False
        else:
            raise ELFParsingError("unknown endiannes specified")

        # XXX: check arch type here

    def unpack(self, fmt):
        sz = struct.calcsize(fmt)
        buf = self.stream.read(sz)
        if self.little_endian:
            endian_str = "<"
        else:
            endian_str = ">"
        return (struct.unpack("%c%s" % (endian_str, fmt), buf), buf)

    def parse_ehdr(self):
        self.stream.seek(16)
        values, buf = self.unpack("HHIQQQIHHHHHH")
        self.e_type, self.e_machine, self.e_version, self.e_entry, \
            self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, \
            self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx = values
        self.ehdr = ctypes.create_string_buffer(buf)

    def parse_pentries(self):
        self.stream.seek(self.e_phoff)
        map_sz, adjust = 0, 0
        first_pt_load = True
        for i in range(0, self.e_phnum):
            values, buf = self.unpack("IIQQQQQQ")
            p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz = values[0], values[1], values[2], values[3], values[5], values[6]
            if p_type == ELFParser.PT_LOAD:
                if first_pt_load:
                    first_pt_load = False
                    if p_vaddr != 0:
                        adjust = p_vaddr
                    else:
                        self.is_pie = True
                map_sz = p_vaddr + p_memsz if (p_vaddr + p_memsz) > map_sz else map_sz
                logging.debug("total mapping is now 0x%08x based on 0x%08x seg at 0x%x" % (map_sz, p_memsz, p_vaddr))

                off = self.stream.tell()
                self.stream.seek(p_offset)
                data = ctypes.create_string_buffer(self.stream.read(p_filesz), p_filesz)
                self.stream.seek(off)

                pentry = {"flags":p_flags, "memsz":p_memsz, "vaddr":p_vaddr, "filesz":p_filesz, "offset":p_offset, "data":data}
                self.ph_entries.append(pentry)
            elif p_type == ELFParser.PT_INTERP:
                self.interp_offset = p_offset
                off = self.stream.tell()
                self.stream.seek(p_offset)
                self.interp = self.stream.read(p_filesz)

                # strip off the last byte as that is a 0-byte and it will cause
                # pathname encoding problems later otherwise
                self.interp = self.interp[:-1]
                self.stream.seek(off)
            else:
                continue

        if not self.is_pie:
            map_sz -= adjust

        mapping = mmap(PAGE_FLOOR(adjust), PAGE_CEIL(map_sz), PROT_READ | PROT_WRITE | PROT_SEM, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if mapping == -1:
            raise ELFParsingError("mmap() failed")

        self.mapping = mapping
        self.virtual_offset = mapping if adjust == 0 else 0
        self.entry_point = self.virtual_offset + self.e_entry

        logging.debug("mapping ELF at 0x%.16x (adjust: 0x%.16x, entry_point: 0x%.16x)" % (self.mapping, adjust, self.entry_point))


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

    def __init__(self, num_pages):
        self.size = 2048 * PAGE_SIZE
        self.base = mmap(0, self.size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0)
        ctypes.memset(self.base, 0, self.size)

        # stack grows down so start of stack needs to be adjusted
        self.base += (self.size - PAGE_SIZE)
        self.stack = (ctypes.c_size_t * PAGE_SIZE).from_address(self.base)
        logging.debug("stack allocated at: 0x%.8x" % (self.base))
        self.refs = []

    def add_ref(self, obj):
        # we simply add the object to the list so that the garbage collector
        # cannot throw havoc on us here; this way the ctypes object will stay
        # in memory properly as there will be a reference to it
        self.refs.append(obj)

    def setup(self, argv, envp, exe, interp=None):
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
        env_off = i+1

        # envp does not have a preceding count and is ultimately NULL terminated
        i = 0
        for env in envp:
            enc = arg.encode("utf-8", errors="ignore")
            buf = ctypes.create_string_buffer(enc)
            self.add_ref(buf)
            stack[i + env_off] = ctypes.addressof(buf)
            i = i + 1
        stack[i + env_off] = c_size_t(0)
        i = i + 1

        aux_off = i + env_off

        end_off = self.setup_auxv(aux_off, exe, interp)

        self.setup_debug(env_off, aux_off, end_off)

    def setup_auxv(self, off, exe, interp=None):
        auxv_ptr = self.base + (off << 3)
        exe_loc = exe.mapping
        interp_loc = interp.mapping if interp else exe_loc
        logging.debug("AT_BASE set to 0x%.16x from %s" % (interp_loc, "interp" if interp else "exe"))
        stack = self.stack
        stack[off] = Stack.AT_BASE
        stack[off + 1] = interp_loc
        stack[off + 2] = Stack.AT_PHDR
        stack[off + 3] = exe_loc + exe.e_phoff
        stack[off + 4] = Stack.AT_ENTRY
        stack[off + 5] = ((exe_loc + exe.e_entry) if exe.e_entry < exe_loc else exe.e_entry)
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
        stack[off + 16] = Stack.AT_NULL
        stack[off + 17] = 0
        return off + 17

    def setup_debug(self, env_off, aux_off, end):
        stack = self.stack
        logging.debug("stack contents:")
        logging.debug(" argv")
        for i in range(0, end):
            if i == env_off:
                logging.debug(" envp")
            elif i >= aux_off:
                if i == aux_off:
                    logging.debug(" auxv")
                if (i - aux_off) % 2 == 1:
                    logging.debug("  %.8x:   0x%.16x 0x%.16x" % ((i-1)*8, stack[i-1], stack[i]))
            else:
                logging.debug("  %.8x:   0x%.16x" % (i*8, stack[i]))


def bincode_jumpbuf(stack_ptr, entry_ptr, jump_delay=False):
    buf = b""
    if jump_delay:
        buf += b"""\x48\x31\xf6\x56\x6a\x03\x54\x5f\x6a\x23\x58\x0f\x05"""
        buf += b"\x48\x89\xe5"
    buf += b"\x48\xbc%s\x48\xb9%s\x48\x31\xd2\xff\xe1" % \
            (struct.pack("<Q", stack_ptr),
             struct.pack("<Q", entry_ptr))
    return buf

def prepare_jumpbuf(buf):
    dst = mmap(0, PAGE_CEIL(len(buf)), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    src = ctypes.create_string_buffer(buf)
    logging.debug("memmove(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, ctypes.addressof(src), len(buf)))
    ret = memmove(dst, src, len(buf))
    ret = mprotect(PAGE_FLOOR(dst), PAGE_CEIL(len(buf)), PROT_READ | PROT_EXEC)

    return ctypes.cast(dst, ctypes.CFUNCTYPE(c_void_p))

def display_jumpbuf(buf):
    with tempfile.NamedTemporaryFile(suffix=".jumpbuf.bin", mode="wb") as tmp:
        tmp.write(buf)
        tmp.seek(0)
        logging.debug("written jumpbuf to %s" % tmp.name)
        # To disassemble run the following with temp filename  appended to it
        cmd = "objdump -m i386:x86-64 -b binary -D %s" % tmp.name
        logging.debug("executing %s" % cmd)
        try:
            output = subprocess.check_output(cmd.split(" "))
        except OSError as e:
            logging.error("objdump not found in $PATH or not installed")
            sys.exit(1)

        logging.info(output.decode("utf-8", errors="ignore"))

def get_phentries_setup_code(exe):
    PF_R = 0x4
    PF_W = 0x2
    PF_X = 0x1

    buf = []
    for entry in exe.ph_entries:

        dst = exe.virtual_offset + entry["vaddr"]
        src = ctypes.addressof(entry["data"])
        sz = entry["filesz"]
        memsz = entry["memsz"]

        code = bincode_memcpy(dst, src, sz)
        buf.append(code)

        flags = entry["flags"]
        prot = PROT_READ if (flags & PF_R) != 0 else 0
        prot |= (PROT_WRITE if (flags & PF_W) != 0 else 0)
        prot |= (PROT_EXEC if (flags & PF_X) != 0 else 0)

        code = bincode_mprotect(PAGE_FLOOR(dst), PAGE_CEIL(memsz), prot)
        buf.append(code)

    return b"".join(buf)


def elf_execute(exe, binary, args, show_jumpbuf=False, jump_delay=False):

    # load interpreter as well if needed
    if exe.interp:
        logging.debug("dynamically linked library so load interpreter %s too" % exe.interp)
        with open(exe.interp, "rb") as fd:
            try:
                interp = ELFParser(fd)
                interp.parse()
            except ELFParsingError as e:
                logging.error("Error while parsing binary: %s" % e)
                sys.exit(1)
    else:
        interp = None

    # construct a stack with 2k pages
    stack = Stack(2048)
    argv = [binary] + args
    envp = []
    for name in os.environ:
        envp.append("%s=%s" % (name, os.environ[name]))

    stack.setup(argv, envp, exe, interp)

    # generate the jump buffer which copies all segments to the right
    # locations in memory, sets the correct protection flags on those
    # memory segments and then prepares for the actual jump into
    # hail mary land.
    jumpbuf = []
    jumpbuf.append(get_phentries_setup_code(exe))
    if interp:
        jumpbuf.append(get_phentries_setup_code(interp))

    # entry point is from the interpreter if binary has one
    entry_point = interp.entry_point if interp else exe.entry_point
    jumpbuf.append(bincode_jumpbuf(stack.base, entry_point, jump_delay))
    jumpbuf = b"".join(jumpbuf)

    if show_jumpbuf:
        display_jumpbuf(jumpbuf)

    # full buffer of instructions setup, now all we need to do is map this to
    # memory and set it such that that segment is executable so we can jump
    # into it
    cfunction = prepare_jumpbuf(jumpbuf)
    cfunction()


def main():
    parser = argparse.ArgumentParser(description="Attempt to execute an ELF binary in userland. Supply the path to the binary, any arguments to it and then sit back and pray.",
                                     usage="%(prog)s [options] <binary> [arguments]",
                                     epilog="Copyright (C) 2021 - Anvil Secure\n")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--show-jumpbuf", action="store_true", help="use objdump to show jumpbuf contents")
    parser.add_argument("--jump-delay", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="<binary> [arguments] (eg. /bin/ls /tmp)")
    ns = parser.parse_args(sys.argv[1:])

    if len(ns.command) == 0:
        parser.print_help()
        sys.exit(1)

    logging.basicConfig(format="%(message)s", level=logging.DEBUG if ns.debug else logging.INFO)

    binary = ns.command[0]
    args = ns.command[1:]

    with open(binary, "rb") as fd:
        elf = ELFParser(fd)
        try:
            elf.parse()
        except ELFParsingError as e:
            logging.error("Error while parsing binary: %s" % e)
            sys.exit(1)

    elf_execute(elf, binary, args, ns.show_jumpbuf, ns.jump_delay)

if __name__ == "__main__":
    main()
