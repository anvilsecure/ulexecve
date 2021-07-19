#!/usr/bin/env python2

import ctypes
import struct
import sys
from ctypes import (CDLL, CFUNCTYPE, c_int, c_size_t, c_void_p, cast, memset,
                    pythonapi, memmove)
from ctypes.util import find_library
personality = ctypes.CDLL(None).personality
personality.restype = ctypes.c_int
personality.argtypes = [ctypes.c_ulong]

print(personality(0xffffffff))

import gc
gc.disable()

PT_LOAD = 0x1
PT_INTERP = 3

PF_R = 0x4
PF_W = 0x2
PF_X = 0x1

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
PROT_SEM = 0x8
MAP_PRIVATE = 0X02
MAP_ANONYMOUS = 0x20
MAP_GROWSDOWN = 0x0100

AT_NULL = 0
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_ENTRY = 9
AT_SECURE = 23
AT_RANDOM = 25

libc = CDLL(find_library('c'))
page_size = pythonapi.getpagesize()

mmap = libc.mmap
mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]
mmap.restype = c_void_p

memcpy = libc.memcpy
memcpy.argtypes = [c_void_p, c_void_p, c_size_t]
memcpy.restype = c_void_p

mprotect = libc.mprotect
mprotect.argtypes = [c_void_p, c_size_t, c_int]
mprotect.restype = c_int

munmap = libc.munmap
munmap.argtypes = [c_void_p, c_size_t]
munmap.restype = c_int


def PAGE_FLOOR(addr):
    return (addr) & (-page_size)


def PAGE_CEIL(addr):
    return (PAGE_FLOOR((addr) + page_size - 1))


class ELFParsingError(Exception):
    pass


class ELFLoader:
    def __init__(self, stream):
        self.stream = stream

    def load(self):
        self.interp = 0
        self.entry_point = 0
        self.mapping = None

        self.parse_head()
        self.parse_ehdr()

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

        self.stream.seek(16)

    def unpack(self, fmt):
        sz = struct.calcsize(fmt)
        buf = self.stream.read(sz)
        if self.little_endian:
            endian_str = "<"
        else:
            endian_str = ">"
        return (struct.unpack("%c%s" % (endian_str, fmt), buf), buf)

    def parse_phdr(self):
        ret, buf = self.unpack("IIQQQQQQ")
        return ret

    def parse_ehdr(self):
        values, buf = self.unpack("HHIQQQIHHHHHH")
        self.e_type, self.e_machine, self.e_version, self.e_entry, \
            self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, \
            self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx = values

        self.ehdr = ctypes.create_string_buffer(buf)

        self.stream.seek(self.e_phoff)
        map_sz = 0
        adjust = 0
        pie_executable = False
        first_pt_load = False
        for i in range(0, self.e_phnum):
            phdr = self.parse_phdr()
            p_type, p_vaddr, p_memsz = phdr[0], phdr[3], phdr[6]
            if p_type == PT_LOAD:
                # if this is the first PT_LOAD segment check if we're PIE and figure out adjustment
                if not first_pt_load:
                    first_pt_load = True
                    if p_vaddr != 0:
                        adjust = p_vaddr
                    else:
                        pie_executable = True

                map_sz = p_vaddr + p_memsz if (p_vaddr + p_memsz) > map_sz else map_sz
                print("total mapping is now 0x%08x based on 0x%08x seg at 0x%x" % (map_sz, p_memsz, p_vaddr))

        if not pie_executable:
            map_sz -= adjust


        adjust = adjust + 0x41414141

        mapping = mmap(PAGE_FLOOR(adjust), PAGE_CEIL(map_sz), PROT_READ | PROT_WRITE | PROT_SEM, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if mapping == -1:
            print("mapping failed :(")
            sys.exit(-1)
        #ret = mprotect(mapping, PAGE_CEIL(p_memsz), PROT_WRITE | PROT_READ | PROT_EXEC)
        memset(mapping, 0, map_sz)

        virtual_offset = mapping if adjust == 0 else 0
        virtual_offset = 0x41414141
        self.entry_point = virtual_offset + self.e_entry


        print("0x%.8x\n", mapping)
        print("0x%.8x\n",virtual_offset)
        print("0x%.8x\n", hex(p_vaddr))
        print("are we pie?: %s" % (pie_executable))
        interp = None
        self.stream.seek(self.e_phoff)
        self.srcs = []
        self.tmpbufs = []
        for i in range(0, self.e_phnum):
            phdr = self.parse_phdr()
            p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz = phdr[0], phdr[1], phdr[2], phdr[3], phdr[5], phdr[6]
            if p_type == PT_INTERP:
                interp = p_offset
                continue
            elif p_type != PT_LOAD:
                continue

            off = self.stream.tell()

            self.stream.seek(p_offset)
            tmpbuf = self.stream.read(p_filesz)
            src = ctypes.create_string_buffer(tmpbuf, p_filesz)
            #self.src = ctypes.c_char_p(self.stream.read(p_filesz))
            self.srcs.append(src)
            self.tmpbufs.append(tmpbuf)
            #src = ctypes.c_void_p(libc.valloc(p_filesz))
            print("!!!!! %s, %i"  % (src, p_filesz))
            dst = virtual_offset + p_vaddr

            print("memcpy(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, ctypes.addressof(src), p_filesz))
            print(".%8x\n" % ctypes.addressof(src))
            #print("memcpy(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, ctypes.byref(src), p_filesz))
            ret = mprotect(PAGE_FLOOR(dst), PAGE_CEIL(p_filesz), PROT_WRITE | PROT_EXEC | PROT_SEM)
            print("%i\n" % ret)
            print(".%8x\n" % ctypes.addressof(src))
            #src = ctypes.cast(ctypes.create_string_buffer(p_filesz),ctypes.POINTER(ctypes.c_char))
            #print(ctypes.addressof(src))
            #ctypes.set_errno(0)
            #ret = memcpy(ctypes.c_void_p(dst), ctypes.addressof(src), p_filesz)
            ret = memmove(dst, ctypes.addressof(src), p_filesz)
            #ret = memmove(dst, 0x4141414141, p_filesz)
            #memset(dst, 0x42, p_filesz)

            sys.stdout.flush() 

            prot = PROT_READ if (p_flags & PF_R) != 0 else 0
            prot |= (PROT_WRITE if (p_flags & PF_W) != 0 else 0)
            prot |= (PROT_EXEC if (p_flags & PF_X) != 0 else 0)

            ret = mprotect(PAGE_FLOOR(dst), PAGE_CEIL(p_memsz), prot)
            print("mprotect: %i\n" % ret)
            # XXX: handle mprotect failure
            self.stream.seek(off)

        if interp is not None:
            interp = mapping + interp

        self.interp = interp
        self.mapping = mapping


def auxv_setup(stack, auxv_ptr, off, exe, interp):
    interp_loc = interp.ehdr
    exe_loc = exe.mapping
    stack[off] = AT_BASE
    stack[off + 1] = exe.mapping
    stack[off + 2] = AT_PHDR
    stack[off + 3] = exe_loc + exe.e_phoff
    stack[off + 4] = AT_ENTRY
    stack[off + 5] = ((exe_loc + exe.e_entry) if exe.e_entry < exe_loc else exe.e_entry)
    stack[off + 6] = AT_PHNUM
    stack[off + 7] = exe.e_phnum
    stack[off + 8] = AT_PHENT
    stack[off + 9] = exe.e_phentsize
    stack[off + 10] = AT_PAGESZ
    stack[off + 11] = page_size
    stack[off + 12] = AT_SECURE
    stack[off + 13] = 0
    stack[off + 14] = AT_RANDOM
    stack[off + 15] = auxv_ptr  # (should be set to start of auxv for stack cookies)
    stack[off + 16] = AT_NULL
    stack[off + 17] = 0


def stack_setup(stack_base, argv, envp, exe, interp):
    stack_ptr = stack_base
    stack = (ctypes.c_size_t*page_size).from_address(stack_base)

    i = 0
    stack[i] = c_size_t(len(argv))
    i = i + 1
    for arg in argv:
        stack[i] = c_size_t(0)
        i += 1
    stack[i] = c_size_t(0)
    i += 1

    for env in envp:
        stack[i] = c_size_t(0)
        i += 1
    stack[i] = c_size_t(0)
    i += 1

    auxv_setup(stack, stack_ptr + (8 * i), i, exe, interp)


def execute_elf(exe):
    stack_size = 2048 * page_size
    stack_ptr = mmap(0, stack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0)
    memset(stack_ptr, 0, stack_size)

    # stack grows down so start of stack needs to be adjusted
    stack_ptr += (stack_size - page_size)
    print("allocated stack at 0x%.8x" % (stack_ptr))

    stack_setup(stack_ptr, [], [], exe, exe)

    addr = exe.entry_point
    print("jumping to ELF entrypoint at 0x%.8x" % addr)

    buf = ""
    buf += "\x48\xbc" + struct.pack("<Q", stack_ptr)    # movabs $0x..., %rsp   (movq %[stack], %%rsp)
    buf += "\x48\xb9" + struct.pack("<Q", addr)    # movabs $0x..., %rcx
    buf += "\x48\x31\xd2"    # xor %rdx, $rdx
    buf += "\xff\xe1"        # jmpq *%rcx

    jumpbuf = mmap(0, PAGE_CEIL(1024), PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    src = ctypes.create_string_buffer(buf)
    dst = jumpbuf

    print("memcpy(0x%.8x, 0x%.8x, 0x%.8x)" % (dst, ctypes.addressof(src), len(buf)))
    ret = memcpy(dst, src, len(buf))
    ret = mprotect(PAGE_FLOOR(dst), PAGE_CEIL(1024), PROT_READ | PROT_EXEC)

    cfun = cast(jumpbuf, CFUNCTYPE(c_void_p))
    cfun()


def run():
    if len(sys.argv) != 2:
        print("needs argument specifying binary to execute")
        sys.exit(1)
    debug = True
    binfn = sys.argv[1]
    fd = open(binfn, "rb")
    elf = ELFLoader(fd)
    elf.load()

    execute_elf(elf)


if __name__ == "__main__":
    run()
