import ctypes
libc = ctypes.cdll.LoadLibrary("libc.so.6")
memfd_create = libc.syscall
memfd_create.restype = ctypes.c_int
memfd_create.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
__NR_memfd_create = 319
BINNAME = "./a.out"
with open(BINNAME, "rb") as f:
    b = f.read()
    fd = memfd_create(__NR_memfd_create,"w00t", 0x1)
    if fd == -1:
        raise RuntimeError("memfd_create")
    i = libc.write(fd,b,len(b))
    if i == -1:
        raise RuntimeError("write")
    e = libc.fexecve(fd, (ctypes.c_char_p*1)(b"id"),(ctypes.c_char_p*0)())
    print(err)
