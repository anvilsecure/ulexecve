#!/usr/bin/env python

import ctypes
import math
import os
import random
import string
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes.util import find_library

import ulexecve as u

python_bin = "python3" if sys.version_info.major == 3 else "python2"


class TestLibcBackwardsCompat(unittest.TestCase):

    def test_getauxval(self):
        libc = ctypes.CDLL(find_library('c'))

        try:
            getauxval = libc.getauxval
            self._run(getauxval)
        except AttributeError:
            pass

    def test_emulate_getauxval(self):
        self.assertIn("_emulate_getauxval", dir(u))
        fn = u._emulate_getauxval
        with self.assertRaises(TypeError):
            fn()
        with self.assertRaises(TypeError):
            fn(1, 2)

    def _run(self, fn):
        # values can be gotten from f.e. /usr/include/x86_64-linux-gnu/bits/auxv.h
        self.assertEqual(fn(0), 0)
        self.assertNotEqual(fn(4), 0)  # AT_PHENT
        self.assertGreater(fn(5), 0)  # AT_PHNUM
        self.assertNotEqual(fn(6), 0)  # AT_PAGESZ
        self.assertNotEqual(fn(7), 0)  # AT_BASE
        self.assertEqual(fn(11), os.getuid())   # AT_UID


class TestUtils(unittest.TestCase):
    def test_pagesize(self):
        self.assertIn("PAGE_SIZE", dir(u))
        self.assertEqual(u.PAGE_SIZE, ctypes.pythonapi.getpagesize())

    def test_page_floor(self):
        pgsize = u.PAGE_SIZE
        self.assertIn("PAGE_FLOOR", dir(u))
        self.assertEqual(u.PAGE_FLOOR(pgsize * 2), pgsize * 2)
        self.assertEqual(u.PAGE_FLOOR(pgsize), pgsize)
        self.assertEqual(u.PAGE_FLOOR(pgsize + 5), pgsize)

    def test_page_ceil(self):
        pgsize = u.PAGE_SIZE
        self.assertIn("PAGE_CEIL", dir(u))
        self.assertEqual(u.PAGE_CEIL(pgsize * 2), pgsize * 2)
        self.assertEqual(u.PAGE_CEIL(pgsize), pgsize)
        self.assertEqual(u.PAGE_CEIL(pgsize + 5), pgsize * 2)


class TestFlags(unittest.TestCase):
    def test_flags(self):
        # just here for accidential modification in main source
        flags = {
            "PROT_READ": 0x01,
            "PROT_WRITE": 0x02,
            "PROT_EXEC": 0X04,
            "MAP_PRIVATE": 0x02,
            "MAP_ANONYMOUS": 0x20,
            "MAP_GROWSDOWN": 0x0100,
            "MAP_FIXED": 0x10,
            "PT_LOAD": 0x1,
            "PT_INTERP": 0x3,
            "EM_X86_64": 0x3e
        }
        for x in flags:
            self.assertIn(x, dir(u))
            self.assertEqual(flags[x], getattr(u, x))


class TestOptions(unittest.TestCase):
    def test_jumpdelay(self):
        delay = 0
        cmd = "echo wutwut | %s %s --jump-delay %i /bin/cat" % (python_bin, u.__file__, delay)
        output = subprocess.check_output(cmd, shell=True)
        self.assertEqual(b"wutwut\n", output)

        with self.assertRaises(subprocess.CalledProcessError):
            delay = -1
            cmd = "%s %s --jump-delay %i /bin/ls 2>&1 >> /dev/null" % (python_bin, u.__file__, delay)
            output = subprocess.check_output(cmd, shell=True)

        with self.assertRaises(subprocess.CalledProcessError):
            delay = 500
            cmd = "%s %s --jump-delay %i /bin/ls 2>&1 >> /dev/null" % (python_bin, u.__file__, delay)
            output = subprocess.check_output(cmd, shell=True)

        t0 = int(math.floor(time.time()))
        delay = 2
        cmd = "echo delayed | %s %s --jump-delay %i /bin/cat" % (python_bin, u.__file__, delay)
        output = subprocess.check_output(cmd, shell=True)
        self.assertEqual(b"delayed\n", output)
        t1 = int(math.floor(time.time()))
        self.assertGreaterEqual(t1 - t0, delay)


class TestBinaries(unittest.TestCase):
    def test_bins(self):
        # run /bin/cat and /bin/ls and see if those work fine
        py_fn = u.__file__
        cat_fn = "/bin/cat"
        cmd = "echo hello | %s %s %s" % (python_bin, py_fn, cat_fn)
        output = subprocess.check_output(cmd, shell=True)
        self.assertEqual(b"hello\n", output)

        cat_fn = "/bin/ls -lha"
        cmd = "%s %s %s %s" % (python_bin, py_fn, cat_fn, os.path.basename(py_fn))
        output = subprocess.check_output(cmd, shell=True)
        self.assertNotEqual(output.find(os.path.basename(py_fn).encode("utf-8")), -1)

    def compile_and_run(self, data, suffix, cmd, extra=""):
        with tempfile.NamedTemporaryFile(suffix="", mode="wb") as out:
            with tempfile.NamedTemporaryFile(suffix=suffix, mode="wb") as inp:
                inp.write(data)
                inp.seek(0)
                cmd = cmd % (out.name, inp.name)
                output = subprocess.check_output(cmd, shell=True)
            cmd = "%s %s %s %s" % (python_bin, u.__file__, out.name, extra)
            output = subprocess.check_output(cmd, shell=True)
            return output

    def test_args(self):
        c = b"#include <stdio.h>\nint main(int argc, char ** argv){printf(\"%i\\n%s\\n%s\\n\", argc, argv[1], argv[2]);}\n"
        try:
            output = self.compile_and_run(c, ".c", "gcc -o %s %s", "hello world")
        except subprocess.CalledProcessError:
            self.skipTest("gcc does not seem to be installed so not running gcc specific tests")
            return
        lines = output.splitlines()
        self.assertEqual(lines[0], b"3")
        self.assertEqual(lines[1], b"hello")
        self.assertEqual(lines[2], b"world")

    def test_envp(self):
        envval = "".join(random.choice(string.ascii_uppercase) for _ in range(10)).encode("utf-8")
        envname = "".join(random.choice(string.ascii_uppercase) for _ in range(10)).encode("utf-8")
        c = b"#include <stdio.h>\n#include <stdlib.h>\nint main(){printf(\"%%s\\n\", getenv(\"%s\"));}\n" % envname
        try:
            os.putenv(envname, envval)
            output = self.compile_and_run(c, ".c", "gcc -o %s %s", "")
        except subprocess.CalledProcessError:
            self.skipTest("gcc does not seem to be installed so not running gcc specific tests")
            return
        self.assertEqual(envval + b"\n", output)

    def test_gcc_dynamic_bin(self):
        c = b"#include <stdio.h>\nint main(){printf(\"hello world from gcc\\n\");}"
        try:
            output = self.compile_and_run(c, ".c", "gcc -o %s %s")
        except subprocess.CalledProcessError:
            self.skipTest("gcc does not seem to be installed so not running gcc specific tests")
            return
        self.assertEqual(b"hello world from gcc\n", output)

    def test_gcc_static_bin(self):
        c = b"#include <stdio.h>\nint main(){printf(\"hello world from gcc static\\n\");}\n"
        try:
            output = self.compile_and_run(c, ".c", "gcc --static -o %s %s")
        except subprocess.CalledProcessError:
            self.skipTest("gcc does not seem to be installed so not running gcc specific tests")
            return
        self.assertEqual(b"hello world from gcc static\n", output)

    def test_gcc_pie_bin(self):
        c = b"#include <stdio.h>\nint main(){printf(\"hello world from gcc pie\\n\");}\n"
        try:
            output = self.compile_and_run(c, ".c", "gcc -O0 -pie -fpie -o %s %s")
        except subprocess.CalledProcessError:
            self.skipTest("gcc does not seem to be installed so not running gcc specific tests")
            return
        self.assertEqual(b"hello world from gcc pie\n", output)

    def test_gcc_nopie_bin(self):
        c = b"#include <stdio.h>\nint main(){printf(\"hello world from gcc no-pie\\n\");}\n"
        try:
            output = self.compile_and_run(c, ".c", "gcc -O0 -no-pie -fno-pie -o %s %s")
        except subprocess.CalledProcessError:
            self.skipTest("gcc does not seem to be installed so not running gcc specific tests")
            return
        self.assertEqual(b"hello world from gcc no-pie\n", output)

    def test_rust_bins(self):
        try:
            c = b"fn main(){println!(\"hello world from rust\");}\n"
            output = self.compile_and_run(c, ".rs", "rustc -o %s %s")
        except subprocess.CalledProcessError:
            self.skipTest("rust does not seem to be installed so not running rust specific test")
            return
        self.assertEqual(b"hello world from rust\n", output)

    def test_golang_bins(self):
        try:
            c = b"package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello world from golang\")}\n"
            output = self.compile_and_run(c, ".go", "go build -o %s %s")
        except subprocess.CalledProcessError:
            self.skipTest("golang does not seem to be installed to not running golang specific test")
            return
        self.assertEqual(b"hello world from golang\n", output)


if __name__ == "__main__":
    unittest.main()
