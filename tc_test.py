#!/usr/bin/env python
"""
The MIT License (MIT)

Copyright (c) 2015 Christian Uhsat <christian@uhsat.de>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import os
import random
import string
import sys
import time


from tc import TinyCrypt


try:
    import pytest
except ImportError:
    sys.exit("Requires py.test (https://pytest.org)")


def setup_module(module):
    """
    Sets unit test specific salt to avoid conflicts.
    """
    TinyCrypt.SALT = b"TinyCrypt Unit Tests"


class TestTinyCrypt:
    """
    TinyCrypt unit tests.
    """
    def test_push_pull(self):
        """
        Simple fuzzy push/pull test.
        """
        key = "".join([random.choice(string.printable) for c in range(32)])
        msg = "".join([random.choice(string.printable) for c in range(64)])

        tinycrypt = TinyCrypt()
        tinycrypt.push(key, msg)

        time.sleep(10)

        assert tinycrypt.pull(key) == msg


def main(*args):
    """
    Starts unit testing and passes all command line arguments to py.test.
    """
    return pytest.main(list(args))


if __name__ == "__main__":
    sys.exit(main(*sys.argv))
