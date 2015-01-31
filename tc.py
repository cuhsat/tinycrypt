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
import base64
import binascii
import os
import re
import sys

try:
    from urllib.error import URLError
    from urllib.request import urlopen
except:
    from urllib2 import URLError, urlopen # Python 2 fallback


try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA512
except ImportError:
    sys.exit("Requires PyCrypto (https://github.com/dlitz/pycrypto)")


__all__, __version__ = ["TinyCrypt"], "0.2.2"


class TinyCrypt(object):
    """
    Uses TinyURL as a key/value storage for encrypted messages.
    """
    SALT = b"Use Your Own Salt"

    def __init__(self, decoy="http://test.com"):
        """
        Sets the decoy URL.
        """
        self.decoy = decoy + "%%3Fdata=%s"

    def __repr__(self):
        """
        Returns the protocol version.
        """
        return "TinyCrypt " + __version__

    def __hash(self, key):
        """
        Returns the SHA512 hash and the alias of the key.
        """
        key = SHA512.new(TinyCrypt.SALT + key.encode("utf-8")).digest()

        return (key, binascii.hexlify(key)[:40].decode("ascii"))

    def __encrypt(self, key, data):
        """
        Returns the AES (CFB8) encrypted data.
        """
        return AES.new(key[:32], AES.MODE_CFB, key[-16:]).encrypt(data)

    def __decrypt(self, key, data):
        """
        Returns the AES (CFB8) decrypted data.
        """
        return AES.new(key[:32], AES.MODE_CFB, key[-16:]).decrypt(data)

    def push(self, key, message):
        """
        Pushes a message.
        """
        key, alias = self.__hash(key)

        data = self.__encrypt(key, message)
        data = base64.urlsafe_b64encode(data).decode("ascii")

        url = "http://tinyurl.com/create.php?alias=%s&url=" + self.decoy
        urlopen(url % (alias, data))

    def pull(self, key):
        """
        Returns a previously pushed message or None.
        """
        try:
            key, alias = self.__hash(key)

            url = urlopen("http://tinyurl.com/" + alias).geturl()

            data = re.split("^.+data=", url, 1)[1]
            data = base64.urlsafe_b64decode(data)

            return self.__decrypt(key, data).decode("utf-8")

        # No message found else error
        except URLError as ex:
            if getattr(ex, "code", None) != 404:
                raise ex


def usage(text, *args):
    """
    Prints the usage text.
    """
    for line in (text % args).split("\n")[1:-1]:
        line = line[4:]

        if os.name in ["posix"]:

            # Color description
            if re.match("^.* Version \d+\.\d+\.\d+$", line):
                line = line.replace("Version", "Version\x1B[34;1m")
                line = "\x1B[39;1m%s\x1B[0m" % line

            # Color list titles
            elif re.match("^[A-Za-z ]+:$", line):
                line = "\x1B[34m%s\x1B[0m" % line

            # Color list points
            elif re.match("^  (-.|[a-z]+)", line):
                line = line.replace("   ", "   \x1B[37;0m")
                line = "\x1B[34;1m%s\x1B[0m" % line

        print(line)


def main(script, arg="--help", *args):
    """
        _________ __                  _______                       ___
       /__   ___/__/_______ ___   ___/  ____/________   ___________/  /__
         /  /  /  /  ___   /  /  /  /  /   /  ___/  /  /  /  ___  /  ___/
        /  /  /  /  /  /  /  /__/  /  /___/  /  /  /__/  /  /__/ /  /__
       /__/  /__/__/  /__/\____   /______/__/   \____   /  _____/\____/
                         /_______/             /_______/__/
      Version %s

    Usage:
      %s [option|key] [message...]

    Options:
      -h --help      Shows this text
      -l --license   Shows license
      -v --version   Shows version

    Report bugs to <christian@uhsat.de>
    """
    try:
        script = os.path.basename(script)

        if arg in ("/?", "-h", "--help"):
            usage(main.__doc__, __version__, script)

        elif arg in ("-l", "--license"):
            print(__doc__.strip())

        elif arg in ("-v", "--version"):
            print("TinyCrypt " + __version__)

        else:
            tinycrypt = TinyCrypt()
            message = tinycrypt.pull(arg)

            if message:
                print(message)
            elif args:
                tinycrypt.push(arg, " ".join(args))

    except Exception as ex:
        return "%s error: %s" % (script, ex)


if __name__ == "__main__":
    sys.exit(main(*sys.argv))
