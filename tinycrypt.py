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
import sys
 
from hashlib import sha1
from urllib2 import URLError, urlopen
 
 
__all__, __version__ = ["TinyCrypt"], "0.1.3"
 
 
URL = (
    "http://tinyurl.com/",
    "create.php?alias=%s&url=https://www.google.com%%3F",
    "referer="
)
 
 
class TinyCrypt(object):
    """
    Using TinyURL as a key/value storage for encrypted messages.
    """
    SALT = "Adjust this value to your own salt !"
 
    def __init__(self, url, action, delimiter):
        """
        Setting up the URLs.
        """
        self.GET = url
        self.SET = url + action + delimiter
        self.DEL = delimiter
 
    def __alias(self, key):
        """
        Uses the SHA(1) hash algorithm.
        """
        return sha1(TinyCrypt.SALT + key).hexdigest()
 
    def __crypt(self, key, data):
        """
        Uses the RC4 stream cipher with a reversed S-Box.
        """
        j, sbox = 0, range(256)[::-1]
 
        for i in range(256)[::-1]:
            j = (j + sbox[i] + ord(key[i % len(key)])) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
 
        i, j, stream = 0, 0, []
 
        for byte in data:
            i = (i + 1) % 256
            j = (j + sbox[i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
            stream.append(chr(ord(byte) ^ sbox[(sbox[i] + sbox[j]) % 256]))
 
        return "".join(stream)
 
    def push(self, key, message):
        """
        Pushes a message.
        """
        k = self.__alias(key)
        v = self.__crypt(key, message)
 
        urlopen((self.SET % k) + v.encode("hex"))
 
    def pull(self, key):
        """
        Returns a previously pushed message or None.
        """
        try:
            k = self.__alias(key)
            v = urlopen(self.GET + k).geturl()
            v = v.split(self.DEL, 1)[-1]
 
            return self.__crypt(key, v.decode("hex"))
 
        except URLError as ex:
            if not ex.code == 404:
                raise ex
 
 
def main(script, key="-h", *args):
    """
    Usage: %s KEY [MESSAGE...]
    """
    if key in ("/?", "-h"):
        return main.__doc__.strip() % os.path.basename(script)
 
    try:
        tiny = TinyCrypt(*URL)
 
        enc = sys.getdefaultencoding()
        key = key.decode(enc)
 
        message = tiny.pull(key)
 
        if message:
            print(message.encode(enc))
 
        elif args:
            message = " ".join(args)
            message = message.decode(enc)
 
            tiny.push(key, message)
 
    except Exception as ex:
        return "Error: %s" % ex
 
 
if __name__ == "__main__":
    sys.exit(main(*sys.argv))
