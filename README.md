# TinyCrypt 0.2.2 ![Build](https://travis-ci.org/cuhsat/tinycrypt.svg)
Using TinyURL as a key/value storage for encrypted messages.

## Usage
```tc.py [option|key] [message...]```

## Examples
Push a message
```
$ tc.py SecretKey "Hello World"
```
Pull a message
```
$ tc.py SecretKey
```

## License
TinyCrypt is released under the terms of the MIT License (MIT).

Copyright (c) 2015 Christian Uhsat <christian@uhsat.de>
