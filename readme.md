pbkdf2-utils
===

[![Build Status](https://travis-ci.org/calvinmetcalf/pbkdf2-utils.svg)](https://travis-ci.org/calvinmetcalf/pbkdf2-utils)

a few helper utilities for using pbkdf2

```js
var pbkdf2 = require('pbkdf2');

pbkdf2.hash(password, iterations, callback);
pbkdf2.hash(password, iterations, len, callback);
pbkdf2.hash(password, iterations, algo, callback);
pbkdf2.hash(password, iterations, len, algo, callback);
pbkdf2.hash(password, iterations, len, algo);

pbkdf2.verify(password, hash, callback);
pbkdf2.verify(password, hash);
```

If callback is omitted a promise is returned, len is the length of the generated hash in bytes, actual length will be 22 bytes longer as a 16 byte random salt along with data specifying the algorithm, length, and iterations, defaults to 32 bytes (58 bytes total), algorithm defaults to sha512, you may also specify sha224, sha256, sha384, ripemd160 and sha1 if you must.

It is assumed that you control the hashes, if for some reason a malicious party was submitting the hashes you were verifying they could substitute weaker ones.  I have no idea how that would even come up in practice just fyi.