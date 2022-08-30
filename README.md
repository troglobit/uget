Almost Useless get-file-over-http Program
==========================================================
[![License Badge][]][License] [![Travis Status][]][Travis]


```
Usage: uget [-hInsvV] [-c CACERT] [-o FILE] [-t SEC.MSEC] [URL]

Options:
  -c CACERT    Override built-in path to CA certificate to use to verify peer
  -h           This help text
  -I           Ask server for HEAD of location instead of GET whole content
  -n           Disable TCP_NODELAY socket option
  -o FILE      Write output to FILE rather than stdout
  -s           Disable strict certificate validation
  -t SEC.MSEC  Set socket send/recv timeout
  -v           Verbose mode, use twice to enable debug messages
  -V           Show program name and version

Copyright (c) 2019-2022  Joachim Wiberg <troglobit@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
```


Caveat
------

Unless you're here for something really small and generally useless,
albeit with a *very liberal* [Open Source license][1], you will want
something else instead, something useful.  Like:

  * [wget](https://www.gnu.org/software/wget/), or
  * [curl](https://curl.haxx.se/)
  
They are really much better suited (and less buggy!) for everyday use
than `uget`.  Each one has its merits; if you just want to fetch files
then use `wget`, `curl` can do this too of course, but you need a few
more command line parameters.  However, if you're a developer and want
to debug HTTP connections, then `curl` is definitely for you!


Origin & References
-------------------

The `uget` project shares most of its code with the `ssdp-scan` tool in
the [ssdp-responder][2] project.  You may also find an equally stupid
web server here.  Please don't use it for anything remotely production
oriented!

Take care  
 /J

[1]: https://en.wikipedia.org/wiki/ISC_license
[2]: https://github.com/troglobit/ssdp-responder/
[License]:         https://en.wikipedia.org/wiki/ISC_license
[License Badge]:   https://img.shields.io/badge/License-ISC-blue.svg
[Travis]:          https://travis-ci.org/troglobit/uget
[Travis Status]:   https://travis-ci.org/troglobit/uget.png?branch=master
