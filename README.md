Atten-shun!
===========
[![License Badge][]][License] [![Travis Status][]][Travis]

Unless you're here for something really small and generally useless,
albeit with a *very liberal* [Open Source license][1], you really want
something useful.  Like:

  * [wget](https://www.gnu.org/software/wget/), or
  * [curl](https://curl.haxx.se/)
  
They are really much better suited (and less buggy!) for everyday use
than `uget`.  Each one has its merits; if you just want to fetch files
then use `wget`, `curl` can do this too of course, but you need a few
more command line parameters.  However, if you're a developer and want
to debug HTTP connections, then `curl` is definitely for you!

The `uget` project is the development arena for the `ssdp-scan` tool in
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
