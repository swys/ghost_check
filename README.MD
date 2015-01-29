ghost_check
===========

Check if you server is vulnerable to Glibc GHOST. Find out more details about GHOST [here](http://www.cyberciti.biz/faq/cve-2015-0235-patch-ghost-on-debian-ubuntu-fedora-centos-rhel-linux/).

This shell will create a C program, run it, and check the output to see if you are vulnerable to the overflow.

It will clean up after itself after its done so you won't have any unnecessary files lying around afterwards.

usage
=====

```
./ghost_check.sh
```

This shell script will return 0 if you are `NOT VULNERABLE` and 1 if you are `VULNERABLE`.

It will also print out messages telling you if its vulnerable or not. So if you are running this on a bunch of system you can check for a `1` return value to confirm you are vulnerable.

license
========

MIT

