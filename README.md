SimpleFixScanner
================
SFS is just a simple file scanner in php to fix some tedious trojans that corrupt some files on the server.
It can be easily updated to fix others trojans.

Usage
=====
Place the script somewhere on the server and point it with the browser.

By default the scanner start the scan process from the SERVER_ROOT, if you want to scan a specific directory you have to specify the path on the $docRoot parameter.


Currently supported trojan
================
- 336988 (Thanks to fatsouls32 for the regex - http://www.freestuff.gr/forums/viewtopic.php?t=64419)
- 68c8c7 (method added by Brett)

