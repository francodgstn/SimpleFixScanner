SimpleFixScanner
================
SFS is just a simple file scanner in php to fix some tedious trojans that corrupt some files on the server.
It can be easily updated to fix others trojans.

Usage
=====
Place the script somewhere on the server and point it with the browser.

By default the scanner starts the scan process from the SERVER_ROOT, if you want to scan a specific directory you will have to specify the path on the $docRoot parameter.


Currently supported fix
================
- 336988 Injection Trojan and variants [336988, 68c8c7, 8f4d8e, a59dc4],  thanks to fatsouls32 for 336988 regex fix - http://www.freestuff.gr/forums/viewtopic.php?t=64419 and to Brett and Paul for the variants


