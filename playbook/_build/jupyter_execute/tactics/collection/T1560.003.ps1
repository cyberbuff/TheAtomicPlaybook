# T1560.003 - Archive via Custom Method
An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.(Citation: ESET Sednit Part 2)

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Custom archival methods can be very difficult to detect, since many of them use standard programming language concepts, such as bitwise operations.