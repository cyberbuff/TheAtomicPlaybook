# T1553.002 - Code Signing
Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. (Citation: Wikipedia Code Signing) The certificates used during an operation may be created, acquired, or stolen by the adversary. (Citation: Securelist Digital Certificates) (Citation: Symantec Digital Certificates) Unlike [Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001), this activity will result in a valid signature.

Code signing to verify software on first run can be used on modern Windows and macOS/OS X systems. It is not used on Linux due to the decentralized nature of the platform. (Citation: Wikipedia Code Signing) 

Code signing certificates may be used to bypass security policies that require signed code to execute on a system. 

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Collect and analyze signing certificate metadata on software that executes within the environment to look for unusual certificate characteristics and outliers.