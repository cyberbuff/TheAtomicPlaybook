# T1052 - Exfiltration Over Physical Medium
Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor file access on removable media. Detect processes that execute when removable media are mounted.