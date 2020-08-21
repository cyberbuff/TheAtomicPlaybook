# T1052.001 - Exfiltration over USB
Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor file access on removable media. Detect processes that execute when removable media are mounted.