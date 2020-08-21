# T1195.003 - Compromise Hardware Supply Chain
Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Perform physical inspection of hardware to look for potential tampering. Perform integrity checking on pre-OS boot mechanisms that can be manipulated for malicious purposes.