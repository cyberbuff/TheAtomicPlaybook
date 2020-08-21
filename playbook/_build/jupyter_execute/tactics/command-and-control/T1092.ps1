# T1092 - Communication Through Removable Media
Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091). Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor file access on removable media. Detect processes that execute when removable media is mounted.