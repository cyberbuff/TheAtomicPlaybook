# T1021.005 - VNC
Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely control machines using Virtual Network Computing (VNC). The adversary may then perform actions as the logged-on user.

VNC is a desktop sharing system that allows users to remotely control another computer’s display by relaying mouse and keyboard inputs over the network. VNC does not necessarily use standard user credentials. Instead, a VNC client and server may be configured with sets of credentials that are used only for VNC connections.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Use of VNC may be legitimate depending on the environment and how it’s used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior with VNC.