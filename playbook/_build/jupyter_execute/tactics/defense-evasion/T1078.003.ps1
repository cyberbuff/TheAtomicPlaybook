# T1078.003 - Local Accounts
Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

Local Accounts may also be abused to elevate privileges and harvest credentials through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement. 

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Perform regular audits of local system accounts to detect accounts that may have been created by an adversary for persistence. Look for suspicious account behavior, such as accounts logged in at odd times or outside of business hours.