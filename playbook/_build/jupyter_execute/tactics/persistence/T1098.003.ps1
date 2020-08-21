# T1098.003 - Add Office 365 Global Administrator Role
An adversary may add the Global Administrator role to an adversary-controlled account to maintain persistent access to an Office 365 tenant.(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: Microsoft O365 Admin Roles) With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins) via the global admin role.(Citation: Microsoft O365 Admin Roles) 

This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Collect usage logs from cloud administrator accounts to identify unusual activity in the assignment of roles to those accounts. Monitor for accounts assigned to admin roles that go over a certain threshold of known admins. 