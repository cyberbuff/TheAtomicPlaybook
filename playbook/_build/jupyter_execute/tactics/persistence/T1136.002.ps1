# T1136.002 - Domain Account
Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the <code>net user /add /domain</code> command can be used to create a domain account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor for processes and command-line parameters associated with domain account creation, such as <code>net user /add /domain</code>. Collect data on account creation within a network. Event ID 4720 is generated when a user account is created on a Windows domain controller. (Citation: Microsoft User Creation Event) Perform regular audits of domain accounts to detect suspicious accounts that may have been created by an adversary.