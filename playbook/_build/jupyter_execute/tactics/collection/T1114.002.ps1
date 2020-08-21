# T1114.002 - Remote Email Collection
Adversaries may target an Exchange server or Office 365 to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services or Office 365 to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific keywords.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor for unusual login activity from unknown or abnormal locations, especially for privileged accounts (ex: Exchange administrator account).