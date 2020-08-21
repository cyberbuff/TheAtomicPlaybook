# T1098.002 - Exchange Email Delegate Permissions
Adversaries may grant additional permission levels, such as ReadPermission or FullAccess, to maintain persistent access to an adversary-controlled email account. The <code>Add-MailboxPermission</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox.(Citation: Microsoft - Add-MailboxPermission)(Citation: FireEye APT35 2018)(Citation: Crowdstrike Hiding in Plain Sight 2018)

This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can assign more access rights to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules (ex: [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)), so the messages evade spam/phishing detection mechanisms.(Citation: Bienstock, D. - Defending O365 - 2019)

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor for unusual Exchange and Office 365 email account permissions changes that may indicate excessively broad permissions being granted to compromised accounts.

A larger than normal volume of emails sent from an account and similar phishing emails sent from  real accounts within a network may be a sign that an account was compromised and attempts to leverage access with modified email permissions is occurring.