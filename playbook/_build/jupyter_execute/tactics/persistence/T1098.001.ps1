# T1098.001 - Additional Azure Service Principal Credentials
Adversaries may add adversary-controlled credentials for Azure Service Principals in addition to existing legitimate credentials(Citation: Create Azure Service Principal) to maintain persistent access to victim Azure accounts.(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) Azure Service Principals support both password and certificate credentials.(Citation: Why AAD Service Principals) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az [PowerShell](https://attack.mitre.org/techniques/T1059/001) modules.(Citation: Demystifying Azure AD Service Principals)

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor Azure Activity Logs for service principal modifications.

Monitor for use of credentials at unusual times or to unusual systems or services. This may also correlate with other suspicious activity.