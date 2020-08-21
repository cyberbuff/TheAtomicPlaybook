# T1550.002 - Use Alternate Authentication Material: Pass the Hash
Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.(Citation: NSA Spotting)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Mimikatz Pass the Hash
Note: must dump hashes first
[Reference](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mimikatz # sekurlsa::pth /user:#{user_name} /domain:#{domain} /ntlm:#{ntlm}
```

Invoke-AtomicTest T1550.002 -TestNumbers 1

### Atomic Test #2 - crackmapexec Pass the Hash
command execute with crackmapexec

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x #{command}
```

Invoke-AtomicTest T1550.002 -TestNumbers 2

## Detection
Audit all logon and credential use events and review for discrepancies. Unusual remote logins that correlate with other suspicious activity (such as writing and executing binaries) may indicate malicious activity. NTLM LogonType 3 authentications that are not associated to a domain login and are not anonymous logins are suspicious.