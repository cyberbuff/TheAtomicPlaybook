# T1003.004 - OS Credential Dumping: LSA Secrets
Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.(Citation: Passcape LSA Secrets)(Citation: Microsoft AD Admin Tier Model)(Citation: Tilbury Windows Credentials) LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets</code>. LSA secrets can also be dumped from memory.(Citation: ired Dumping LSA Secrets)

[Reg](https://attack.mitre.org/software/S0075) can be used to extract from the Registry. [Mimikatz](https://attack.mitre.org/software/S0002) can be used to extract secrets from memory.(Citation: ired Dumping LSA Secrets)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Dumping LSA Secrets
Dump secrets key from Windows registry
When successful, the dumped file will be written to $env:Temp\secrets.
Attackers may use the secrets key to assist with extracting passwords and enumerating other sensitive system information.
https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/#:~:text=LSA%20Secrets%20is%20a%20registry,host%2C%20local%20security%20policy%20etc.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{psexec_exe} -accepteula -s reg save HKLM\security\policy\secrets %temp%\secrets```

Invoke-AtomicTest T1003.004 -TestNumbers 1

## Detection
Monitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like Mimikatz. PowerShell scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module,(Citation: Powersploit) which may require additional logging features to be configured in the operating system to collect necessary information for analysis.