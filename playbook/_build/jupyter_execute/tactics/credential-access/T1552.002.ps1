# T1552.002 - Unsecured Credentials: Credentials in Registry
Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.

Example commands to find Registry keys related to password information: (Citation: Pentestlab Stored Credentials)

* Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code>
* Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code>

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Enumeration for Credentials in Registry
Queries to enumerate for credentials in the Registry. Upon execution, any registry key containing the word "password" will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Invoke-AtomicTest T1552.002 -TestNumbers 1

### Atomic Test #2 - Enumeration for PuTTY Credentials in Registry
Queries to enumerate for PuTTY credentials in the Registry. PuTTY must be installed for this test to work. If any registry
entries are found, they will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s
```

Invoke-AtomicTest T1552.002 -TestNumbers 2

## Detection
Monitor processes for applications that can be used to query the Registry, such as [Reg](https://attack.mitre.org/software/S0075), and collect command parameters that may indicate credentials are being searched. Correlate activity with related suspicious behavior that may indicate an active intrusion to reduce false positives.