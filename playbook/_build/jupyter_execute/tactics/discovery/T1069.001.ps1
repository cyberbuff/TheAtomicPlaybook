# T1069.001 - Permission Groups Discovery: Local Groups
Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.

Commands such as <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscl . -list /Groups</code> on macOS, and <code>groups</code> on Linux can list local groups.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Permission Groups Discovery (Local)
Permission Groups Discovery

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
if [ -x "$(command -v dscacheutil)" ]; then dscacheutil -q group; else echo "dscacheutil is missing from the machine. skipping..."; fi;
if [ -x "$(command -v dscl)" ]; then dscl . -list /Groups; else echo "dscl is missing from the machine. skipping..."; fi;
if [ -x "$(command -v groups)" ]; then groups; else echo "groups is missing from the machine. skipping..."; fi;
```

Invoke-AtomicTest T1069.001 -TestNumbers 1

### Atomic Test #2 - Basic Permission Groups Discovery Windows (Local)
Basic Permission Groups Discovery for Windows. This test will display some errors if run on a computer not connected to a domain. Upon execution, domain
information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net localgroup
net localgroup "Administrators"
```

Invoke-AtomicTest T1069.001 -TestNumbers 2

### Atomic Test #3 - Permission Groups Discovery PowerShell (Local)
Permission Groups Discovery utilizing PowerShell. This test will display some errors if run on a computer not connected to a domain. Upon execution, domain
information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
get-localgroup
Get-LocalGroupMember -Name "Administrators"
```

Invoke-AtomicTest T1069.001 -TestNumbers 3

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).