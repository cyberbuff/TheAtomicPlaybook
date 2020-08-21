# T1087.002 - Account Discovery: Domain Account
Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior.

Commands such as <code>net user /domain</code> and <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscacheutil -q group</code>on macOS, and <code>ldapsearch</code> on Linux can list domain users and groups.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Enumerate all accounts (Domain)
Enumerate all accounts
Upon exection, multiple enumeration commands will be run and their output displayed in the PowerShell session

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net user /domain
net group /domain
```

Invoke-AtomicTest T1087.002 -TestNumbers 1

### Atomic Test #2 - Enumerate all accounts via PowerShell (Domain)
Enumerate all accounts via PowerShell. Upon execution, lots of user account and group information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
net user /domain
get-localgroupmember -group Users
get-aduser -filter *
```

Invoke-AtomicTest T1087.002 -TestNumbers 2

### Atomic Test #3 - Enumerate logged on users via CMD (Domain)
Enumerate logged on users. Upon exeuction, logged on users will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
query user /SERVER:#{computer_name}
```

Invoke-AtomicTest T1087.002 -TestNumbers 3

### Atomic Test #4 - Automated AD Recon (ADRecon)
ADRecon extracts and combines information about an AD environement into a report. Upon execution, an Excel file with all of the data will be generated and its
path will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Invoke-Expression #{adrecon_path}
```

Invoke-AtomicTest T1087.002 -TestNumbers 4

### Atomic Test #5 - Adfind -Listing password policy
Adfind tool can be used for reconnaissance in an Active directory environment. The example chosen illustrates adfind used to query the local password policy.
reference- http://www.joeware.net/freetools/tools/adfind/, https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
PathToAtomicsFolder\T1087.002\src\AdFind -default -s base lockoutduration lockoutthreshold lockoutobservationwindow maxpwdage minpwdage minpwdlength pwdhistorylength pwdproperties
```

Invoke-AtomicTest T1087.002 -TestNumbers 5

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.
Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).
