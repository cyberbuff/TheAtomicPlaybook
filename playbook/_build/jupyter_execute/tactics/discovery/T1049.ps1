# T1049 - System Network Connections Discovery
Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview)

Utilities and commands that acquire this information include [netstat](https://attack.mitre.org/software/S0104), "net use," and "net session" with [Net](https://attack.mitre.org/software/S0039). In Mac and Linux, [netstat](https://attack.mitre.org/software/S0104) and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to "net session".

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - System Network Connections Discovery
Get a listing of network connections.

Upon successful execution, cmd.exe will execute `netstat`, `net use` and `net sessions`. Results will output via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netstat
net use
net sessions
```

Invoke-AtomicTest T1049 -TestNumbers 1

### Atomic Test #2 - System Network Connections Discovery with PowerShell
Get a listing of network connections.

Upon successful execution, powershell.exe will execute `get-NetTCPConnection`. Results will output via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-NetTCPConnection
```

Invoke-AtomicTest T1049 -TestNumbers 2

### Atomic Test #3 - System Network Connections Discovery Linux & MacOS
Get a listing of network connections.

Upon successful execution, sh will execute `netstat` and `who -a`. Results will output via stdout.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
netstat
who -a
```

Invoke-AtomicTest T1049 -TestNumbers 3

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).