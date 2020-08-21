# T1518.001 - Software Discovery: Security Software Discovery
Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Example commands that can be used to obtain security software information are [netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with [Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with [cmd](https://attack.mitre.org/software/S0106), and [Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for. It is becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.

Adversaries may also utilize cloud APIs to discover the configurations of firewall rules within an environment.(Citation: Expel IO Evil in AWS)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Security Software Discovery
Methods to identify Security Software on an endpoint

when sucessfully executed, the test is going to display running processes, firewall configuration on network profiles
and specific security software.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netsh.exe advfirewall  show allprofiles
tasklist.exe
tasklist.exe | findstr /i virus
tasklist.exe | findstr /i cb
tasklist.exe | findstr /i defender
tasklist.exe | findstr /i cylance
```

Invoke-AtomicTest T1518.001 -TestNumbers 1

### Atomic Test #2 - Security Software Discovery - powershell
Methods to identify Security Software on an endpoint

when sucessfully executed, powershell is going to processes related AV products if they are running.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
get-process | ?{$_.Description -like "*virus*"}
get-process | ?{$_.Description -like "*carbonblack*"}
get-process | ?{$_.Description -like "*defender*"}
get-process | ?{$_.Description -like "*cylance*"}
```

Invoke-AtomicTest T1518.001 -TestNumbers 2

### Atomic Test #3 - Security Software Discovery - ps
Methods to identify Security Software on an endpoint
when sucessfully executed, command shell  is going to display AV software it is running( Little snitch or carbon black ).

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
ps -ef | grep Little\ Snitch | grep -v grep
ps aux | grep CbOsxSensorService
ps aux | grep falcond
```

Invoke-AtomicTest T1518.001 -TestNumbers 3

### Atomic Test #4 - Security Software Discovery - Sysmon Service
Discovery of an installed Sysinternals Sysmon service using driver altitude (even if the name is changed).

when sucessfully executed, the test is going to display sysmon driver instance if it is installed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
fltmc.exe | findstr.exe 385201
```

Invoke-AtomicTest T1518.001 -TestNumbers 4

### Atomic Test #5 - Security Software Discovery - AV Discovery via WMI
Discovery of installed antivirus products via a WMI query.

when sucessfully executed, the test is going to display installed AV software.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic.exe /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List```

Invoke-AtomicTest T1518.001 -TestNumbers 5

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as lateral movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

In cloud environments, additionally monitor logs for the usage of APIs that may be used to gather information about security software configurations within the environment.