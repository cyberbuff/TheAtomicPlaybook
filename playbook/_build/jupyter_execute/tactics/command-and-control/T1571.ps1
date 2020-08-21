# T1571 - Non-Standard Port
Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Testing usage of uncommonly used port with PowerShell
Testing uncommonly used port utilizing PowerShell. APT33 has been known to attempt telnet over port 8081. Upon execution, details about the successful
port check will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Test-NetConnection -ComputerName #{domain} -port #{port}
```

Invoke-AtomicTest T1571 -TestNumbers 1

### Atomic Test #2 - Testing usage of uncommonly used port
Testing uncommonly used port utilizing telnet.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
telnet #{domain} #{port}
```

Invoke-AtomicTest T1571 -TestNumbers 2

## Detection
Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.(Citation: University of Birmingham C2)