# T1047 - Windows Management Instrumentation
Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) for remote access. RPCS operates over port 135. (Citation: MSDN WMI)

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - WMI Reconnaissance Users
An adversary might use WMI to list all local User Accounts. 
When the test completes , there should be local user accounts information displayed on the command line.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic useraccount get /ALL /format:csv
```

Invoke-AtomicTest T1047 -TestNumbers 1

### Atomic Test #2 - WMI Reconnaissance Processes
An adversary might use WMI to list Processes running on the compromised host.
When the test completes , there should be running processes listed on the command line.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic process get caption,executablepath,commandline /format:csv
```

Invoke-AtomicTest T1047 -TestNumbers 2

### Atomic Test #3 - WMI Reconnaissance Software
An adversary might use WMI to list installed Software hotfix and patches.
When the test completes, there should be a list of installed patches and when they were installed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic qfe get description,installedOn /format:csv
```

Invoke-AtomicTest T1047 -TestNumbers 3

### Atomic Test #4 - WMI Reconnaissance List Remote Services
An adversary might use WMI to check if a certain Remote Service is running on a remote device. 
When the test completes, a service information will be displayed on the screen if it exists.
A common feedback message is that "No instance(s) Available" if the service queried is not running.
A common error message is "Node - (provided IP or default)  ERROR Description =The RPC server is unavailable" 
if the provided remote host is unreacheable

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic /node:"#{node}" service where (caption like "%#{service_search_string}%")
```

Invoke-AtomicTest T1047 -TestNumbers 4

### Atomic Test #5 - WMI Execute Local Process
This test uses wmic.exe to execute a process on the local host.
When the test completes , a new process will be started locally .A notepad application will be started when input is left on default.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic process call create #{process_to_execute}
```

Invoke-AtomicTest T1047 -TestNumbers 5

### Atomic Test #6 - WMI Execute Remote Process
This test uses wmic.exe to execute a process on a remote host. Specify a valid value for remote IP using the node parameter.
To clean up, provide the same node input as the one provided to run the test
A common error message is "Node - (provided IP or default)  ERROR Description =The RPC server is unavailable" if the default or provided IP is unreachable

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic /node:"#{node}" process call create #{process_to_execute}
```

Invoke-AtomicTest T1047 -TestNumbers 6

## Detection
Monitor network traffic for WMI connections; the use of WMI in environments that do not typically use WMI may be suspect. Perform process monitoring to capture command-line arguments of "wmic" and detect commands that are used to perform remote behavior. (Citation: FireEye WMI 2015)