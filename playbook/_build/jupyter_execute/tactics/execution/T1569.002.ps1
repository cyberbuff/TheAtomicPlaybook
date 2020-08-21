# T1569.002 - System Services: Service Execution
Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (<code>services.exe</code>) is an interface to manage and manipulate services.(Citation: Microsoft Service Control Manager) The service control manager is accessible to users via GUI components as well as system utilities such as <code>sc.exe</code> and [Net](https://attack.mitre.org/software/S0039).

[PsExec](https://attack.mitre.org/software/S0029) can also be used to execute commands or payloads via a temporary Windows service created through the service control manager API.(Citation: Russinovich Sysinternals)

Adversaries may leverage these mechanisms to execute malicious content. This can be done by either executing a new or modified service. This technique is the execution used in conjunction with [Windows Service](https://attack.mitre.org/techniques/T1543/003) during service persistence or privilege escalation.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Execute a Command as a Service
Creates a service specifying an aribrary command and executes it. When executing commands such as PowerShell, the service will report that it did not start correctly even when code executes properly.

Upon successful execution, cmd.exe create a new service using sc.exe create that will start powershell.exe to create a new file `art-marker.txt`

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sc.exe create #{service_name} binPath= "#{executable_command}"
sc.exe start #{service_name}
sc.exe delete #{service_name}
```

Invoke-AtomicTest T1569.002 -TestNumbers 1

### Atomic Test #2 - Use PsExec to execute a command on a remote host
Requires having Sysinternals installed, path to sysinternals is one of the input input_arguments
Will run a command on a remote host.

Upon successful execution, powershell will download psexec.exe and spawn calc.exe on a remote endpoint (default:localhost).

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
#{psexec_exe} \\#{remote_host} -accepteula "C:\Windows\System32\calc.exe"
```

Invoke-AtomicTest T1569.002 -TestNumbers 2

## Detection
Changes to service Registry entries and command line invocation of tools capable of modifying services that do not correlate with known software, patch cycles, etc., may be suspicious. If a service is used only to execute a binary or script and not to persist, then it will likely be changed back to its original form shortly after the service is restarted so the service is not left broken, as is the case with the common administrator tool [PsExec](https://attack.mitre.org/software/S0029).