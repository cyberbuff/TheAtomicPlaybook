# T1010 - Application Window Discovery
Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - List Process Main Windows - C# .NET
Compiles and executes C# code to list main window titles associated with each process.

Upon successful execution, powershell will download the .cs from the Atomic Red Team repo, and cmd.exe will compile and execute T1010.exe. Upon T1010.exe execution, expected output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:#{output_file_name} #{input_source_code}
#{output_file_name}
```

Invoke-AtomicTest T1010 -TestNumbers 1

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).