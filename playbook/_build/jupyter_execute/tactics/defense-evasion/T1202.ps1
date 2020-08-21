# T1202 - Indirect Command Execution
Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking [cmd](https://attack.mitre.org/software/S0106). For example, [Forfiles](https://attack.mitre.org/software/S0193), the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)

Adversaries may abuse these features for [Defense Evasion](https://attack.mitre.org/tactics/TA0005), specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of [cmd](https://attack.mitre.org/software/S0106) or file extensions more commonly associated with malicious payloads.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Indirect Command Execution - pcalua.exe
The Program Compatibility Assistant (pcalua.exe) may invoke the execution of programs and commands from a Command-Line Interface.
[Reference](https://twitter.com/KyleHanslovan/status/912659279806640128)
Upon execution, calc.exe should open

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
pcalua.exe -a #{process}
pcalua.exe -a #{payload_path}
```

Invoke-AtomicTest T1202 -TestNumbers 1

### Atomic Test #2 - Indirect Command Execution - forfiles.exe
forfiles.exe may invoke the execution of programs and commands from a Command-Line Interface.
[Reference](https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Forfiles.md)
"This is basically saying for each occurrence of notepad.exe in c:\windows\system32 run calc.exe"
Upon execution calc.exe will be opened

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
forfiles /p c:\windows\system32 /m notepad.exe /c #{process}
forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"
```

Invoke-AtomicTest T1202 -TestNumbers 2

## Detection
Monitor and analyze logs from host-based detection mechanisms, such as Sysmon, for events such as process creations that include or are resulting from parameters associated with invoking programs/commands/files and/or spawning child processes/network connections. (Citation: RSA Forfiles Aug 2017)