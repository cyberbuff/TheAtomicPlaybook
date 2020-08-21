# T1059.003 - Command and Scripting Interpreter: Windows Command Shell
Adversaries may abuse the Windows command shell for execution. The Windows command shell (<code>cmd.exe</code>) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. 

Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may leverage <code>cmd.exe</code> to execute various commands and payloads. Common uses include <code>cmd.exe /c</code> to execute a single command, or abusing <code>cmd.exe</code> interactively with input and output forwarded over a command and control channel.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Create and Execute Batch Script
Creates and executes a simple batch script. Upon execution, CMD will briefly launh to run the batch script then close again.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Start-Process #{script_path}
```

Invoke-AtomicTest T1059.003 -TestNumbers 1

## Detection
Usage of the Windows command shell may be common on administrator, developer, or power user systems depending on job function. If scripting is restricted for normal users, then any attempt to enable scripts running on a system would be considered suspicious. If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching or other administrator functions are suspicious. Scripts should be captured from the file system when possible to determine their actions and intent.

Scripts are likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for script execution and subsequent behavior. Actions may be related to network and system information Discovery, Collection, or other scriptable post-compromise behaviors and could be used as indicators of detection leading back to the source script.