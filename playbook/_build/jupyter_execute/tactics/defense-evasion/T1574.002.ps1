# T1574.002 - Hijack Execution Flow: DLL Side-Loading
Adversaries may execute their own malicious payloads by hijacking the library manifest used to load DLLs. Adversaries may take advantage of vague references in the library manifest of a program by replacing a legitimate library with a malicious one, causing the operating system to load their malicious library when it is called for by the victim program.

Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests (Citation: About Side by Side Assemblies) are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable by replacing the legitimate DLL with a malicious one.  (Citation: FireEye DLL Side-Loading)

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - DLL Side-Loading using the Notepad++ GUP.exe binary
GUP is an open source signed binary used by Notepad++ for software updates, and is vulnerable to DLL Side-Loading, thus enabling the libcurl dll to be loaded.
Upon execution, calc.exe will be opened.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{gup_executable}
```

Invoke-AtomicTest T1574.002 -TestNumbers 1

## Detection
Monitor processes for unusual activity (e.g., a process that does not use the network begins to do so). Track DLL metadata, such as a hash, and compare DLLs that are loaded at process execution time against previous executions to detect differences that do not correlate with patching or updates.