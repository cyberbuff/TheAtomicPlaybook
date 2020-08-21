# T1574.010 - Hijack Execution Flow: Services File Permissions Weakness
Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - File System Permissions Weakness
This test to show checking file system permissions weakness and which can lead to privilege escalation by replacing malicious file. Example; check weak file permission and then replace.
powershell -c "Get-WmiObject win32_service | select PathName"   (check service file location) and
copy /Y C:\temp\payload.exe C:\ProgramData\folder\Update\weakpermissionfile.exe   ( replace weak permission file with malicious file )

Upon execution, open the weak permission file at %temp%\T1574.010_weak_permission_file.txt and verify that it's contents read "T1574.010 Malicious file". To verify
the weak file permissions, open File Explorer to%temp%\T1574.010_weak_permission_file.exe then open Properties and Security to view the Full Control permission is enabled.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-WmiObject win32_service | select PathName
Copy-Item #{malicious_file} -Destination #{weak_permission_file} -Force
```

Invoke-AtomicTest T1574.010 -TestNumbers 1

## Detection
Look for changes to binaries and service executables that may normally occur during software updates. If an executable is written, renamed, and/or moved to match an existing service executable, it could be detected and correlated with other suspicious behavior. Hashing of binaries and service executables could be used to detect replacement against historical data.

Look for abnormal process call trees from typical processes and services and for execution of other commands that could relate to Discovery or other adversary techniques. 