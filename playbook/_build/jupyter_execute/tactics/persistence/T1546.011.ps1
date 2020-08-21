# T1546.011 - Event Triggered Execution: Application Shimming
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. (Citation: Endgame Process Injection July 2017)

Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS. 

A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in:

* <code>%WINDIR%\AppPatch\sysmain.sdb</code> and
* <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb</code>

Custom databases are stored in:

* <code>%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom</code> and
* <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom</code>

To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to [Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002) (UAC and RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress).

Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. (Citation: FireEye Application Shimming) Shims can also be abused to establish persistence by continuously being invoked by affected programs.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Application Shim Installation
Install a shim database. This technique is used for privilege escalation and bypassing user access control.
Upon execution, "Installation of AtomicShim complete." will be displayed. To verify the shim behavior, run 
the AtomicTest.exe from the <PathToAtomicsFolder>\\T1546.011\\bin directory. You should see a message box appear
with "Atomic Shim DLL Test!" as defined in the AtomicTest.dll. To better understand what is happening, review
the source code files is the <PathToAtomicsFolder>\\T1546.011\\src directory.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sdbinst.exe #{file_path}
```

Invoke-AtomicTest T1546.011 -TestNumbers 1

### Atomic Test #2 - New shim database files created in the default shim database directory
Upon execution, check the "C:\Windows\apppatch\Custom\" folder for the new shim database

https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Copy-Item $PathToAtomicsFolder\T1546.011\bin\T1546.011CompatDatabase.sdb C:\Windows\apppatch\Custom\T1546.011CompatDatabase.sdb
Copy-Item $PathToAtomicsFolder\T1546.011\bin\T1546.011CompatDatabase.sdb C:\Windows\apppatch\Custom\Custom64\T1546.011CompatDatabase.sdb
```

Invoke-AtomicTest T1546.011 -TestNumbers 2

### Atomic Test #3 - Registry key creation and/or modification events for SDB
Create registry keys in locations where fin7 typically places SDB patches. Upon execution, output will be displayed describing
the registry keys that were created. These keys can also be viewed using the Registry Editor.

https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-ItemProperty -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" -Name "AtomicRedTeamT1546.011" -Value "AtomicRedTeamT1546.011"
New-ItemProperty -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" -Name "AtomicRedTeamT1546.011" -Value "AtomicRedTeamT1546.011"
```

Invoke-AtomicTest T1546.011 -TestNumbers 3

## Detection
There are several public tools available that will detect shims that are currently available (Citation: Black Hat 2015 App Shim):

* Shim-Process-Scanner - checks memory of every running process for any shim flags
* Shim-Detector-Lite - detects installation of custom shim databases
* Shim-Guard - monitors registry for any shim installations
* ShimScanner - forensic tool to find active shims in memory
* ShimCacheMem - Volatility plug-in that pulls shim cache from memory (note: shims are only cached after reboot)

Monitor process execution for sdbinst.exe and command-line arguments for potential indications of application shim abuse.