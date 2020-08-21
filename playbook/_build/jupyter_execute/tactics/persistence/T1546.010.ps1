# T1546.010 - Event Triggered Execution: AppInit DLLs
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Endgame Process Injection July 2017)

Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. 

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Install AppInit Shim
AppInit_DLLs is a mechanism that allows an arbitrary list of DLLs to be loaded into each user mode process on the system. Upon succesfully execution, 
you will see the message "The operation completed successfully." Each time the DLL is loaded, you will see a message box with a message of "Install AppInit Shim DLL was called!" appear.
This will happen regularly as your computer starts up various applications and may in fact drive you crazy. A reliable way to make the message box appear and verify the 
AppInit Dlls are loading is to start the notepad application. Be sure to run the cleanup commands afterwards so you don't keep getting message boxes showing up

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg.exe import #{registry_file}
```

Invoke-AtomicTest T1546.010 -TestNumbers 1

## Detection
Monitor DLL loads by processes that load user32.dll and look for DLLs that are not recognized or not normally loaded into a process. Monitor the AppInit_DLLs Registry values for modifications that do not correlate with known software, patch cycles, etc. Monitor and analyze application programming interface (API) calls that are indicative of Registry edits such as <code>RegCreateKeyEx</code> and <code>RegSetValueEx</code>. (Citation: Endgame Process Injection July 2017)

Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current AppInit DLLs. (Citation: TechNet Autoruns) 

Look for abnormal process behavior that may be due to a process loading a malicious DLL. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as making network connections for Command and Control, learning details about the environment through Discovery, and conducting Lateral Movement.