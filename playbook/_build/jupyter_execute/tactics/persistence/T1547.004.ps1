# T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL
Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\Software[\\Wow6432Node\\]\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> and <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> are used to manage additional helper programs and functionalities that support Winlogon. (Citation: Cylance Reg Persistence Sept 2013) 

Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse: (Citation: Cylance Reg Persistence Sept 2013)

* Winlogon\Notify - points to notification package DLLs that handle Winlogon events
* Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on
* Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on

Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Winlogon Shell Key Persistence - PowerShell
PowerShell code to set Winlogon shell key to execute a binary at logon along with explorer.exe.

Upon successful execution, PowerShell will modify a registry value to execute cmd.exe upon logon/logoff.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, #{binary_to_execute}" -Force
```

Invoke-AtomicTest T1547.004 -TestNumbers 1

### Atomic Test #2 - Winlogon Userinit Key Persistence - PowerShell
PowerShell code to set Winlogon userinit key to execute a binary at logon along with userinit.exe.

Upon successful execution, PowerShell will modify a registry value to execute cmd.exe upon logon/logoff.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, #{binary_to_execute}" -Force
```

Invoke-AtomicTest T1547.004 -TestNumbers 2

### Atomic Test #3 - Winlogon Notify Key Logon Persistence - PowerShell
PowerShell code to set Winlogon Notify key to execute a notification package DLL at logon.

Upon successful execution, PowerShell will modify a registry value to execute atomicNotificationPackage.dll upon logon/logoff.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -Force
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" "logon" "#{binary_to_execute}" -Force
```

Invoke-AtomicTest T1547.004 -TestNumbers 3

## Detection
Monitor for changes to Registry entries associated with Winlogon that do not correlate with known software, patch cycles, etc. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current Winlogon helper values. (Citation: TechNet Autoruns)  New DLLs written to System32 that do not correlate with known good software or patching may also be suspicious.

Look for abnormal process behavior that may be due to a process loading a malicious DLL. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.