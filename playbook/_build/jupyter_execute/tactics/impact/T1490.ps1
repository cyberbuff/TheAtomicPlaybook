# T1490 - Inhibit System Recovery
Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486).(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017)

A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:

* <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - <code>vssadmin.exe delete shadows /all /quiet</code>
* [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) can be used to delete volume shadow copies - <code>wmic shadowcopy delete</code>
* <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - <code>wbadmin.exe delete catalog -quiet</code>
* <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no</code>

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Windows - Delete Volume Shadow Copies
Deletes Windows Volume Shadow Copies. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer. Upon
execution, if no shadow volumes exist the message "No items found that satisfy the query." will be displayed. If shadow volumes are present, it
will delete them without printing output to the screen. This is because the /quiet parameter was passed which also suppresses the y/n
confirmation prompt. Shadow copies can only be created on Windows server or Windows 8.

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc788055(v=ws.11)

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
vssadmin.exe delete shadows /all /quiet
```

Invoke-AtomicTest T1490 -TestNumbers 1

### Atomic Test #2 - Windows - Delete Volume Shadow Copies via WMI
Deletes Windows Volume Shadow Copies via WMI. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer.
Shadow copies can only be created on Windows server or Windows 8.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic.exe shadowcopy delete
```

Invoke-AtomicTest T1490 -TestNumbers 2

### Atomic Test #3 - Windows - Delete Windows Backup Catalog
Deletes Windows Backup Catalog. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer. Upon execution,
"The backup catalog has been successfully deleted." will be displayed in the PowerShell session.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wbadmin.exe delete catalog -quiet
```

Invoke-AtomicTest T1490 -TestNumbers 3

### Atomic Test #4 - Windows - Disable Windows Recovery Console Repair
Disables repair by the Windows Recovery Console on boot. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer.
Upon execution, "The operation completed successfully." will be displayed in the powershell session.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
```

Invoke-AtomicTest T1490 -TestNumbers 4

### Atomic Test #5 - Windows - Delete Volume Shadow Copies via WMI with PowerShell
Deletes Windows Volume Shadow Copies with PowerShell code and Get-WMIObject.
This technique is used by numerous ransomware families such as Sodinokibi/REvil.
Executes Get-WMIObject. Shadow copies can only be created on Windows server or Windows 8, so upon execution
there may be no output displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```

Invoke-AtomicTest T1490 -TestNumbers 5

### Atomic Test #6 - Windows - Delete Backup Files
Deletes backup files in a manner similar to Ryuk ransomware. Upon exection, many "access is denied" messages will appear as the commands try
to delete files from around the system.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk
```

Invoke-AtomicTest T1490 -TestNumbers 6

## Detection
Use process monitoring to monitor the execution and command line parameters of binaries involved in inhibiting system recovery, such as vssadmin, wbadmin, and bcdedit. The Windows event logs, ex. Event ID 524 indicating a system catalog was deleted, may contain entries associated with suspicious activity.

Monitor the status of services involved in system recovery. Monitor the registry for changes associated with system recovery features (ex: the creation of <code>HKEY_CURRENT_USER\Software\Policies\Microsoft\PreviousVersions\DisableLocalPage</code>).