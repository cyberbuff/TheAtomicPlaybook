# T1119 - Automated Collection
Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. 

This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) to identify and move files.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Automated Collection Command Prompt
Automated Collection. Upon execution, check the users temp directory (%temp%) for the folder T1119_command_prompt_collection
to see what was collected.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mkdir %temp%\T1119_command_prompt_collection >nul 2>&1
dir c: /b /s .docx | findstr /e .docx
for /R c: %f in (*.docx) do copy %f %temp%\T1119_command_prompt_collection
```

Invoke-AtomicTest T1119 -TestNumbers 1

### Atomic Test #2 - Automated Collection PowerShell
Automated Collection. Upon execution, check the users temp directory (%temp%) for the folder T1119_powershell_collection
to see what was collected.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item -Path $env:TEMP\T1119_powershell_collection -ItemType Directory -Force | Out-Null
Get-ChildItem -Recurse -Include *.doc | % {Copy-Item $_.FullName -destination $env:TEMP\T1119_powershell_collection}
```

Invoke-AtomicTest T1119 -TestNumbers 2

### Atomic Test #3 - Recon information for export with PowerShell
collect information for exfiltration. Upon execution, check the users temp directory (%temp%) for files T1119_*.txt
to see what was collected.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-Service > $env:TEMP\T1119_1.txt
Get-ChildItem Env: > $env:TEMP\T1119_2.txt
Get-Process > $env:TEMP\T1119_3.txt
```

Invoke-AtomicTest T1119 -TestNumbers 3

### Atomic Test #4 - Recon information for export with Command Prompt
collect information for exfiltration. Upon execution, check the users temp directory (%temp%) for files T1119_*.txt
to see what was collected.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sc query type=service > %TEMP%\T1119_1.txt
doskey /history > %TEMP%\T1119_2.txt
wmic process list > %TEMP%\T1119_3.txt
tree C:\AtomicRedTeam\atomics > %TEMP%\T1119_4.txt
```

Invoke-AtomicTest T1119 -TestNumbers 4

## Detection
Depending on the method used, actions could include common file system commands and parameters on the command-line interface within batch files or scripts. A sequence of actions like this may be unusual, depending on the system and network environment. Automated collection may occur along with other techniques such as [Data Staged](https://attack.mitre.org/techniques/T1074). As such, file access monitoring that shows an unusual process performing sequential file opens and potentially copy actions to another location on the file system for many files at once may indicate automated collection behavior. Remote access tools with built-in features may interact directly with the Windows API to gather data. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).