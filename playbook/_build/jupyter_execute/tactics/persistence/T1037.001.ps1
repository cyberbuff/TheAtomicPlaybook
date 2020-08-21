# T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)
Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.(Citation: TechNet Logon Scripts) This is done via adding a path to a script to the <code>HKCU\Environment\UserInitMprLogonScript</code> Registry key.(Citation: Hexacorn Logon Scripts)

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Logon Scripts
Adds a registry value to run batch script created in the %temp% directory. Upon execution, there will be a new environment variable in the HKCU\Environment key
that can be viewed in the Registry Editor.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
echo "#{script_command}" > #{script_path}
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "#{script_path}" /f
```

Invoke-AtomicTest T1037.001 -TestNumbers 1

## Detection
Monitor for changes to Registry values associated with Windows logon scrips, nameley <code>HKCU\Environment\UserInitMprLogonScript</code>.

Monitor running process for actions that could be indicative of abnormal programs or executables running upon logon.