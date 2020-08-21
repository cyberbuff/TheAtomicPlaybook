# T1115 - Clipboard Data
Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

In Windows, Applications can access clipboard data by using the Windows API.(Citation: MSDN Clipboard) OSX provides a native command, <code>pbpaste</code>, to grab clipboard contents.(Citation: Operating with EmPyre)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Utilize Clipboard to store or execute commands from
Add data to clipboard to copy off or execute commands from.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
dir | clip
echo "T1115" > %temp%\T1115.txt
clip < %temp%\T1115.txt
```

Invoke-AtomicTest T1115 -TestNumbers 1

### Atomic Test #2 - Execute Commands from Clipboard using PowerShell
Utilize PowerShell to echo a command to clipboard and execute it

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
echo Get-Process | clip
Get-Clipboard | iex
```

Invoke-AtomicTest T1115 -TestNumbers 2

## Detection
Access to the clipboard is a legitimate function of many applications on an operating system. If an organization chooses to monitor for this behavior, then the data will likely need to be correlated against other suspicious or non-user-driven activity.