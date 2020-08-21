# T1562.002 - Impair Defenses: Disable Windows Event Logging
Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more.(Citation: Windows Log Events) This data is used by security tools and analysts to generate detections.

Adversaries may targeting system-wide logging or just that of a particular application. By disabling Windows event logging, adversaries can operate while leaving less evidence of a compromise behind.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Disable Windows IIS HTTP Logging
Disables HTTP logging on a Windows IIS web server as seen by Threat Group 3390 (Bronze Union).
This action requires HTTP logging configurations in IIS to be unlocked.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
C:\Windows\System32\inetsrv\appcmd.exe set config "#{website_name}" /section:httplogging /dontLog:true
```

Invoke-AtomicTest T1562.002 -TestNumbers 1

## Detection
Monitor processes and command-line arguments for commands that can be used to disable logging. Lack of event logs may be suspicious.