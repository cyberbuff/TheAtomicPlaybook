# T1216 - Signed Script Proxy Execution
Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.(Citation: GitHub Ultimate AppLocker Bypass List)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - SyncAppvPublishingServer Signed Script PowerShell Command Execution
Executes the signed SyncAppvPublishingServer script with options to execute an arbitrary PowerShell command.
Upon execution, calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\windows\system32\SyncAppvPublishingServer.vbs "\n;#{command_to_execute}"
```

Invoke-AtomicTest T1216 -TestNumbers 1

### Atomic Test #2 - manage-bde.wsf Signed Script Command Execution
Executes the signed manage-bde.wsf script with options to execute an arbitrary command.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
set comspec=#{command_to_execute}
cscript %windir%\System32\manage-bde.wsf
```

Invoke-AtomicTest T1216 -TestNumbers 2

## Detection
Monitor script processes, such as `cscript`, and command-line parameters for scripts like PubPrn.vbs that may be used to proxy execution of malicious files.