# T1056.001 - Input Capture: Keylogging
Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:

* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.
* Reading raw keystroke data from the hardware buffer.
* Windows Registry modifications.
* Custom drivers.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Input Capture
Utilize PowerShell and external resource to capture keystrokes
[Payload](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/src/Get-Keystrokes.ps1)
Provided by [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-Keystrokes.ps1)

Upon successful execution, Powershell will execute `Get-Keystrokes.ps1` and output to key.log.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Set-Location $PathToAtomicsFolder
.\T1056.001\src\Get-Keystrokes.ps1 -LogPath #{filepath}
```

Invoke-AtomicTest T1056.001 -TestNumbers 1

## Detection
Keyloggers may take many forms, possibly involving modification to the Registry and installation of a driver, setting a hook, or polling to intercept keystrokes. Commonly used API calls include `SetWindowsHook`, `GetKeyState`, and `GetAsyncKeyState`.(Citation: Adventures of a Keystroke) Monitor the Registry and file system for such changes, monitor driver installs, and look for common keylogging API calls. API calls alone are not an indicator of keylogging, but may provide behavioral data that is useful when combined with other information such as new files written to disk and unusual processes.