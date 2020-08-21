# T1546.013 - Event Triggered Execution: PowerShell Profile
Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments.

[PowerShell](https://attack.mitre.org/techniques/T1059/001) supports several profiles depending on the user or host program. For example, there can be different profiles for [PowerShell](https://attack.mitre.org/techniques/T1059/001) host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles) 

Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or [PowerShell](https://attack.mitre.org/techniques/T1059/001) drives to gain persistence. Every time a user opens a [PowerShell](https://attack.mitre.org/techniques/T1059/001) session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. (Citation: ESET Turla PowerShell May 2019) 

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator. (Citation: Wits End and Shady PowerShell Profiles)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Append malicious start-process cmdlet
Appends a start process cmdlet to the current user's powershell profile pofile that points to a malicious executable. Upon execution, calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Add-Content #{ps_profile} -Value ""
Add-Content #{ps_profile} -Value "Start-Process #{exe_path}"
powershell -Command exit
```

Invoke-AtomicTest T1546.013 -TestNumbers 1

## Detection
Locations where <code>profile.ps1</code> can be stored should be monitored for new profiles or modifications. (Citation: Malware Archaeology PowerShell Cheat Sheet) Example profile locations include:

* <code>$PsHome\Profile.ps1</code>
* <code>$PsHome\Microsoft.{HostProgram}_profile.ps1</code>
* <code>$Home\My Documents\PowerShell\Profile.ps1</code>
* <code>$Home\My Documents\PowerShell\Microsoft.{HostProgram}_profile.ps1</code>

Monitor abnormal PowerShell commands, unusual loading of PowerShell drives or modules, and/or execution of unknown programs.