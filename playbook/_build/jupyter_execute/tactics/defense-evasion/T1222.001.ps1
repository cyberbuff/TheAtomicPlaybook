# T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification
Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Windows implements file and directory ACLs as Discretionary Access Control Lists (DACLs).(Citation: Microsoft DACL May 2018) Similar to a standard ACL, DACLs identifies the accounts that are allowed or denied access to a securable object. When an attempt is made to access a securable object, the system checks the access control entries in the DACL in order. If a matching entry is found, access to the object is granted. Otherwise, access is denied.(Citation: Microsoft Access Control Lists May 2018)

Adversaries can interact with the DACLs using built-in Windows commands, such as `icacls`, `takeown`, and `attrib`, which can grant adversaries higher permissions on specific files and folders. Further, [PowerShell](https://attack.mitre.org/techniques/T1059/001) provides cmdlets that can be used to retrieve or modify file and directory DACLs. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Take ownership using takeown utility
Modifies the filesystem permissions of the specified file or folder to take ownership of the object. Upon execution, "SUCCESS" will
be displayed for the folder and each file inside of it.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
takeown.exe /f #{file_folder_to_own} /r
```

Invoke-AtomicTest T1222.001 -TestNumbers 1

### Atomic Test #2 - cacls - Grant permission to specified user or group recursively
Modifies the filesystem permissions of the specified folder and contents to allow the specified user or group Full Control. If "Access is denied"
is displayed it may be because the file or folder doesn't exit. Run the prereq command to create it. Upon successfull execution, "Successfully processed 3 files"
will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
Icacls.exe #{file_or_folder} /grant #{user_or_group}:F
```

Invoke-AtomicTest T1222.001 -TestNumbers 2

### Atomic Test #3 - attrib - Remove read-only attribute
Removes the read-only attribute from a file or folder using the attrib.exe command. Upon execution, no output will be displayed.
Open the file in File Explorer > Right Click - Prperties and observe that the Read Only checkbox is empty.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
attrib.exe -r #{file_or_folder}\*.* /s
```

Invoke-AtomicTest T1222.001 -TestNumbers 3

## Detection
Monitor and investigate attempts to modify DACLs and file/directory ownership. Many of the commands used to modify DACLs and file/directory ownership are built-in system utilities and may generate a high false positive alert rate, so compare against baseline knowledge for how systems are typically used and correlate modification events with other indications of malicious activity where possible.

Consider enabling file/directory permission change auditing on folders containing key binary/configuration files. For example, Windows Security Log events (Event ID 4670) are created when DACLs are modified.(Citation: EventTracker File Permissions Feb 2014)