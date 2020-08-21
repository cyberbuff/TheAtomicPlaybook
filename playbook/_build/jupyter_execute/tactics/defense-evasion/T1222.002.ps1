# T1222.002 - File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification
Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Most Linux and Linux-based platforms provide a standard set of permission groups (user, group, and other) and a standard set of permissions (read, write, and execute) that are applied to each group. While nuances of each platform’s permissions implementation may vary, most of the platforms provide two primary commands used to manipulate file and directory ACLs: <code>chown</code> (short for change owner), and <code>chmod</code> (short for change mode).

Adversarial may use these commands to make themselves the owner of files and directories or change the mode if current permissions allow it. They could subsequently lock others out of the file. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [.bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004) or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - chmod - Change file or folder mode (numeric mode)
Changes a file or folder's permissions using chmod and a specified numeric mode.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chmod #{numeric_mode} #{file_or_folder}
```

Invoke-AtomicTest T1222.002 -TestNumbers 1

### Atomic Test #2 - chmod - Change file or folder mode (symbolic mode)
Changes a file or folder's permissions using chmod and a specified symbolic mode.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chmod #{symbolic_mode} #{file_or_folder}
```

Invoke-AtomicTest T1222.002 -TestNumbers 2

### Atomic Test #3 - chmod - Change file or folder mode (numeric mode) recursively
Changes a file or folder's permissions recursively using chmod and a specified numeric mode.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chmod #{numeric_mode} #{file_or_folder} -R
```

Invoke-AtomicTest T1222.002 -TestNumbers 3

### Atomic Test #4 - chmod - Change file or folder mode (symbolic mode) recursively
Changes a file or folder's permissions recursively using chmod and a specified symbolic mode.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chmod #{symbolic_mode} #{file_or_folder} -R
```

Invoke-AtomicTest T1222.002 -TestNumbers 4

### Atomic Test #5 - chown - Change file or folder ownership and group
Changes a file or folder's ownership and group information using chown.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chown #{owner}:#{group} #{file_or_folder}
```

Invoke-AtomicTest T1222.002 -TestNumbers 5

### Atomic Test #6 - chown - Change file or folder ownership and group recursively
Changes a file or folder's ownership and group information recursively using chown.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chown #{owner}:#{group} #{file_or_folder} -R
```

Invoke-AtomicTest T1222.002 -TestNumbers 6

### Atomic Test #7 - chown - Change file or folder mode ownership only
Changes a file or folder's ownership only using chown.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chown #{owner} #{file_or_folder}
```

Invoke-AtomicTest T1222.002 -TestNumbers 7

### Atomic Test #8 - chown - Change file or folder ownership recursively
Changes a file or folder's ownership only recursively using chown.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
chown #{owner} #{file_or_folder} -R
```

Invoke-AtomicTest T1222.002 -TestNumbers 8

### Atomic Test #9 - chattr - Remove immutable file attribute
Remove's a file's `immutable` attribute using `chattr`.
This technique was used by the threat actor Rocke during the compromise of Linux web servers.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
chattr -i #{file_to_modify}
```

Invoke-AtomicTest T1222.002 -TestNumbers 9

## Detection
Monitor and investigate attempts to modify ACLs and file/directory ownership. Many of the commands used to modify ACLs and file/directory ownership are built-in system utilities and may generate a high false positive alert rate, so compare against baseline knowledge for how systems are typically used and correlate modification events with other indications of malicious activity where possible.

Consider enabling file/directory permission change auditing on folders containing key binary/configuration files.