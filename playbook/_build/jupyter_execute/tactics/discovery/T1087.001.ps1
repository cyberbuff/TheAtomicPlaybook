# T1087.001 - Account Discovery: Local Account
Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

Commands such as <code>net user</code> and <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility and <code>id</code> and <code>groups</code>on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated through the use of the <code>/etc/passwd</code> file.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Enumerate all accounts (Local)
Enumerate all accounts by copying /etc/passwd to another file

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
cat /etc/passwd > #{output_file}
cat #{output_file}
```

Invoke-AtomicTest T1087.001 -TestNumbers 1

### Atomic Test #2 - View sudoers access
(requires root)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
sudo cat /etc/sudoers > #{output_file}
cat #{output_file}
```

Invoke-AtomicTest T1087.001 -TestNumbers 2

### Atomic Test #3 - View accounts with UID 0
View accounts with UID 0

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
grep 'x:0:' /etc/passwd > #{output_file}
cat #{output_file} 2>/dev/null
```

Invoke-AtomicTest T1087.001 -TestNumbers 3

### Atomic Test #4 - List opened files by user
List opened files by user

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username
```

Invoke-AtomicTest T1087.001 -TestNumbers 4

### Atomic Test #5 - Show if a user account has ever logged in remotely
Show if a user account has ever logged in remotely

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
lastlog > #{output_file}
cat #{output_file}
```

Invoke-AtomicTest T1087.001 -TestNumbers 5

### Atomic Test #6 - Enumerate users and groups
Utilize groups and id to enumerate users and groups

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
groups
id
```

Invoke-AtomicTest T1087.001 -TestNumbers 6

### Atomic Test #7 - Enumerate users and groups
Utilize local utilities to enumerate users and groups

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
dscl . list /Groups
dscl . list /Users
dscl . list /Users | grep -v '_'
dscacheutil -q group
dscacheutil -q user
```

Invoke-AtomicTest T1087.001 -TestNumbers 7

### Atomic Test #8 - Enumerate all accounts on Windows (Local)
Enumerate all accounts
Upon exection, multiple enumeration commands will be run and their output displayed in the PowerShell session

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net user
dir c:\Users\
cmdkey.exe /list
net localgroup "Users"
net localgroup
```

Invoke-AtomicTest T1087.001 -TestNumbers 8

### Atomic Test #9 - Enumerate all accounts via PowerShell (Local)
Enumerate all accounts via PowerShell. Upon execution, lots of user account and group information will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
net user
get-localuser
get-localgroupmember -group Users
cmdkey.exe /list
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-localgroup
net localgroup
```

Invoke-AtomicTest T1087.001 -TestNumbers 9

### Atomic Test #10 - Enumerate logged on users via CMD (Local)
Enumerate logged on users. Upon exeuction, logged on users will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
query user
```

Invoke-AtomicTest T1087.001 -TestNumbers 10

### Atomic Test #11 - Enumerate logged on users via PowerShell
Enumerate logged on users via PowerShell. Upon exeuction, logged on users will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
query user
```

Invoke-AtomicTest T1087.001 -TestNumbers 11

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).