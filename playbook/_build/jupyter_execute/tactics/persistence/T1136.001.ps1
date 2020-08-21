# T1136.001 - Create Account: Local Account
Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. With a sufficient level of access, the <code>net user /add</code> command can be used to create a local account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Create a user account on a Linux system
Create a user via useradd

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
useradd -M -N -r -s /bin/bash -c evil_account #{username}
```

Invoke-AtomicTest T1136.001 -TestNumbers 1

### Atomic Test #2 - Create a user account on a MacOS system
Creates a user on a MacOS system with dscl

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
dscl . -create /Users/#{username}
dscl . -create /Users/#{username} UserShell /bin/zsh
dscl . -create /Users/#{username} RealName "#{realname}"
dscl . -create /Users/#{username} UniqueID "1010"
dscl . -create /Users/#{username} PrimaryGroupID 80
dscl . -create /Users/#{username} NFSHomeDirectory /Users/#{username}
```

Invoke-AtomicTest T1136.001 -TestNumbers 2

### Atomic Test #3 - Create a new user in a command prompt
Creates a new user in a command prompt. Upon execution, "The command completed successfully." will be displayed. To verify the
new account, run "net user" in powershell or CMD and observe that there is a new user named "T1136.001_CMD"

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net user /add "#{username}" "#{password}"
```

Invoke-AtomicTest T1136.001 -TestNumbers 3

### Atomic Test #4 - Create a new user in PowerShell
Creates a new user in PowerShell. Upon execution, details about the new account will be displayed in the powershell session. To verify the
new account, run "net user" in powershell or CMD and observe that there is a new user named "T1136.001_PowerShell"

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-LocalUser -Name "#{username}" -NoPassword
```

Invoke-AtomicTest T1136.001 -TestNumbers 4

### Atomic Test #5 - Create a new user in Linux with `root` UID and GID.
Creates a new user in Linux and adds the user to the `root` group. This technique was used by adversaries during the Butter attack campaign.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
useradd -g 0 -M -d /root -s /bin/bash #{username}
if [ $(cat /etc/os-release | grep -i 'Name="ubuntu"') ]; then echo "#{username}:#{password}" | sudo chpasswd; else echo "#{password}" | passwd --stdin #{username}; fi;
```

Invoke-AtomicTest T1136.001 -TestNumbers 5

### Atomic Test #6 - Create a new Windows admin user
Creates a new admin user in a command prompt.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net user /add "#{username}" "#{password}"
net localgroup administrators "#{username}" /add
```

Invoke-AtomicTest T1136.001 -TestNumbers 6

## Detection
Monitor for processes and command-line parameters associated with local account creation, such as <code>net user /add</code> or <code>useradd</code>. Collect data on account creation within a network. Event ID 4720 is generated when a user account is created on a Windows system. (Citation: Microsoft User Creation Event) Perform regular audits of local system accounts to detect suspicious accounts that may have been created by an adversary.