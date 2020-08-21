# T1201 - Password Policy Discovery
Adversaries may attempt to access detailed information about the password policy used within an enterprise network. Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).

Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as <code>net accounts (/domain)</code>, <code>chage -l <username></code>, <code>cat /etc/pam.d/common-password</code>, and <code>pwpolicy getaccountpolicies</code>.(Citation: Superuser Linux Password Policies) (Citation: Jamf User Password Policies)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Examine password complexity policy - Ubuntu
Lists the password complexity policy to console on Ubuntu Linux.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
cat /etc/pam.d/common-password
```

Invoke-AtomicTest T1201 -TestNumbers 1

### Atomic Test #2 - Examine password complexity policy - CentOS/RHEL 7.x
Lists the password complexity policy to console on CentOS/RHEL 7.x Linux.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
cat /etc/security/pwquality.conf
```

Invoke-AtomicTest T1201 -TestNumbers 2

### Atomic Test #3 - Examine password complexity policy - CentOS/RHEL 6.x
Lists the password complexity policy to console on CentOS/RHEL 6.x Linux.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
cat /etc/pam.d/system-auth
cat /etc/security/pwquality.conf
```

Invoke-AtomicTest T1201 -TestNumbers 3

### Atomic Test #4 - Examine password expiration policy - All Linux
Lists the password expiration policy to console on CentOS/RHEL/Ubuntu.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
cat /etc/login.defs
```

Invoke-AtomicTest T1201 -TestNumbers 4

### Atomic Test #5 - Examine local password policy - Windows
Lists the local password policy to console on Windows.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net accounts
```

Invoke-AtomicTest T1201 -TestNumbers 5

### Atomic Test #6 - Examine domain password policy - Windows
Lists the domain password policy to console on Windows.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net accounts /domain
```

Invoke-AtomicTest T1201 -TestNumbers 6

### Atomic Test #7 - Examine password policy - macOS
Lists the password policy to console on macOS.

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
pwpolicy getaccountpolicies```

Invoke-AtomicTest T1201 -TestNumbers 7

## Detection
Monitor processes for tools and command line arguments that may indicate they're being used for password policy discovery. Correlate that activity with other suspicious activity from the originating system to reduce potential false positives from valid user or administrator activity. Adversaries will likely attempt to find the password policy early in an operation and the activity is likely to happen with other Discovery activity.