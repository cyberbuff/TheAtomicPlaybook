# T1546.004 - Event Triggered Execution: .bash_profile and .bashrc
Adversaries may establish persistence by executing malicious content triggered by a user’s shell. <code>~/.bash_profile</code> and <code>~/.bashrc</code> are shell scripts that contain shell commands. These files are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly.

<code>~/.bash_profile</code> is executed for login shells and <code>~/.bashrc</code> is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), the <code>~/.bash_profile</code> script is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, the <code>~/.bashrc</code> script is executed. This allows users more fine-grained control over when they want certain commands executed. These shell scripts are meant to be written to by the local user to configure their own environment.

The macOS Terminal.app is a little different in that it runs a login shell by default each time a new terminal window is opened, thus calling <code>~/.bash_profile</code> each time instead of <code>~/.bashrc</code>.

Adversaries may abuse these shell scripts by inserting arbitrary shell commands that may be used to execute other binaries to gain persistence. Every time the user logs in or opens a new shell, the modified ~/.bash_profile and/or ~/.bashrc scripts will be executed.(Citation: amnesia malware)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Add command to .bash_profile
Adds a command to the .bash_profile file of the current user

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
echo "#{command_to_add}" >> ~/.bash_profile
```

Invoke-AtomicTest T1546.004 -TestNumbers 1

### Atomic Test #2 - Add command to .bashrc
Adds a command to the .bashrc file of the current user

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
echo "#{command_to_add}" >> ~/.bashrc
```

Invoke-AtomicTest T1546.004 -TestNumbers 2

## Detection
While users may customize their <code>~/.bashrc</code> and <code>~/.bash_profile</code> files , there are only certain types of commands that typically appear in these files. Monitor for abnormal commands such as execution of unknown programs, opening network sockets, or reaching out across the network when user profiles are loaded during the login process.