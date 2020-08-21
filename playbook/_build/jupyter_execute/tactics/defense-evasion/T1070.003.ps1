# T1070.003 - Indicator Removal on Host: Clear Command History
In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. macOS and Linux both keep track of the commands users type in their terminal so that users can retrace what they've done.

These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable <code>HISTFILE</code>. When a user logs off a system, this information is flushed to a file in the user's home directory called <code>~/.bash_history</code>. The benefit of this is that it allows users to go back to commands they've used before in different sessions.

Adversaries can use a variety of methods to prevent their own commands from appear in these logs, such as clearing the history environment variable (<code>unset HISTFILE</code>), setting the command history size to zero (<code>export HISTFILESIZE=0</code>), manually clearing the history (<code>history -c</code>), or deleting the bash history file <code>rm ~/.bash_history</code>.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Clear Bash history (rm)
Clears bash history via rm

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
rm ~/.bash_history
```

Invoke-AtomicTest T1070.003 -TestNumbers 1

### Atomic Test #2 - Clear Bash history (echo)
Clears bash history via rm

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
echo "" > ~/.bash_history
```

Invoke-AtomicTest T1070.003 -TestNumbers 2

### Atomic Test #3 - Clear Bash history (cat dev/null)
Clears bash history via cat /dev/null

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
cat /dev/null > ~/.bash_history
```

Invoke-AtomicTest T1070.003 -TestNumbers 3

### Atomic Test #4 - Clear Bash history (ln dev/null)
Clears bash history via a symlink to /dev/null

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
ln -sf /dev/null ~/.bash_history
```

Invoke-AtomicTest T1070.003 -TestNumbers 4

### Atomic Test #5 - Clear Bash history (truncate)
Clears bash history via truncate

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
truncate -s0 ~/.bash_history
```

Invoke-AtomicTest T1070.003 -TestNumbers 5

### Atomic Test #6 - Clear history of a bunch of shells
Clears the history of a bunch of different shell types by setting the history size to zero

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
unset HISTFILE
export HISTFILESIZE=0
history -c
```

Invoke-AtomicTest T1070.003 -TestNumbers 6

### Atomic Test #7 - Clear and Disable Bash History Logging
Clears the history and disable bash history logging of the current shell and future shell sessions

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
set +o history
echo 'set +o history' >> ~/.bashrc
. ~/.bashrc
history -c
```

Invoke-AtomicTest T1070.003 -TestNumbers 7

### Atomic Test #8 - Use Space Before Command to Avoid Logging to History
Using a space before a command causes the command to not be logged in the Bash History file

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
hostname
whoami
```

Invoke-AtomicTest T1070.003 -TestNumbers 8

## Detection
User authentication, especially via remote terminal services like SSH, without new entries in that user's <code>~/.bash_history</code> is suspicious. Additionally, the modification of the <code>HISTFILE</code> and <code>HISTFILESIZE</code> environment variables or the removal/clearing of the <code>~/.bash_history</code> file are indicators of suspicious activity.