# T1053.003 - Scheduled Task/Job: Cron
Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code. The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.

An adversary may use <code>cron</code> in Linux or Unix environments to execute programs at system startup or on a scheduled basis for persistence. <code>cron</code> can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Cron - Replace crontab with referenced file
This test replaces the current user's crontab file with the contents of the referenced file. This technique was used by numerous IoT automated exploitation attacks.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
echo "* * * * * #{command}" > #{tmp_cron} && crontab #{tmp_cron}
```

Invoke-AtomicTest T1053.003 -TestNumbers 1

### Atomic Test #2 - Cron - Add script to cron folder
This test adds a script to a cron folder configured to execute on a schedule. This technique was used by the threat actor Rocke during the exploitation of Linux web servers.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
echo "#{command}" > /etc/cron.daily/#{cron_script_name}```

Invoke-AtomicTest T1053.003 -TestNumbers 2

## Detection
Monitor scheduled task creation from common utilities using command-line invocation. Legitimate scheduled tasks may be created during installation of new software or through system administration functions. Look for changes to tasks that do not correlate with known software, patch cycles, etc.  

Suspicious program execution through scheduled tasks may show up as outlier processes that have not been seen before when compared against historical data. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement. 