# T1070.002 - Indicator Removal on Host: Clear Linux or Mac System Logs
Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the <code>/var/log/</code> directory. Subfolders in this directory categorize logs by their related functions, such as:(Citation: Linux Logs)

* <code>/var/log/messages:</code>: General and system-related messages
* <code>/var/log/secure</code> or <code>/var/log/auth.log</code>: Authentication logs
* <code>/var/log/utmp</code> or <code>/var/log/wtmp</code>: Login records
* <code>/var/log/kern.log</code>: Kernel logs
* <code>/var/log/cron.log</code>: Crond logs
* <code>/var/log/maillog</code>: Mail server logs
* <code>/var/log/httpd/</code>: Web server access and error logs


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - rm -rf
Delete system and audit logs

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
sudo rm -rf /private/var/log/system.log*
sudo rm -rf /private/var/audit/*
```

Invoke-AtomicTest T1070.002 -TestNumbers 1

### Atomic Test #2 - Overwrite Linux Mail Spool
This test overwrites the Linux mail spool of a specified user. This technique was used by threat actor Rocke during the exploitation of Linux web servers.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
echo 0> /var/spool/mail/#{username}
```

Invoke-AtomicTest T1070.002 -TestNumbers 2

### Atomic Test #3 - Overwrite Linux Log
This test overwrites the specified log. This technique was used by threat actor Rocke during the exploitation of Linux web servers.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
echo 0> #{log_path}
```

Invoke-AtomicTest T1070.002 -TestNumbers 3

## Detection
File system monitoring may be used to detect improper deletion or modification of indicator files. Also monitor for suspicious processes interacting with log files.