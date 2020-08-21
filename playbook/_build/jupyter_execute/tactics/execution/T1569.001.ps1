# T1569.001 - System Services: Launchctl
Adversaries may abuse launchctl to execute commands or programs. Launchctl controls the macOS launchd process, which handles things like [Launch Agent](https://attack.mitre.org/techniques/T1543/001)s and [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)s, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.(Citation: Launchctl Man)

By loading or reloading [Launch Agent](https://attack.mitre.org/techniques/T1543/001)s or [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)s, adversaries can install persistence or execute changes they made.(Citation: Sofacy Komplex Trojan)

Running a command from launchctl is as simple as <code>launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg"</code>. Adversaries can abuse this functionality to execute code or even bypass application control if launchctl is an allowed process.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Launchctl
Utilize launchctl

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
launchctl submit -l #{label_name} -- #{executable_path}
```

Invoke-AtomicTest T1569.001 -TestNumbers 1

## Detection
KnockKnock can be used to detect persistent programs such as those installed via launchctl as launch agents or launch daemons. Additionally, every launch agent or launch daemon must have a corresponding plist file on disk which can be monitored. Monitor process execution from launchctl/launchd for unusual or unknown processes.