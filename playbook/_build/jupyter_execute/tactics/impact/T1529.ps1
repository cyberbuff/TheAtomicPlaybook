# T1529 - System Shutdown/Reboot
Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer.(Citation: Microsoft Shutdown Oct 2017) Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.

Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) or [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490), to hasten the intended effects on system availability.(Citation: Talos Nyetya June 2017)(Citation: Talos Olympic Destroyer 2018)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Shutdown System - Windows
This test shuts down a Windows system.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
shutdown /s /t #{timeout}
```

Invoke-AtomicTest T1529 -TestNumbers 1

### Atomic Test #2 - Restart System - Windows
This test restarts a Windows system.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
shutdown /r /t #{timeout}
```

Invoke-AtomicTest T1529 -TestNumbers 2

### Atomic Test #3 - Restart System via `shutdown` - macOS/Linux
This test restarts a macOS/Linux system.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
shutdown -r #{timeout}
```

Invoke-AtomicTest T1529 -TestNumbers 3

### Atomic Test #4 - Shutdown System via `shutdown` - macOS/Linux
This test shuts down a macOS/Linux system using a halt.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
shutdown -h #{timeout}
```

Invoke-AtomicTest T1529 -TestNumbers 4

### Atomic Test #5 - Restart System via `reboot` - macOS/Linux
This test restarts a macOS/Linux system via `reboot`.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `bash`
```bash
reboot
```

Invoke-AtomicTest T1529 -TestNumbers 5

### Atomic Test #6 - Shutdown System via `halt` - Linux
This test shuts down a Linux system using `halt`.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
halt -p
```

Invoke-AtomicTest T1529 -TestNumbers 6

### Atomic Test #7 - Reboot System via `halt` - Linux
This test restarts a Linux system using `halt`.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
halt --reboot
```

Invoke-AtomicTest T1529 -TestNumbers 7

### Atomic Test #8 - Shutdown System via `poweroff` - Linux
This test shuts down a Linux system using `poweroff`.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
poweroff
```

Invoke-AtomicTest T1529 -TestNumbers 8

### Atomic Test #9 - Reboot System via `poweroff` - Linux
This test restarts a Linux system using `poweroff`.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
poweroff --reboot
```

Invoke-AtomicTest T1529 -TestNumbers 9

## Detection
Use process monitoring to monitor the execution and command line parameters of binaries involved in shutting down or rebooting systems. Windows event logs may also designate activity associated with a shutdown/reboot, ex. Event ID 1074 and 6006.