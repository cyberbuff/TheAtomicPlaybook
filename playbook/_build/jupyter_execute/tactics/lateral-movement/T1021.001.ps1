# T1021.001 - Remote Services: Remote Desktop Protocol
Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services) 

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1546/008) technique for Persistence.(Citation: Alperovitch Malware)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - RDPto-DomainController
Attempt an RDP session via Remote Desktop Application to a DomainController.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$Server=#{logonserver}
$User = Join-Path #{domain} #{username}
$Password="#{password}"
cmdkey /generic:TERMSRV/$Server /user:$User /pass:$Password
mstsc /v:$Server
echo "RDP connection established"
```

Invoke-AtomicTest T1021.001 -TestNumbers 1

### Atomic Test #2 - RDP to Server
Attempt an RDP session via Remote Desktop Application over Powershell

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$Server="#{logonserver}"
$User="#{username}"
$Password="#{password}"
cmdkey /generic:TERMSRV/$Server /user:$User /pass:$Password
mstsc /v:$Server
echo "RDP connection established"
```

Invoke-AtomicTest T1021.001 -TestNumbers 2

## Detection
Use of RDP may be legitimate, depending on the network environment and how it is used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior with RDP. Monitor for user accounts logged into systems they would not normally access or access patterns to multiple systems over a relatively short period of time.