# T1482 - Domain Trust Discovery
Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct [SID-History Injection](https://attack.mitre.org/techniques/T1134/005), [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003), and [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Windows - Discover domain trusts with dsquery
Uses the dsquery command to discover domain trusts.
Requires the installation of dsquery via Windows RSAT or the Windows Server AD DS role.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
dsquery * -filter "(objectClass=trustedDomain)" -attr *
```

Invoke-AtomicTest T1482 -TestNumbers 1

### Atomic Test #2 - Windows - Discover domain trusts with nltest
Uses the nltest command to discover domain trusts.
Requires the installation of nltest via Windows RSAT or the Windows Server AD DS role.
This technique has been used by the Trickbot malware family.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
nltest /domain_trusts
```

Invoke-AtomicTest T1482 -TestNumbers 2

### Atomic Test #3 - Powershell enumerate domains and forests
Use powershell to enumerate AD information.
Requires the installation of PowerShell AD admin cmdlets via Windows RSAT or the Windows Server AD DS role.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Import-Module "$env:TEMP\PowerView.ps1"
Get-NetDomainTrust
Get-NetForestTrust
Get-ADDomain
Get-ADGroupMember Administrators -Recursive
```

Invoke-AtomicTest T1482 -TestNumbers 3

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information, such as `nltest /domain_trusts`. Remote access tools with built-in features may interact directly with the Windows API to gather information. Look for the `DSEnumerateDomainTrusts()` Win32 API call to spot activity associated with [Domain Trust Discovery](https://attack.mitre.org/techniques/T1482).(Citation: Harmj0y Domain Trusts) Information may also be acquired through Windows system management tools such as [PowerShell](https://attack.mitre.org/techniques/T1059/001). The .NET method `GetAllTrustRelationships()` can be an indicator of [Domain Trust Discovery](https://attack.mitre.org/techniques/T1482).(Citation: Microsoft GetAllTrustRelationships)
