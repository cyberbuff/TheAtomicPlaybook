# T1543.003 - Create or Modify System Process: Windows Service
Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry. Service configurations can be modified using utilities such as sc.exe and [Reg](https://attack.mitre.org/software/S0075). 

Adversaries may install a new service or modify an existing service by using system utilities to interact with services, by directly modifying the Registry, or by using custom tools to interact with the Windows API. Adversaries may configure services to execute at startup in order to persist on a system.

An adversary may also incorporate [Masquerading](https://attack.mitre.org/techniques/T1036) by using a service name from a related operating system or benign software, or by modifying existing services to make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used. 

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002). 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Modify Fax service to run PowerShell
This test will temporarily modify the service Fax by changing the binPath to PowerShell
and will then revert the binPath change, restoring Fax to its original state.
Upon successful execution, cmd will modify the binpath for `Fax` to spawn powershell. Powershell will then spawn.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sc config Fax binPath= "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -c \"write-host 'T1543.003 Test'\""
sc start Fax
```

Invoke-AtomicTest T1543.003 -TestNumbers 1

### Atomic Test #2 - Service Installation CMD
Download an executable from github and start it as a service.
Upon successful execution, powershell will download `AtomicService.exe` from github. cmd.exe will spawn sc.exe which will create and start the service. Results will output via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sc.exe create #{service_name} binPath= #{binary_path}
sc.exe start #{service_name}
```

Invoke-AtomicTest T1543.003 -TestNumbers 2

### Atomic Test #3 - Service Installation PowerShell
Installs A Local Service via PowerShell.
Upon successful execution, powershell will download `AtomicService.exe` from github. Powershell will then use `New-Service` and `Start-Service` to start service. Results will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Service -Name "#{service_name}" -BinaryPathName "#{binary_path}"
Start-Service -Name "#{service_name}"
```

Invoke-AtomicTest T1543.003 -TestNumbers 3

## Detection
Monitor processes and command-line arguments for actions that could create or modify services. Command-line invocation of tools capable of adding or modifying services may be unusual, depending on how systems are typically used in a particular environment. Services may also be modified through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001), so additional logging may need to be configured to gather the appropriate data. Remote access tools with built-in features may also interact directly with the Windows API to perform these functions outside of typical system utilities. Collect service utility execution and service binary path arguments used for analysis. Service binary paths may even be changed to execute commands or scripts.  

Look for changes to service Registry entries that do not correlate with known software, patch cycles, etc. Service information is stored in the Registry at <code>HKLM\SYSTEM\CurrentControlSet\Services</code>. Changes to the binary path and the service startup type changed from manual or disabled to automatic, if it does not typically do so, may be suspicious. Tools such as Sysinternals Autoruns may also be used to detect system service changes that could be attempts at persistence.(Citation: TechNet Autoruns)  

Creation of new services may generate an alterable event (ex: Event ID 4697 and/or 7045 (Citation: Microsoft 4697 APR 2017)(Citation: Microsoft Windows Event Forwarding FEB 2018)). New, benign services may be created during installation of new software.

Suspicious program execution through services may show up as outlier processes that have not been seen before when compared against historical data. Look for abnormal process call trees from known services and for execution of other commands that could relate to Discovery or other adversary techniques. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.