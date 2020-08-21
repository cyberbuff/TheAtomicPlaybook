# T1036.003 - Masquerading: Rename System Utilities
Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. (Citation: LOLBAS Main Site) It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename <code>rundll32.exe</code>). (Citation: Endgame Masquerade Ball) An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths. (Citation: F-Secure CozyDuke)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Masquerading as Windows LSASS process
Copies cmd.exe, renames it, and launches it to masquerade as an instance of lsass.exe.

Upon execution, cmd will be launched by powershell. If using Invoke-AtomicTest, The test will hang until the 120 second timeout cancels the session

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
%SystemRoot%\Temp\lsass.exe /B
```

Invoke-AtomicTest T1036.003 -TestNumbers 1

### Atomic Test #2 - Masquerading as Linux crond process.
Copies sh process, renames it as crond, and executes it to masquerade as the cron daemon.

Upon successful execution, sh is renamed to `crond` and executed.

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
cp /bin/sh /tmp/crond;
/tmp/crond
```

Invoke-AtomicTest T1036.003 -TestNumbers 2

### Atomic Test #3 - Masquerading - cscript.exe running as notepad.exe
Copies cscript.exe, renames it, and launches it to masquerade as an instance of notepad.exe.

Upon successful execution, cscript.exe is renamed as notepad.exe and executed from non-standard path.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y
cmd.exe /c %APPDATA%\notepad.exe /B
```

Invoke-AtomicTest T1036.003 -TestNumbers 3

### Atomic Test #4 - Masquerading - wscript.exe running as svchost.exe
Copies wscript.exe, renames it, and launches it to masquerade as an instance of svchost.exe.

Upon execution, no windows will remain open but wscript will have been renamed to svchost and ran out of the temp folder

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y
cmd.exe /c %APPDATA%\svchost.exe /B
```

Invoke-AtomicTest T1036.003 -TestNumbers 4

### Atomic Test #5 - Masquerading - powershell.exe running as taskhostw.exe
Copies powershell.exe, renames it, and launches it to masquerade as an instance of taskhostw.exe.

Upon successful execution, powershell.exe is renamed as taskhostw.exe and executed from non-standard path.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y
cmd.exe /K %APPDATA%\taskhostw.exe
```

Invoke-AtomicTest T1036.003 -TestNumbers 5

### Atomic Test #6 - Masquerading - non-windows exe running as windows exe
Copies an exe, renames it as a windows exe, and launches it to masquerade as a real windows exe

Upon successful execution, powershell will execute T1036.003.exe as svchost.exe from on a non-standard path.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
copy #{inputfile} #{outputfile}
$myT1036_003 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036_003
```

Invoke-AtomicTest T1036.003 -TestNumbers 6

### Atomic Test #7 - Masquerading - windows exe running as different windows exe
Copies a windows exe, renames it as another windows exe, and launches it to masquerade as second windows exe

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
copy #{inputfile} #{outputfile}
$myT1036_003 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036_003
```

Invoke-AtomicTest T1036.003 -TestNumbers 7

### Atomic Test #8 - Malicious process Masquerading as LSM.exe
Detect LSM running from an incorrect directory and an incorrect service account
This works by copying cmd.exe to a file, naming it lsm.exe, then copying a file to the C:\ folder.

Upon successful execution, cmd.exe will be renamed as lsm.exe and executed from non-standard path.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy C:\Windows\System32\cmd.exe C:\lsm.exe
C:\lsm.exe /c echo T1036.003 > C:\T1036.003.txt
```

Invoke-AtomicTest T1036.003 -TestNumbers 8

### Atomic Test #9 - File Extension Masquerading
download and execute a file masquerading as images or Office files. Upon execution 3 calc instances and 3 vbs windows will be launched.

e.g SOME_LEGIT_NAME.[doc,docx,xls,xlsx,pdf,rtf,png,jpg,etc.].[exe,vbs,js,ps1,etc] (Quartelyreport.docx.exe)

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy #{exe_path} %temp%\T1036.003_masquerading.docx.exe /Y
copy #{exe_path} %temp%\T1036.003_masquerading.pdf.exe /Y
copy #{exe_path} %temp%\T1036.003_masquerading.ps1.exe /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.xls.vbs /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.xlsx.vbs /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.png.vbs /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.doc.ps1 /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.pdf.ps1 /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.rtf.ps1 /Y
%temp%\T1036.003_masquerading.docx.exe
%temp%\T1036.003_masquerading.pdf.exe
%temp%\T1036.003_masquerading.ps1.exe
%temp%\T1036.003_masquerading.xls.vbs
%temp%\T1036.003_masquerading.xlsx.vbs
%temp%\T1036.003_masquerading.png.vbs
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.doc.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.pdf.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.rtf.ps1
```

Invoke-AtomicTest T1036.003 -TestNumbers 9

## Detection
If file names are mismatched between the file name on disk and that of the binary's PE metadata, this is a likely indicator that a binary was renamed after it was compiled. Collecting and comparing disk and resource filenames for binaries by looking to see if the InternalName, OriginalFilename, and/or ProductName match what is expected could provide useful leads, but may not always be indicative of malicious activity. (Citation: Endgame Masquerade Ball) Do not focus on the possible names a file could have, but instead on the command-line arguments that are known to be used and are distinct because it will have a better rate of detection.(Citation: Twitter ItsReallyNick Masquerading Update)