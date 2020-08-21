# T1070.006 - Indicator Removal on Host: Timestomp
Adversaries may modify file time attributes to hide new or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools.

Timestomping may be used along with file name [Masquerading](https://attack.mitre.org/techniques/T1036) to hide malware and tools.(Citation: WindowsIR Anti-Forensic Techniques)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Set a file's access timestamp
Stomps on the access timestamp of a file

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
touch -a -t 197001010000.00 #{target_filename}
```

Invoke-AtomicTest T1070.006 -TestNumbers 1

### Atomic Test #2 - Set a file's modification timestamp
Stomps on the modification timestamp of a file

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
touch -m -t 197001010000.00 #{target_filename}
```

Invoke-AtomicTest T1070.006 -TestNumbers 2

### Atomic Test #3 - Set a file's creation timestamp
Stomps on the create timestamp of a file

Setting the creation timestamp requires changing the system clock and reverting.
Sudo or root privileges are required to change date. Use with caution.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
NOW=$(date)
date -s "1970-01-01 00:00:00"
touch #{target_filename}
date -s "$NOW"
stat #{target_filename}
```

Invoke-AtomicTest T1070.006 -TestNumbers 3

### Atomic Test #4 - Modify file timestamps using reference file
Modifies the `modify` and `access` timestamps using the timestamps of a specified reference file.

This technique was used by the threat actor Rocke during the compromise of Linux web servers.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
touch -acmr #{reference_file_path} #{target_file_path}
```

Invoke-AtomicTest T1070.006 -TestNumbers 4

### Atomic Test #5 - Windows - Modify file creation timestamp with PowerShell
Modifies the file creation timestamp of a specified file. This technique was seen in use by the Stitch RAT.
To verify execution, use File Explorer to view the Properties of the file and observe that the Created time is the year 1970.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-ChildItem #{file_path} | % { $_.CreationTime = "#{target_date_time}" }
```

Invoke-AtomicTest T1070.006 -TestNumbers 5

### Atomic Test #6 - Windows - Modify file last modified timestamp with PowerShell
Modifies the file last modified timestamp of a specified file. This technique was seen in use by the Stitch RAT.
To verify execution, use File Explorer to view the Properties of the file and observe that the Modified time is the year 1970.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-ChildItem #{file_path} | % { $_.LastWriteTime = "#{target_date_time}" }
```

Invoke-AtomicTest T1070.006 -TestNumbers 6

### Atomic Test #7 - Windows - Modify file last access timestamp with PowerShell
Modifies the last access timestamp of a specified file. This technique was seen in use by the Stitch RAT.
To verify execution, use File Explorer to view the Properties of the file and observe that the Accessed time is the year 1970.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-ChildItem #{file_path} | % { $_.LastAccessTime = "#{target_date_time}" }
```

Invoke-AtomicTest T1070.006 -TestNumbers 7

### Atomic Test #8 - Windows - Timestomp a File
Timestomp kxwn.lock.

Successful execution will include the placement of kxwn.lock in #{file_path} and execution of timestomp.ps1 to modify the time of the .lock file. 

[Mitre ATT&CK Evals](https://github.com/mitre-attack/attack-arsenal/blob/master/adversary_emulation/APT29/CALDERA_DIY/evals/data/abilities/defensive-evasion/4a2ad84e-a93a-4b2e-b1f0-c354d6a41278.yml)

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
import-module #{file_path}\timestomp.ps1
timestomp -dest "#{file_path}\kxwn.lock"
```

Invoke-AtomicTest T1070.006 -TestNumbers 8

## Detection
Forensic techniques exist to detect aspects of files that have had their timestamps modified. (Citation: WindowsIR Anti-Forensic Techniques) It may be possible to detect timestomping using file modification monitoring that collects information on file handle opens and can compare timestamp values.