# T1070.004 - Indicator Removal on Host: File Deletion
Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native [cmd](https://attack.mitre.org/software/S0106) functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools. (Citation: Trend Micro APT Attack Tools)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Delete a single file - Linux/macOS
Delete a single file from the temporary directory

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
rm -f #{file_to_delete}
```

Invoke-AtomicTest T1070.004 -TestNumbers 1

### Atomic Test #2 - Delete an entire folder - Linux/macOS
Recursively delete the temporary directory and all files contained within it

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
rm -rf #{folder_to_delete}
```

Invoke-AtomicTest T1070.004 -TestNumbers 2

### Atomic Test #3 - Overwrite and delete a file with shred
Use the `shred` command to overwrite the temporary file and then delete it

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
shred -u #{file_to_shred}
```

Invoke-AtomicTest T1070.004 -TestNumbers 3

### Atomic Test #4 - Delete a single file - Windows cmd
Delete a single file from the temporary directory using cmd.exe.
Upon execution, no output will be displayed. Use File Explorer to verify the file was deleted.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
del /f #{file_to_delete}
```

Invoke-AtomicTest T1070.004 -TestNumbers 4

### Atomic Test #5 - Delete an entire folder - Windows cmd
Recursively delete a folder in the temporary directory using cmd.exe.
Upon execution, no output will be displayed. Use File Explorer to verify the folder was deleted.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rmdir /s /q #{folder_to_delete}
```

Invoke-AtomicTest T1070.004 -TestNumbers 5

### Atomic Test #6 - Delete a single file - Windows PowerShell
Delete a single file from the temporary directory using Powershell. Upon execution, no output will be displayed. Use File Explorer to verify the file was deleted.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Remove-Item -path #{file_to_delete}
```

Invoke-AtomicTest T1070.004 -TestNumbers 6

### Atomic Test #7 - Delete an entire folder - Windows PowerShell
Recursively delete a folder in the temporary directory using Powershell. Upon execution, no output will be displayed. Use File Explorer to verify the folder was deleted.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Remove-Item -Path #{folder_to_delete} -Recurse
```

Invoke-AtomicTest T1070.004 -TestNumbers 7

### Atomic Test #8 - Delete Filesystem - Linux
This test deletes the entire root filesystem of a Linux system. This technique was used by Amnesia IoT malware to avoid analysis. This test is dangerous and destructive, do NOT use on production equipment.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
rm -rf / --no-preserve-root > /dev/null 2> /dev/null
```

Invoke-AtomicTest T1070.004 -TestNumbers 8

### Atomic Test #9 - Delete-PrefetchFile
Delete a single prefetch file.  Deletion of prefetch files is a known anti-forensic technique. To verify execution, Run "(Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" | Measure-Object).Count"
before and after the test to verify that the number of prefetch files decreases by 1.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])
```

Invoke-AtomicTest T1070.004 -TestNumbers 9

### Atomic Test #10 - Delete TeamViewer Log Files
Adversaries may delete TeamViewer log files to hide activity. This should provide a high true-positive alert ration.
This test just places the files in a non-TeamViewer folder, a detection would just check for a deletion event matching the TeamViewer
log file format of TeamViewer_##.log. Upon execution, no output will be displayed. Use File Explorer to verify the folder was deleted.

https://twitter.com/SBousseaden/status/1197524463304290305?s=20

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Remove-Item #{teamviewer_log_file}
```

Invoke-AtomicTest T1070.004 -TestNumbers 10

## Detection
It may be uncommon for events related to benign command-line functions such as DEL or third-party utilities or tools to be found in an environment, depending on the user base and how systems are typically used. Monitoring for command-line deletion functions to correlate with binaries or other files that an adversary may drop and remove may lead to detection of malicious activity. Another good practice is monitoring for known deletion and secure deletion tools that are not already on systems within an enterprise network that an adversary could introduce. Some monitoring tools may collect command-line arguments, but may not capture DEL commands since DEL is a native function within cmd.exe.