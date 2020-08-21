# T1560 - Archive Collected Data
An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.

Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Compress Data for Exfiltration With PowerShell
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration.
When the test completes you should find the files from the $env:USERPROFILE directory compressed in a file called T1560-data-ps.zip in the $env:USERPROFILE directory 

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}
```

Invoke-AtomicTest T1560 -TestNumbers 1

## Detection
Archival software and archived files can be detected in many ways. Common utilities that may be present on the system or brought in by an adversary may be detectable through process monitoring and monitoring for command-line arguments for known archival utilities. This may yield a significant number of benign events, depending on how systems in the environment are typically used.

A process that loads the Windows DLL crypt32.dll may be used to perform encryption, decryption, or verification of file signatures.

Consider detecting writing of files with extensions and/or headers associated with compressed or encrypted file types. Detection efforts may focus on follow-on exfiltration activity, where compressed or encrypted files can be detected in transit with a network intrusion detection or data loss prevention system analyzing file headers.(Citation: Wikipedia File Header Signatures)