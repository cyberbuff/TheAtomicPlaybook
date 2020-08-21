# T1218.007 - Signed Binary Proxy Execution: Msiexec
Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi).(Citation: Microsoft msiexec) Msiexec.exe is digitally signed by Microsoft.

Adversaries may abuse msiexec.exe to launch local or network accessible MSI files. Msiexec.exe can also execute DLLs.(Citation: LOLBAS Msiexec)(Citation: TrendMicro Msiexec Feb 2018) Since it is signed and native on Windows systems, msiexec.exe can be used to bypass application control solutions that do not account for its potential abuse.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Msiexec.exe - Execute Local MSI file
Execute arbitrary MSI file. Commonly seen in application installation. The MSI opens notepad.exe when sucessfully executed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
msiexec.exe /q /i "#{msi_payload}"
```

Invoke-AtomicTest T1218.007 -TestNumbers 1

### Atomic Test #2 - Msiexec.exe - Execute Remote MSI file
Execute arbitrary MSI file retrieved remotely. Less commonly seen in application installation, commonly seen in malware execution. The MSI opens notepad.exe when sucessfully executed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
msiexec.exe /q /i "#{msi_payload}"
```

Invoke-AtomicTest T1218.007 -TestNumbers 2

### Atomic Test #3 - Msiexec.exe - Execute Arbitrary DLL
Execute arbitrary DLL file stored locally. Commonly seen in application installation.
Upon execution, a window titled "Boom!" will open that says "Locked and Loaded!". For 32 bit systems change the dll_payload argument to the Win32 folder.
By default, if the src folder is not in place, it will download the 64 bit version.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
msiexec.exe /y "#{dll_payload}"
```

Invoke-AtomicTest T1218.007 -TestNumbers 3

## Detection
Use process monitoring to monitor the execution and arguments of msiexec.exe. Compare recent invocations of msiexec.exe with prior history of known good arguments and executed MSI files or DLLs to determine anomalous and potentially adversarial activity. Command arguments used before and after the invocation of msiexec.exe may also be useful in determining the origin and purpose of the MSI files or DLLs being executed.