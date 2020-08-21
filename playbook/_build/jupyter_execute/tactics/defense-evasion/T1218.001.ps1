# T1218.001 - Signed Binary Proxy Execution: Compiled HTML File
Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable Program)

A custom CHM file containing embedded payloads could be delivered to a victim then triggered by [User Execution](https://attack.mitre.org/techniques/T1204). CHM execution may also bypass application application control on older and/or unpatched systems that do not account for execution of binaries through hh.exe. (Citation: MsitPros CHM Aug 2017) (Citation: Microsoft CVE-2017-8625 Aug 2017)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Compiled HTML Help Local Payload
Uses hh.exe to execute a local compiled HTML Help payload.
Upon execution calc.exe will open

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
hh.exe #{local_chm_file}
```

Invoke-AtomicTest T1218.001 -TestNumbers 1

### Atomic Test #2 - Compiled HTML Help Remote Payload
Uses hh.exe to execute a remote compiled HTML Help payload.
Upon execution displays an error saying the file cannot be open

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
hh.exe #{remote_chm_file}
```

Invoke-AtomicTest T1218.001 -TestNumbers 2

## Detection
Monitor and analyze the execution and arguments of hh.exe. (Citation: MsitPros CHM Aug 2017) Compare recent invocations of hh.exe with prior history of known good arguments to determine anomalous and potentially adversarial activity (ex: obfuscated and/or malicious commands). Non-standard process execution trees may also indicate suspicious or malicious behavior, such as if hh.exe is the parent process for suspicious processes and activity relating to other adversarial techniques.

Monitor presence and use of CHM files, especially if they are not typically used within an environment.