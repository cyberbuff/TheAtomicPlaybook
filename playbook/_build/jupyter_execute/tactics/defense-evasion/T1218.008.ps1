# T1218.008 - Signed Binary Proxy Execution: Odbcconf
Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names.(Citation: Microsoft odbcconf.exe) Odbcconf.exe is digitally signed by Microsoft.

Adversaries may abuse odbcconf.exe to bypass application control solutions that do not account for its potential abuse. Similar to [Regsvr32](https://attack.mitre.org/techniques/T1218/010), odbcconf.exe has a <code>REGSVR</code> flag that can be misused to execute DLLs (ex: <code>odbcconf.exe /S /A &lbrace;REGSVR "C:\Users\Public\file.dll"&rbrace;</code>). (Citation: LOLBAS Odbcconf)(Citation: TrendMicro Squiblydoo Aug 2017)(Citation: TrendMicro Cobalt Group Nov 2017) 


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Odbcconf.exe - Execute Arbitrary DLL
Execute arbitrary DLL file stored locally.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
odbcconf.exe /S /A {REGSVR "#{dll_payload}"}
```

Invoke-AtomicTest T1218.008 -TestNumbers 1

## Detection
Use process monitoring to monitor the execution and arguments of odbcconf.exe. Compare recent invocations of odbcconf.exe with prior history of known good arguments and loaded DLLs to determine anomalous and potentially adversarial activity. Command arguments used before and after the invocation of odbcconf.exe may also be useful in determining the origin and purpose of the DLL being loaded.