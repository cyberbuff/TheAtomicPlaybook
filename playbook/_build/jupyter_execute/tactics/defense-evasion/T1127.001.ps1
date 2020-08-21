# T1127.001 - Trusted Developer Utilities Proxy Execution: MSBuild
Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.(Citation: MSDN MSBuild)

Adversaries can abuse MSBuild to proxy execution of malicious code. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into an XML project file.(Citation: MSDN MSBuild) MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application control defenses that are configured to allow MSBuild.exe execution.(Citation: LOLBAS Msbuild)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - MSBuild Bypass Using Inline Tasks
Executes the code in a project file using. C# Example

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe #{filename}
```

Invoke-AtomicTest T1127.001 -TestNumbers 1

## Detection
Use process monitoring to monitor the execution and arguments of MSBuild.exe. Compare recent invocations of those binaries with prior history of known good arguments and executed binaries to determine anomalous and potentially adversarial activity. Command arguments used before and after invocation of the utilities may also be useful in determining the origin and purpose of the binary being executed.