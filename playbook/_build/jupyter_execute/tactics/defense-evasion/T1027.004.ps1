# T1027.004 - Obfuscated Files or Information: Compile After Delivery
Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)

Source code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Phishing](https://attack.mitre.org/techniques/T1566). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Compile After Delivery using csc.exe
Compile C# code using csc.exe binary used by .NET
Upon execution an exe named T1027.004.exe will be placed in the temp folder

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:#{output_file} #{input_file}
```

Invoke-AtomicTest T1027.004 -TestNumbers 1

### Atomic Test #2 - Dynamic C# Compile
When C# is compiled dynamically, a .cmdline file will be created as a part of the process. 
Certain processes are not typically observed compiling C# code, but can do so without touching disk. This can be used to unpack a payload for execution.
The exe file that will be executed is named as T1027.004_DynamicCompile.exe is containted in the 'bin' folder of this atomic, and the source code to the file is in the 'src' folder.
Upon execution, the exe will print 'T1027.004 Dynamic Compile'.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Invoke-Expression #{input_file}
```

Invoke-AtomicTest T1027.004 -TestNumbers 2

## Detection
Monitor the execution file paths and command-line arguments for common compilers, such as csc.exe and GCC/MinGW, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior. The compilation of payloads may also generate file creation and/or file write events. Look for non-native binary formats and cross-platform compiler and execution frameworks like Mono and determine if they have a legitimate purpose on the system.(Citation: TrendMicro WindowsAppMac) Typically these should only be used in specific and limited cases, like for software development.