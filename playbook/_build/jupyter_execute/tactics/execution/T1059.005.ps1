# T1059.005 - Command and Scripting Interpreter: Visual Basic
Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and the [Native API](https://attack.mitre.org/techniques/T1106) through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.(Citation: VB .NET Mar 2020)(Citation: VB Microsoft)

Derivative languages based on VB have also been created, such as Visual Basic for Applications (VBA) and VBScript. VBA is an event-driven programming language built into Office applications.(Citation: Microsoft VBA)  VBA enables documents to contain macros used to automate the execution of tasks and other functionality on the host. VBScript is a default scripting language on Windows hosts and can also be used in place of [JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007) on HTML Application (HTA) webpages served to Internet Explorer (though most modern browsers do not come with VBScript support).(Citation: Microsoft VBScript)

Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) payloads.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Visual Basic script execution to gather local computer information
Visual Basic execution test, execute vbscript via PowerShell.

When successful, system information will be written to $env:TEMP\T1059.005.out.txt.
**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
cscript #{vbscript} > $env:TEMP\out.txt```

Invoke-AtomicTest T1059.005 -TestNumbers 1

## Detection
Monitor for events associated with VB execution, such as Office applications spawning processes, usage of the Windows Script Host (typically cscript.exe or wscript.exe), file activity involving VB payloads or scripts, or loading of modules associated with VB languages (ex: vbscript.dll). VB execution is likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for execution and subsequent behavior. Actions may be related to network and system information [Discovery](https://attack.mitre.org/tactics/TA0007), [Collection](https://attack.mitre.org/tactics/TA0009), or other programable post-compromise behaviors and could be used as indicators of detection leading back to the source.

Understanding standard usage patterns is important to avoid a high number of false positives. If VB execution is restricted for normal users, then any attempts to enable related components running on a system would be considered suspicious. If VB execution is not commonly used on a system, but enabled, execution running out of cycle from patching or other administrator functions is suspicious. Payloads and scripts should be captured from the file system when possible to determine their actions and intent.