# T1564.003 - Hide Artifacts: Hidden Window
Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks. 

On Windows, there are a variety of features in scripting languages in Windows, such as [PowerShell](https://attack.mitre.org/techniques/T1059/001), Jscript, and [Visual Basic](https://attack.mitre.org/techniques/T1059/005) to make windows hidden. One example of this is <code>powershell.exe -WindowStyle Hidden</code>. (Citation: PowerShell About 2019)

Similarly, on macOS the configurations for how applications run are listed in property list (plist) files. One of the tags in these files can be <code>apple.awt.UIElement</code>, which allows for Java applications to prevent the application's icon from appearing in the Dock. A common use for this is when applications run in the system tray, but don't also want to show up in the Dock.

Adversaries may abuse these functionalities to hide otherwise visible windows from users so as not to alert the user to adversary activity on the system.(Citation: Antiquated Mac Malware)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Hidden Window
Launch PowerShell with the "-WindowStyle Hidden" argument to conceal PowerShell windows by setting the WindowStyle parameter to hidden.
Upon execution a hidden PowerShell window will launch calc.exe

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Start-Process #{powershell_command}
```

Invoke-AtomicTest T1564.003 -TestNumbers 1

## Detection
Monitor processes and command-line arguments for actions indicative of hidden windows. In Windows, enable and configure event logging and PowerShell logging to check for the hidden window style. In MacOS, plist files are ASCII text files with a specific format, so they're relatively easy to parse. File monitoring can check for the <code>apple.awt.UIElement</code> or any other suspicious plist tag in plist files and flag them.