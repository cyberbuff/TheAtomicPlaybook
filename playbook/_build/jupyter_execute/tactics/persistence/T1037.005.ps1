# T1037.005 - Boot or Logon Initialization Scripts: Startup Items
Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. (Citation: Startup Items)

This is technically a deprecated technology (superseded by [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)), and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory. 

An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism (Citation: Methods of Mac Malware Persistence). Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Add file to Local Library StartupItems
Modify or create an file in /Library/StartupItems

[Reference](https://www.alienvault.com/blogs/labs-research/diversity-in-recent-mac-malware)

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo touch /Library/StartupItems/EvilStartup.plist
```

Invoke-AtomicTest T1037.005 -TestNumbers 1

## Detection
The <code>/Library/StartupItems</code> folder can be monitored for changes. Similarly, the programs that are actually executed from this mechanism should be checked against a whitelist.

Monitor processes that are executed during the bootup process to check for unusual or unknown applications and behavior.