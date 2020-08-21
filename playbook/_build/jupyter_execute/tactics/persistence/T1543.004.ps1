# T1543.004 - Create or Modify System Process: Launch Daemon
Adversaries may create or modify launch daemons to repeatedly execute malicious payloads as part of persistence. Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence). 

Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directories  (Citation: OSX Malware Detection). The daemon name may be disguised by using a name from a related operating system or benign software (Citation: WireLurker). Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root. 

The plist file permissions must be root:wheel, but the script or program that it points to has no such requirement. So, it is possible for poor configurations to allow an adversary to modify a current Launch Daemon’s executable and gain persistence or Privilege Escalation. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Launch Daemon
Utilize LaunchDaemon to launch `Hello World`

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
sudo cp #{path_malicious_plist} /Library/LaunchDaemons/#{plist_filename}
sudo launchctl load -w /Library/LaunchDaemons/#{plist_filename}
```

Invoke-AtomicTest T1543.004 -TestNumbers 1

## Detection
Monitor for launch daemon creation or modification through plist files and utilities such as Objective-See's KnockKnock application. 