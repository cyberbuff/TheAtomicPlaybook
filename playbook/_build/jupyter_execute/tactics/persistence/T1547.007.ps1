# T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications
Adversaries may modify plist files to automatically run an application when a user logs in. Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user logs into their machine after reboot. While this is usually done via a Graphical User Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain this information as well located at <code>~/Library/Preferences/com.apple.loginwindow.plist</code> and <code>~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist</code>. 

An adversary can modify one of these files directly to include a link to their malicious executable to provide a persistence mechanism each time the user reboots their machine (Citation: Methods of Mac Malware Persistence).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Re-Opened Applications
Plist Method

[Reference](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html)

**Supported Platforms:** macos
Run it with these steps!
1
.
 
c
r
e
a
t
e
 
a
 
c
u
s
t
o
m
 
p
l
i
s
t
:




 
 
 
 
~
/
L
i
b
r
a
r
y
/
P
r
e
f
e
r
e
n
c
e
s
/
c
o
m
.
a
p
p
l
e
.
l
o
g
i
n
w
i
n
d
o
w
.
p
l
i
s
t




o
r




 
 
 
 
~
/
L
i
b
r
a
r
y
/
P
r
e
f
e
r
e
n
c
e
s
/
B
y
H
o
s
t
/
c
o
m
.
a
p
p
l
e
.
l
o
g
i
n
w
i
n
d
o
w
.
*
.
p
l
i
s
t



### Atomic Test #2 - Re-Opened Applications
Mac Defaults

[Reference](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CustomLogin.html)

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo defaults write com.apple.loginwindow LoginHook #{script}
```

Invoke-AtomicTest T1547.007 -TestNumbers 2

## Detection
Monitoring the specific plist files associated with reopening applications can indicate when an application has registered itself to be reopened.