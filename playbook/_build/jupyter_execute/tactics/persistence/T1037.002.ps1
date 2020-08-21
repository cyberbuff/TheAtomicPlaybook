# T1037.002 - Boot or Logon Initialization Scripts: Logon Script (Mac)
Adversaries may use macOS logon scripts automatically executed at logon initialization to establish persistence. macOS allows logon scripts (known as login hooks) to be executed whenever a specific user logs into a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike [Startup Items](https://attack.mitre.org/techniques/T1037/005), a login hook executes as the elevated root user.(Citation: creating login hook)

Adversaries may use these login hooks to maintain persistence on a single system.(Citation: S1 macOs Persistence) Access to login hook scripts may allow an adversary to insert additional malicious code. There can only be one login hook at a time though and depending on the access configuration of the hooks, either local credentials or an administrator account may be necessary. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Logon Scripts - Mac
Mac logon script

**Supported Platforms:** macos
Run it with these steps!
1
.
 
C
r
e
a
t
e
 
t
h
e
 
r
e
q
u
i
r
e
d
 
p
l
i
s
t
 
f
i
l
e




 
 
 
 
s
u
d
o
 
t
o
u
c
h
 
/
p
r
i
v
a
t
e
/
v
a
r
/
r
o
o
t
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




2
.
 
P
o
p
u
l
a
t
e
 
t
h
e
 
p
l
i
s
t
 
w
i
t
h
 
t
h
e
 
l
o
c
a
t
i
o
n
 
o
f
 
y
o
u
r
 
s
h
e
l
l
 
s
c
r
i
p
t




 
 
 
 
s
u
d
o
 
d
e
f
a
u
l
t
s
 
w
r
i
t
e
 
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
 
L
o
g
i
n
H
o
o
k
 
/
L
i
b
r
a
r
y
/
S
c
r
i
p
t
s
/
A
t
o
m
i
c
R
e
d
T
e
a
m
.
s
h




3
.
 
C
r
e
a
t
e
 
t
h
e
 
r
e
q
u
i
r
e
d
 
p
l
i
s
t
 
f
i
l
e
 
i
n
 
t
h
e
 
t
a
r
g
e
t
 
u
s
e
r
'
s
 
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
 
d
i
r
e
c
t
o
r
y




	
 
 
t
o
u
c
h
 
/
U
s
e
r
s
/
$
U
S
E
R
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




4
.
 
P
o
p
u
l
a
t
e
 
t
h
e
 
p
l
i
s
t
 
w
i
t
h
 
t
h
e
 
l
o
c
a
t
i
o
n
 
o
f
 
y
o
u
r
 
s
h
e
l
l
 
s
c
r
i
p
t




	
 
 
d
e
f
a
u
l
t
s
 
w
r
i
t
e
 
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
 
L
o
g
i
n
H
o
o
k
 
/
L
i
b
r
a
r
y
/
S
c
r
i
p
t
s
/
A
t
o
m
i
c
R
e
d
T
e
a
m
.
s
h



## Detection
Monitor logon scripts for unusual access by abnormal users or at abnormal times. Look for files added or modified by unusual accounts outside of normal administration duties. Monitor running process for actions that could be indicative of abnormal programs or executables running upon logon.