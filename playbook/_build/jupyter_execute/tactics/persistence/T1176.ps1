# T1176 - Browser Extensions
Adversaries may abuse Internet browser extensions to establish persistence access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access. (Citation: Wikipedia Browser Extension) (Citation: Chrome Extensions Definition)

Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores so it may not be difficult for malicious extensions to defeat automated scanners. (Citation: Malicious Chrome Extension Numbers) Once the extension is installed, it can browse to websites in the background, (Citation: Chrome Extension Crypto Miner) (Citation: ICEBRG Chrome Extensions) steal all information that a user enters into a browser (including credentials) (Citation: Banker Google Chrome Extension Steals Creds) (Citation: Catch All Chrome Extension) and be used as an installer for a RAT for persistence.

There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions. (Citation: Stantinko Botnet) There have also been similar examples of extensions being used for command & control  (Citation: Chrome Extension C2 Malware).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Chrome (Developer Mode)
Turn on Chrome developer mode and Load Extension found in the src directory
**Supported Platforms:** linux, windows, macos
Run it with these steps!
1
.
 
N
a
v
i
g
a
t
e
 
t
o
 
[
c
h
r
o
m
e
:
/
/
e
x
t
e
n
s
i
o
n
s
]
(
c
h
r
o
m
e
:
/
/
e
x
t
e
n
s
i
o
n
s
)
 
a
n
d


t
i
c
k
 
'
D
e
v
e
l
o
p
e
r
 
M
o
d
e
'
.




2
.
 
C
l
i
c
k
 
'
L
o
a
d
 
u
n
p
a
c
k
e
d
 
e
x
t
e
n
s
i
o
n
.
.
.
'
 
a
n
d
 
n
a
v
i
g
a
t
e
 
t
o


[
B
r
o
w
s
e
r
_
E
x
t
e
n
s
i
o
n
]
(
.
.
/
t
1
1
7
6
/
s
r
c
/
)




3
.
 
C
l
i
c
k
 
'
S
e
l
e
c
t
'



### Atomic Test #2 - Chrome (Chrome Web Store)
Install the "Minimum Viable Malicious Extension" Chrome extension
**Supported Platforms:** linux, windows, macos
Run it with these steps!
1
.
 
N
a
v
i
g
a
t
e
 
t
o
 
h
t
t
p
s
:
/
/
c
h
r
o
m
e
.
g
o
o
g
l
e
.
c
o
m
/
w
e
b
s
t
o
r
e
/
d
e
t
a
i
l
/
m
i
n
i
m
u
m
-
v
i
a
b
l
e
-
m
a
l
i
c
i
o
u
s
/
o
d
l
p
f
d
o
l
e
h
m
h
c
i
i
e
b
a
h
b
p
n
a
o
p
n
e
i
c
e
n
d


i
n
 
C
h
r
o
m
e




2
.
 
C
l
i
c
k
 
'
A
d
d
 
t
o
 
C
h
r
o
m
e
'



### Atomic Test #3 - Firefox
Create a file called test.wma, with the duration of 30 seconds

**Supported Platforms:** linux, windows, macos
Run it with these steps!
1
.
 
N
a
v
i
g
a
t
e
 
t
o
 
[
a
b
o
u
t
:
d
e
b
u
g
g
i
n
g
]
(
a
b
o
u
t
:
d
e
b
u
g
g
i
n
g
)
 
a
n
d


c
l
i
c
k
 
"
L
o
a
d
 
T
e
m
p
o
r
a
r
y
 
A
d
d
-
o
n
"




2
.
 
N
a
v
i
g
a
t
e
 
t
o
 
[
m
a
n
i
f
e
s
t
.
j
s
o
n
]
(
.
/
s
r
c
/
m
a
n
i
f
e
s
t
.
j
s
o
n
)




3
.
 
T
h
e
n
 
c
l
i
c
k
 
'
O
p
e
n
'



### Atomic Test #4 - Edge Chromium Addon - VPN
Adversaries may use VPN extensions in an attempt to hide traffic sent from a compromised host. This will install one (of many) available VPNS in the Edge add-on store.

**Supported Platforms:** windows, macos
Run it with these steps!
1
.
 
N
a
v
i
g
a
t
e
 
t
o
 
h
t
t
p
s
:
/
/
m
i
c
r
o
s
o
f
t
e
d
g
e
.
m
i
c
r
o
s
o
f
t
.
c
o
m
/
a
d
d
o
n
s
/
d
e
t
a
i
l
/
f
j
n
e
h
c
b
e
c
a
g
g
o
b
j
h
o
l
e
k
j
i
j
a
a
e
k
b
n
l
g
j


i
n
 
E
d
g
e
 
C
h
r
o
m
i
u
m




2
.
 
C
l
i
c
k
 
'
G
e
t
'



## Detection
Inventory and monitor browser extension installations that deviate from normal, expected, and benign extensions. Process and network monitoring can be used to detect browsers communicating with a C2 server. However, this may prove to be a difficult way of initially detecting a malicious extension depending on the nature and volume of the traffic it generates.

Monitor for any new items written to the Registry or PE files written to disk. That may correlate with browser extension installation.