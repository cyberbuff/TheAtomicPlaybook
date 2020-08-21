# T1207 - Rogue Domain Controller
Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. (Citation: DCShadow Blog) Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.

Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz Guide)

This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors). (Citation: DCShadow Blog) The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis. Adversaries may also utilize this technique to perform [SID-History Injection](https://attack.mitre.org/techniques/T1178) and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence. (Citation: DCShadow Blog)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - DCShadow - Mimikatz
Utilize Mimikatz DCShadow method to simulate behavior of a Domain Controller

[DCShadow](https://www.dcshadow.com/)
[Additional Reference](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)

**Supported Platforms:** windows
Run it with these steps!
1
.
 
S
t
a
r
t
 
M
i
m
i
k
a
t
z
 
a
n
d
 
u
s
e
 
!
p
r
o
c
e
s
s
t
o
k
e
n
 
(
a
n
d
 
n
o
t
 
t
o
k
e
n
:
:
e
l
e
v
a
t
e
 
-
 
a
s
 
i
t
 
e
l
e
v
a
t
e
s
 
a
 
t
h
r
e
a
d
)
 
t
o
 
e
s
c
a
l
a
t
e
 
t
o
 
S
Y
S
T
E
M
.


2
.
 
S
t
a
r
t
 
a
n
o
t
h
e
r
 
m
i
m
i
k
a
t
z
 
w
i
t
h
 
D
A
 
p
r
i
v
i
l
e
g
e
s
.
 
T
h
i
s
 
i
s
 
t
h
e
 
i
n
s
t
a
n
c
e
 
w
h
i
c
h
 
r
e
g
i
s
t
e
r
s
 
a
 
D
C
 
a
n
d
 
i
s
 
u
s
e
d
 
t
o
 
"
p
u
s
h
"
 
t
h
e
 
a
t
t
r
i
b
u
t
e
s
.


3
.
 
l
s
a
d
u
m
p
:
:
d
c
s
h
a
d
o
w
 
/
o
b
j
e
c
t
:
o
p
s
-
u
s
e
r
1
9
$
 
/
a
t
t
r
i
b
u
t
e
:
u
s
e
r
A
c
c
o
u
n
t
C
o
n
t
r
o
l
 
/
v
a
l
u
e
:
5
3
2
4
8
0


4
.
 
l
s
a
d
u
m
p
:
:
d
c
s
h
a
d
o
w
 
/
p
u
s
h



## Detection
Monitor and analyze network traffic associated with data replication (such as calls to DrsAddEntry, DrsReplicaAdd, and especially GetNCChanges) between DCs as well as to/from non DC hosts. (Citation: GitHub DCSYNCMonitor) (Citation: DCShadow Blog) DC replication will naturally take place every 15 minutes but can be triggered by an attacker or by legitimate urgent changes (ex: passwords). Also consider monitoring and alerting on the replication of AD objects (Audit Detailed Directory Service Replication Events 4928 and 4929). (Citation: DCShadow Blog)

Leverage AD directory synchronization (DirSync) to monitor changes to directory state using AD replication cookies. (Citation: Microsoft DirSync) (Citation: ADDSecurity DCShadow Feb 2018)

Baseline and periodically analyze the Configuration partition of the AD schema and alert on creation of nTDSDSA objects. (Citation: DCShadow Blog)

Investigate usage of Kerberos Service Principal Names (SPNs), especially those associated with services (beginning with “GC/”) by computers not present in the DC organizational unit (OU). The SPN associated with the Directory Replication Service (DRS) Remote Protocol interface (GUID E3514235–4B06–11D1-AB04–00C04FC2DCD2) can be set without logging. (Citation: ADDSecurity DCShadow Feb 2018) A rogue DC must authenticate as a service using these two SPNs for the replication process to successfully complete.