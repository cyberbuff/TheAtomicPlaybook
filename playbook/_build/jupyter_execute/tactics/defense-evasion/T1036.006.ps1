# T1036.006 - Masquerading: Space after Filename
Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system.

For example, if there is a Mach-O executable file called <code>evil.bin</code>, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to <code>evil.txt</code>, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to <code>evil.txt </code> (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed (Citation: Mac Backdoors are back).

Adversaries can use this feature to trick users into double clicking benign-looking files of any format and ultimately executing something malicious.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Space After Filename
Space After Filename

**Supported Platforms:** macos
Run it with these steps!
1
.
 
1
.
 
e
c
h
o
 
'
#
!
/
b
i
n
/
b
a
s
h
\
n
e
c
h
o
 
"
p
r
i
n
t
 
\
"
h
e
l
l
o
,
 
w
o
r
l
d
!
\
"
"
 
|
 
/
u
s
r
/
b
i
n
/
p
y
t
h
o
n
\
n
e
x
i
t
'
 
>
 
e
x
e
c
u
t
e
.
t
x
t
 
&
&
 
c
h
m
o
d
 
+
x
 
e
x
e
c
u
t
e
.
t
x
t




2
.
 
m
v
 
e
x
e
c
u
t
e
.
t
x
t
 
"
e
x
e
c
u
t
e
.
t
x
t
 
"




3
.
 
.
/
e
x
e
c
u
t
e
.
t
x
t
\
 



## Detection
It's not common for spaces to be at the end of filenames, so this is something that can easily be checked with file monitoring. From the user's perspective though, this is very hard to notice from within the Finder.app or on the command-line in Terminal.app. Processes executed from binaries containing non-standard extensions in the filename are suspicious.