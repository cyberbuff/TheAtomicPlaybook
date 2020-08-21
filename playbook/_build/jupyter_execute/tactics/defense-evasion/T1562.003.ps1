# T1562.003 - Impair Defenses: HISTCONTROL
Adversaries may configure <code>HISTCONTROL</code> to not log all command history. The <code>HISTCONTROL</code> environment variable keeps track of what should be saved by the <code>history</code> command and eventually into the <code>~/.bash_history</code> file when a user logs out. <code>HISTCONTROL</code> does not exist by default on macOS, but can be set by the user and will be respected.

This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". <code>HISTCONTROL</code> can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history.

 Adversaries can abuse this to operate without leaving traces by simply prepending a space to all of their terminal commands.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Disable history collection
Disables history collection in shells

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
export HISTCONTROL=ignoreboth
#{evil_command}
```

Invoke-AtomicTest T1562.003 -TestNumbers 1

### Atomic Test #2 - Mac HISTCONTROL
The HISTCONTROL variable is set to ignore (not write to the history file) command that are a duplicate of something already in the history 
and commands that start with a space. This atomic sets this variable in the current session and also writes it to the current user's ~/.bash_profile 
so that it will apply to all future settings as well.
https://www.linuxjournal.com/content/using-bash-history-more-efficiently-histcontrol

**Supported Platforms:** macos, linux
Run it with these steps!
1
.
 
e
x
p
o
r
t
 
H
I
S
T
C
O
N
T
R
O
L
=
i
g
n
o
r
e
b
o
t
h


2
.
 
e
c
h
o
 
e
x
p
o
r
t
 
"
H
I
S
T
C
O
N
T
R
O
L
=
i
g
n
o
r
e
b
o
t
h
"
 
>
>
 
~
/
.
b
a
s
h
_
p
r
o
f
i
l
e


3
.
 
l
s


4
.
 
w
h
o
a
m
i
 
>
 
r
e
c
o
n
.
t
x
t



## Detection
Correlating a user session with a distinct lack of new commands in their <code>.bash_history</code> can be a clue to suspicious behavior. Additionally, users checking or changing their <code>HISTCONTROL</code> environment variable is also suspicious.