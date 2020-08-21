# T1564.001 - Hide Artifacts: Hidden Files and Directories
Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (<code>dir /a</code> for Windows and <code>ls –a</code> for Linux and macOS).

On Linux and Mac, users can mark specific files as hidden simply by putting a “.” as the first character in the file or folder name  (Citation: Sofacy Komplex Trojan) (Citation: Antiquated Mac Malware). Files and folders that start with a period, ‘.’, are by default hidden from being viewed in the Finder application and standard command-line utilities like “ls”. Users must specifically change settings to have these files viewable.

Files on macOS can also be marked with the UF_HIDDEN flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.app (Citation: WireLurker). On Windows, users can mark specific files as hidden by using the attrib.exe binary. Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys.

Adversaries can use this to their advantage to hide files and folders anywhere on the system and evading a typical user or system analysis that does not incorporate investigation of hidden files.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Create a hidden file in a hidden directory
Creates a hidden file inside a hidden directory

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
mkdir /var/tmp/.hidden-directory
echo "T1564.001" > /var/tmp/.hidden-directory/.hidden-file
```

Invoke-AtomicTest T1564.001 -TestNumbers 1

### Atomic Test #2 - Mac Hidden file
Hide a file on MacOS

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
xattr -lr * / 2>&1 /dev/null | grep -C 2 "00 00 00 00 00 00 00 00 40 00 FF FF FF FF 00 00"
```

Invoke-AtomicTest T1564.001 -TestNumbers 2

### Atomic Test #3 - Create Windows System File with Attrib
Creates a file and marks it as a system file using the attrib.exe utility. Upon execution, open the file in file explorer then open Properties > Details
and observe that the Attributes are "SA" for System and Archive.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
attrib.exe +s #{file_to_modify}
```

Invoke-AtomicTest T1564.001 -TestNumbers 3

### Atomic Test #4 - Create Windows Hidden File with Attrib
Creates a file and marks it as hidden using the attrib.exe utility.Upon execution, open File Epxplorer and enable View > Hidden Items. Then, open Properties > Details on the file
and observe that the Attributes are "SH" for System and Hidden.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
attrib.exe +h #{file_to_modify}
```

Invoke-AtomicTest T1564.001 -TestNumbers 4

### Atomic Test #5 - Hidden files
Requires Apple Dev Tools

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
setfile -a V #{filename}
```

Invoke-AtomicTest T1564.001 -TestNumbers 5

### Atomic Test #6 - Hide a Directory
Hide a directory on MacOS

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
touch /var/tmp/T1564.001_mac.txt
chflags hidden /var/tmp/T1564.001_mac.txt
```

Invoke-AtomicTest T1564.001 -TestNumbers 6

### Atomic Test #7 - Show all hidden files
Show all hidden files on MacOS

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
defaults write com.apple.finder AppleShowAllFiles YES
```

Invoke-AtomicTest T1564.001 -TestNumbers 7

## Detection
Monitor the file system and shell commands for files being created with a leading "." and the Windows command-line use of attrib.exe to add the hidden attribute.