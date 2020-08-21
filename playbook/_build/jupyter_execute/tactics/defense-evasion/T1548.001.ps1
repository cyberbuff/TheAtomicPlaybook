# T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid
An adversary may perform shell escapes or exploit vulnerabilities in an application with the setsuid or setgid bits to get code running in a different user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application, the application will run with the privileges of the owning user or group respectively. (Citation: setuid man page). Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them doesn’t need the elevated privileges.

Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications. These bits are indicated with an "s" instead of an "x" when viewing a file's attributes via <code>ls -l</code>. The <code>chmod</code> program can set these bits with via bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, <code>chmod u+s [file]</code>.

Adversaries can use this mechanism on their own malware to make sure they're able to execute in elevated contexts in the future.(Citation: OSX Keydnap malware).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Make and modify binary from C source
Make, change owner, and change file attributes on a C source code file

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
cp #{payload} /tmp/hello.c
sudo chown root /tmp/hello.c
sudo make /tmp/hello
sudo chown root /tmp/hello
sudo chmod u+s /tmp/hello
/tmp/hello
```

Invoke-AtomicTest T1548.001 -TestNumbers 1

### Atomic Test #2 - Set a SetUID flag on file
This test sets the SetUID flag on a file in Linux and macOS.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
sudo touch #{file_to_setuid}
sudo chown root #{file_to_setuid}
sudo chmod u+s #{file_to_setuid}
```

Invoke-AtomicTest T1548.001 -TestNumbers 2

### Atomic Test #3 - Set a SetGID flag on file
This test sets the SetGID flag on a file in Linux and macOS.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
sudo touch #{file_to_setuid}
sudo chown root #{file_to_setuid}
sudo chmod g+s #{file_to_setuid}
```

Invoke-AtomicTest T1548.001 -TestNumbers 3

## Detection
Monitor the file system for files that have the setuid or setgid bits set. Monitor for execution of utilities, like chmod, and their command-line arguments to look for setuid or setguid bits being set.