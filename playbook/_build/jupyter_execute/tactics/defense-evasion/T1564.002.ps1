# T1564.002 - Hide Artifacts: Hidden Users
Adversaries may use hidden users to mask the presence of user accounts they create. Every user account in macOS has a userID associated with it. When creating a user, you can specify the userID for that account.

There is a property value in <code>/Library/Preferences/com.apple.loginwindow</code> called <code>Hide500Users</code> that prevents users with userIDs 500 and lower from appearing at the login screen. When using the [Create Account](https://attack.mitre.org/techniques/T1136) technique with a userID under 500 (ex: <code>sudo dscl . -create /Users/username UniqueID 401</code>) and enabling this property (setting it to Yes), an adversary can conceal user accounts. (Citation: Cybereason OSX Pirrit).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Hidden Users
Add a hidden user on MacOS

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
sudo dscl . -create /Users/#{user_name} UniqueID 333
```

Invoke-AtomicTest T1564.002 -TestNumbers 1

## Detection
This technique prevents the new user from showing up at the log in screen, but all of the other signs of a new user still exist. The user still gets a home directory and will appear in the authentication logs.