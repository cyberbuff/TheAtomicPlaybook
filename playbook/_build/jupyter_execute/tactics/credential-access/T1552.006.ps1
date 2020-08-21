# T1552.006 - Unsecured Credentials: Group Policy Preferences
Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.(Citation: Microsoft GPP 2016)

These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public).(Citation: Microsoft GPP Key)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: <code>post/windows/gather/credentials/gpp</code>
* Get-GPPPassword(Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: <code>dir /s * .xml</code>


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - GPP Passwords (findstr)
Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller. This value can be decrypted with gpp-decrypt on Kali Linux.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
findstr /S cpassword %logonserver%\sysvol\*.xml
```

Invoke-AtomicTest T1552.006 -TestNumbers 1

### Atomic Test #2 - GPP Passwords (Get-GPPPassword)
Look for the encrypted cpassword value within Group Policy Preference files on the Domain Controller.
This test is intended to be run from a domain joined workstation, not on the Domain Controller itself.
The Get-GPPPasswords.ps1 executed during this test can be obtained using the get-prereq_commands.

Successful test execution will either display the credentials found in the GPP files or indicate "No preference files found".

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
. #{gpp_script_path}
Get-GPPPassword -Verbose
```

Invoke-AtomicTest T1552.006 -TestNumbers 2

## Detection
Monitor for attempts to access SYSVOL that involve searching for XML files. 

Deploy a new XML file with permissions set to Everyone:Deny and monitor for Access Denied errors.(Citation: ADSecurity Finding Passwords in SYSVOL)