# T1531 - Account Access Removal
Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.

Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Change User Password - Windows
Changes the user password to hinder access attempts. Seen in use by LockerGoga. Upon execution, log into the user account "AtomicAdministrator" with
the password "HuHuHUHoHo283283".

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net user #{user_account} #{new_user_password} /add
net.exe user #{user_account} #{new_password}
```

Invoke-AtomicTest T1531 -TestNumbers 1

### Atomic Test #2 - Delete User - Windows
Deletes a user account to prevent access. Upon execution, run the command "net user" to verify that the new "AtomicUser" account was deleted.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net user #{user_account} #{new_user_password} /add
net.exe user #{user_account} /delete
```

Invoke-AtomicTest T1531 -TestNumbers 2

### Atomic Test #3 - Remove Account From Domain Admin Group
This test will remove an account from the domain admins group

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$PWord = ConvertTo-SecureString -String #{super_pass} -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList #{super_user}, $PWord
if((Get-ADUser #{remove_user} -Properties memberof).memberof -like "CN=Domain Admins*"){
  Remove-ADGroupMember -Identity "Domain Admins" -Members #{remove_user} -Credential $Credential -Confirm:$False
} else{
    write-host "Error - Make sure #{remove_user} is in the domain admins group" -foregroundcolor Red
}
```

Invoke-AtomicTest T1531 -TestNumbers 3

## Detection
Use process monitoring to monitor the execution and command line parameters of binaries involved in deleting accounts or changing passwords, such as use of [Net](https://attack.mitre.org/software/S0039). Windows event logs may also designate activity associated with an adversary's attempt to remove access to an account:

* Event ID 4723 - An attempt was made to change an account's password
* Event ID 4724 - An attempt was made to reset an account's password
* Event ID 4726 - A user account was deleted
* Event ID 4740 - A user account was locked out

Alerting on [Net](https://attack.mitre.org/software/S0039) and these Event IDs may generate a high degree of false positives, so compare against baseline knowledge for how systems are typically used and correlate modification events with other indications of malicious activity where possible.