# T1114.001 - Email Collection: Local Email Collection
Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.

Outlook stores data locally in offline data files with an extension of .ost. Outlook 2010 and later supports .ost file sizes up to 50GB, while earlier versions of Outlook support up to 20GB.(Citation: Outlook File Sizes) IMAP accounts in Outlook 2013 (and earlier) and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP accounts in Outlook 2016 (and later) use .ost files. Both types of Outlook data files are typically stored in `C:\Users\<username>\Documents\Outlook Files` or `C:\Users\<username>\AppData\Local\Microsoft\Outlook`.(Citation: Microsoft Outlook Files)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Email Collection with PowerShell Get-Inbox
Search through local Outlook installation, extract mail, compress the contents, and saves everything to a directory for later exfiltration.
Successful execution will produce stdout message stating "Please be patient, this may take some time...". Upon completion, final output will be a mail.csv file.

Note: Outlook is required, but no email account necessary to produce artifacts.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
powershell -executionpolicy bypass -command #{file_path}\Get-Inbox.ps1 -file #{output_file}
```

Invoke-AtomicTest T1114.001 -TestNumbers 1

## Detection
Monitor processes and command-line arguments for actions that could be taken to gather local email files. Monitor for unusual processes accessing local email files. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).