# T1552.001 - Unsecured Credentials: Credentials In Files
Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. (Citation: SRD GPP)

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files. (Citation: Specter Ops - Cloud Credential Storage)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Extract Browser and System credentials with LaZagne
[LaZagne Source](https://github.com/AlessandroZ/LaZagne)

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
python2 laZagne.py all
```

Invoke-AtomicTest T1552.001 -TestNumbers 1

### Atomic Test #2 - Extract passwords with grep
Extracting credentials from files

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
grep -ri password #{file_path}
```

Invoke-AtomicTest T1552.001 -TestNumbers 2

### Atomic Test #3 - Extracting passwords with findstr
Extracting Credentials from Files. Upon execution, the contents of files that contain the word "password" will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
findstr /si pass *.xml *.doc *.txt *.xls
ls -R | select-string -Pattern password
```

Invoke-AtomicTest T1552.001 -TestNumbers 3

### Atomic Test #4 - Access unattend.xml
Attempts to access unattend.xml, where credentials are commonly stored, within the Panther directory where installation logs are stored.
If these files exist, their contents will be displayed. They are used to store credentials/answers during the unattended windows install process.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
type C:\Windows\Panther\unattend.xml
type C:\Windows\Panther\Unattend\unattend.xml
```

Invoke-AtomicTest T1552.001 -TestNumbers 4

## Detection
While detecting adversaries accessing these files may be difficult without knowing they exist in the first place, it may be possible to detect adversary use of credentials they have obtained. Monitor the command-line arguments of executing processes for suspicious words or regular expressions that may indicate searching for a password (for example: password, pwd, login, secure, or credentials). See [Valid Accounts](https://attack.mitre.org/techniques/T1078) for more information.