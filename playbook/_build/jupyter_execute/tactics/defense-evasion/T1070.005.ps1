# T1070.005 - Indicator Removal on Host: Network Share Connection Removal
Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) connections can be removed when no longer needed. [Net](https://attack.mitre.org/software/S0039) is an example utility that can be used to remove network share connections with the <code>net use \\system\share /delete</code> command. (Citation: Technet Net Use)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Add Network Share
Add a Network Share utilizing the command_prompt

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net use c: #{share_name}
net share test=#{share_name} /REMARK:"test share" /CACHE:No
```

Invoke-AtomicTest T1070.005 -TestNumbers 1

### Atomic Test #2 - Remove Network Share
Removes a Network Share utilizing the command_prompt

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net share #{share_name} /delete
```

Invoke-AtomicTest T1070.005 -TestNumbers 2

### Atomic Test #3 - Remove Network Share PowerShell
Removes a Network Share utilizing PowerShell

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Remove-SmbShare -Name #{share_name}
Remove-FileShare -Name #{share_name}
```

Invoke-AtomicTest T1070.005 -TestNumbers 3

## Detection
Network share connections may be common depending on how an network environment is used. Monitor command-line invocation of <code>net use</code> commands associated with establishing and removing remote shares over SMB, including following best practices for detection of [Windows Admin Shares](https://attack.mitre.org/techniques/T1077). SMB traffic between systems may also be captured and decoded to look for related network share session and file transfer activity. Windows authentication logs are also useful in determining when authenticated network shares are established and by which account, and can be used to correlate network share activity to other events to investigate potentially malicious activity.