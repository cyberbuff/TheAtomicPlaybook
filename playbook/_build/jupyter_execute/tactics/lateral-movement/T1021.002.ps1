# T1021.002 - Remote Services: SMB/Windows Admin Shares
Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include `C$`, `ADMIN$`, and `IPC$`. Adversaries may use this technique in conjunction with administrator-level [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system over SMB,(Citation: Wikipedia Server Message Block) to interact with systems using remote procedure calls (RPCs),(Citation: TechNet RPC) transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Service Execution](https://attack.mitre.org/techniques/T1569/002), and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM hashes to access administrator shares on systems with [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) and certain configuration and patch levels.(Citation: Microsoft Admin Shares)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Map admin share
Connecting To Remote Shares

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
cmd.exe /c "net use \\#{computer_name}\#{share_name} #{password} /u:#{user_name}"
```

Invoke-AtomicTest T1021.002 -TestNumbers 1

### Atomic Test #2 - Map Admin Share PowerShell
Map Admin share utilizing PowerShell

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
New-PSDrive -name #{map_name} -psprovider filesystem -root \\#{computer_name}\#{share_name}
```

Invoke-AtomicTest T1021.002 -TestNumbers 2

### Atomic Test #3 - Copy and Execute File with PsExec
Copies a file to a remote host and executes it using PsExec. Requires the download of PsExec from [https://docs.microsoft.com/en-us/sysinternals/downloads/psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec).

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
psexec.exe #{remote_host} -accepteula -c #{command_path}
```

Invoke-AtomicTest T1021.002 -TestNumbers 3

### Atomic Test #4 - Execute command writing output to local Admin Share
Executes a command, writing the output to a local Admin Share.
This technique is used by post-exploitation frameworks.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
cmd.exe /Q /c #{command_to_execute} 1> \\127.0.0.1\ADMIN$\#{output_file} 2>&1
```

Invoke-AtomicTest T1021.002 -TestNumbers 4

## Detection
Ensure that proper logging of accounts used to log into systems is turned on and centrally collected. Windows logging is able to collect success/failure for accounts that may be used to move laterally and can be collected using tools such as Windows Event Forwarding. (Citation: Lateral Movement Payne)(Citation: Windows Event Forwarding Payne) Monitor remote login events and associated SMB activity for file transfers and remote process execution. Monitor the actions of remote users who connect to administrative shares. Monitor for use of tools and commands to connect to remote shares, such as [Net](https://attack.mitre.org/software/S0039), on the command-line interface and Discovery techniques that could be used to find remotely accessible systems.(Citation: Medium Detecting WMI Persistence)