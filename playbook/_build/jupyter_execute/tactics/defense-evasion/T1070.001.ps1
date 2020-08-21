# T1070.001 - Indicator Removal on Host: Clear Windows Event Logs
Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.

The event logs can be cleared with the following utility commands:

* <code>wevtutil cl system</code>
* <code>wevtutil cl application</code>
* <code>wevtutil cl security</code>

These logs may also be cleared through other mechanisms, such as the event viewer GUI or [PowerShell](https://attack.mitre.org/techniques/T1059/001).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Clear Logs
Upon execution this test will clear Windows Event Logs. Open the System.evtx logs at C:\Windows\System32\winevt\Logs and verify that it is now empty.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wevtutil cl #{log_name}
```

Invoke-AtomicTest T1070.001 -TestNumbers 1

### Atomic Test #2 - Delete System Logs Using Clear-EventLog
Clear event logs using built-in PowerShell commands.
Upon successful execution, you should see the list of deleted event logs
Upon execution, open the Security.evtx logs at C:\Windows\System32\winevt\Logs and verify that it is now empty or has very few logs in it.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$logs = Get-EventLog -List | ForEach-Object {$_.Log}
$logs | ForEach-Object {Clear-EventLog -LogName $_ }
Get-EventLog -list
```

Invoke-AtomicTest T1070.001 -TestNumbers 2

## Detection
Deleting Windows event logs (via native binaries (Citation: Microsoft wevtutil Oct 2017), API functions (Citation: Microsoft EventLog.Clear), or [PowerShell](https://attack.mitre.org/techniques/T1059/001) (Citation: Microsoft Clear-EventLog)) may also generate an alterable event (Event ID 1102: "The audit log was cleared").