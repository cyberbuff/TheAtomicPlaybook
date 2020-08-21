# T1489 - Service Stop
Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster) 

Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <code>MSExchangeIS</code>, which will make Exchange content inaccessible (Citation: Novetta Blockbuster). In some cases, adversaries may stop or disable many or all services to render systems unusable.(Citation: Talos Olympic Destroyer 2018) Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct [Data Destruction](https://attack.mitre.org/techniques/T1485) or [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) on the data stores of services like Exchange and SQL Server.(Citation: SecureWorks WannaCry Analysis)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Windows - Stop service using Service Controller
Stops a specified service using the sc.exe command. Upon execution, if the spooler service was running infomration will be displayed saying
it has changed to a state of STOP_PENDING. If the spooler service was not running "The service has not been started." will be displayed and it can be
started by running the cleanup command.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
sc.exe stop #{service_name}
```

Invoke-AtomicTest T1489 -TestNumbers 1

### Atomic Test #2 - Windows - Stop service using net.exe
Stops a specified service using the net.exe command. Upon execution, if the service was running "The Print Spooler service was stopped successfully."
will be displayed. If the service was not running, "The Print Spooler service is not started." will be displayed and it can be
started by running the cleanup command.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net.exe stop #{service_name}
```

Invoke-AtomicTest T1489 -TestNumbers 2

### Atomic Test #3 - Windows - Stop service by killing process
Stops a specified service killng the service's process.
This technique was used by WannaCry. Upon execution, if the spoolsv service was running "SUCCESS: The process "spoolsv.exe" with PID 2316 has been terminated."
will be displayed. If the service was not running "ERROR: The process "spoolsv.exe" not found." will be displayed and it can be
started by running the cleanup command.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
taskkill.exe /f /im #{process_name}
```

Invoke-AtomicTest T1489 -TestNumbers 3

## Detection
Monitor processes and command-line arguments to see if critical processes are terminated or stop running.

Monitor Registry edits for modifications to services and startup programs that correspond to services of high importance. Look for changes to service Registry entries that do not correlate with known software, patch cycles, etc. Service information is stored in the Registry at <code>HKLM\SYSTEM\CurrentControlSet\Services</code>.

Alterations to the service binary path or the service startup type changed to disabled may be suspicious.

Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. For example, <code>ChangeServiceConfigW</code> may be used by an adversary to prevent services from starting.(Citation: Talos Olympic Destroyer 2018)