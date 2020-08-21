# T1546.005 - Event Triggered Execution: Trap
Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.

Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where "command list" will be executed when "signals" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Trap
After exiting the shell, the script will download and execute.
After sending a keyboard interrupt (CTRL+C) the script will download and execute.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
trap "nohup sh $PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh | bash" EXIT
exit
trap "nohup sh $PathToAtomicsFolder/T1546.005/src/echo-art-fish.sh | bash" SIGINt
```

Invoke-AtomicTest T1546.005 -TestNumbers 1

## Detection
Trap commands must be registered for the shell or programs, so they appear in files. Monitoring files for suspicious or overly broad trap commands can narrow down suspicious behavior during an investigation. Monitor for suspicious processes executed through trap interrupts.