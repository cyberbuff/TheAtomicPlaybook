# T1030 - Data Transfer Size Limits
An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Data Transfer Size Limits
Take a file/directory, split it into 5Mb chunks

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
cd #{folder_path}; split -b 5000000 #{file_name}
ls -l #{folder_path}
```

Invoke-AtomicTest T1030 -TestNumbers 1

## Detection
Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). If a process maintains a long connection during which it consistently sends fixed size data packets or a process opens connections and sends fixed sized data packets at regular intervals, it may be performing an aggregate data transfer. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)