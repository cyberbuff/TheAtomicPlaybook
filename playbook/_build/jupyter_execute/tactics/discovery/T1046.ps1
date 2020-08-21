# T1046 - Network Service Scanning
Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. 

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Port Scan
Scan ports to check for listening ports.

Upon successful execution, sh will perform a network connection against a single host (192.168.1.1) and determine what ports are open in the range of 1-65535. Results will be via stdout.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
for port in {1..65535};
do
  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" || echo "port $port is closed" : ;
done
```

Invoke-AtomicTest T1046 -TestNumbers 1

### Atomic Test #2 - Port Scan Nmap
Scan ports to check for listening ports with Nmap.

Upon successful execution, sh will utilize nmap, telnet, and nc to contact a single or range of adresseses on port 80 to determine if listening. Results will be via stdout.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
nmap -sS #{network_range} -p #{port}
telnet #{host} #{port}
nc -nv #{host} #{port}
```

Invoke-AtomicTest T1046 -TestNumbers 2

### Atomic Test #3 - Port Scan NMap for Windows
Scan ports to check for listening ports for the local host 127.0.0.1
**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
nmap #{host_to_scan}```

Invoke-AtomicTest T1046 -TestNumbers 3

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Normal, benign system and network events from legitimate remote service scanning may be uncommon, depending on the environment and how they are used. Legitimate open port and vulnerability scanning may be conducted within the environment and will need to be deconflicted with any detection capabilities developed. Network intrusion detection systems can also be used to identify scanning activity. Monitor for process use of the networks and inspect intra-network flows to detect port scans.