# T1040 - Network Sniffing
Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Packet Capture Linux
Perform a PCAP. Wireshark will be required for tshark. TCPdump may already be installed.

Upon successful execution, tshark or tcpdump will execute and capture 5 packets on interface ens33.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
tcpdump -c 5 -nnni #{interface}
tshark -c 5 -i #{interface}
```

Invoke-AtomicTest T1040 -TestNumbers 1

### Atomic Test #2 - Packet Capture macOS
Perform a PCAP on macOS. This will require Wireshark/tshark to be installed. TCPdump may already be installed.

Upon successful execution, tshark or tcpdump will execute and capture 5 packets on interface en0A.

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
sudo tcpdump -c 5 -nnni #{interface}    
if [ -x "$(command -v tshark)" ]; then sudo tshark -c 5 -i #{interface}; fi;
```

Invoke-AtomicTest T1040 -TestNumbers 2

### Atomic Test #3 - Packet Capture Windows Command Prompt
Perform a packet capture using the windows command prompt. This will require a host that has Wireshark/Tshark
installed.

Upon successful execution, tshark will execute and capture 5 packets on interface "Ethernet".

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
"c:\Program Files\Wireshark\tshark.exe" -i #{interface} -c 5
```

Invoke-AtomicTest T1040 -TestNumbers 3

### Atomic Test #4 - Windows Internal Packet Capture
Uses the built-in Windows packet capture
After execution you should find a file named trace.etl and trace.cab in the temp directory
**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10```

Invoke-AtomicTest T1040 -TestNumbers 4

## Detection
Detecting the events leading up to sniffing network traffic may be the best method of detection. From the host level, an adversary would likely need to perform a man-in-the-middle attack against other devices on a wired network in order to capture traffic that was not to or from the current compromised system. This change in the flow of information is detectable at the enclave network level. Monitor for ARP spoofing and gratuitous ARP broadcasts. Detecting compromised network devices is a bit more challenging. Auditing administrator logins, configuration changes, and device images is required to detect malicious changes.