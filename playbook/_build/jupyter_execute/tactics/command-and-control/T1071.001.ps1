# T1071.001 - Application Layer Protocol: Web Protocols
Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

Protocols such as HTTP and HTTPS that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Malicious User Agents - Powershell
This test simulates an infected host beaconing to command and control. Upon execution, no output will be displayed. 
Use an application such as Wireshark to record the session and observe user agent strings and responses.

Inspired by APTSimulator - https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Invoke-WebRequest #{domain} -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest #{domain} -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest #{domain} -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest #{domain} -UserAgent "*<|>*" | out-null
```

Invoke-AtomicTest T1071.001 -TestNumbers 1

### Atomic Test #2 - Malicious User Agents - CMD
This test simulates an infected host beaconing to command and control. Upon execution, no out put will be displayed. 
Use an application such as Wireshark to record the session and observe user agent strings and responses.

Inspired by APTSimulator - https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
#{curl_path} -s -A "HttpBrowser/1.0" -m3 #{domain} >nul 2>&1
#{curl_path} -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain} >nul 2>&1
#{curl_path} -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain} >nul 2>&1
#{curl_path} -s -A "*<|>*" -m3 #{domain} >nul 2>&1
```

Invoke-AtomicTest T1071.001 -TestNumbers 2

### Atomic Test #3 - Malicious User Agents - Nix
This test simulates an infected host beaconing to command and control.
Inspired by APTSimulator - https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
curl -s -A "HttpBrowser/1.0" -m3 #{domain}
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain}
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain}
curl -s -A "*<|>*" -m3 #{domain}
```

Invoke-AtomicTest T1071.001 -TestNumbers 3

## Detection
Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol standards regarding syntax, structure, or any other variable adversaries could leverage to conceal data.(Citation: University of Birmingham C2)

Monitor for web traffic to/from known-bad or suspicious domains. 