# T1090.001 - Proxy: Internal Proxy
Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment.

By using a compromised internal system as a proxy, adversaries may conceal the true destination of C2 traffic while reducing the need for numerous connections to external systems.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Connection Proxy
Enable traffic redirection.

Note that this test may conflict with pre-existing system configuration.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
export #{proxy_scheme}_proxy=#{proxy_server}
```

Invoke-AtomicTest T1090.001 -TestNumbers 1

### Atomic Test #2 - Connection Proxy for macOS UI
Enable traffic redirection on macOS UI (not terminal).
The test will modify and enable the "Web Proxy" and "Secure Web Proxy" settings  in System Preferences => Network => Advanced => Proxies for the specified network interface.

Note that this test may conflict with pre-existing system configuration.

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
networksetup -setwebproxy #{interface} #{proxy_server} #{proxy_port}
networksetup -setsecurewebproxy #{interface} #{proxy_server} #{proxy_port}
```

Invoke-AtomicTest T1090.001 -TestNumbers 2

### Atomic Test #3 - portproxy reg key
Adds a registry key to set up a proxy on the endpoint at HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4
Upon execution there will be a new proxy entry in netsh
netsh interface portproxy show all

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
netsh interface portproxy add v4tov4 listenport=#{listenport} connectport=#{connectport} connectaddress=#{connectaddress}```

Invoke-AtomicTest T1090.001 -TestNumbers 3

## Detection
Analyze network data for uncommon data flows between clients that should not or often do not communicate with one another. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.(Citation: University of Birmingham C2)