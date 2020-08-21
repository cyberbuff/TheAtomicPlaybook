# T1016 - System Network Configuration Discovery
Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - System Network Configuration Discovery on Windows
Identify network configuration information

Upon successful execution, cmd.exe will spawn multiple commands to list network configuration settings. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
ipconfig /all
netsh interface show interface
arp -a
nbtstat -n
net config
```

Invoke-AtomicTest T1016 -TestNumbers 1

### Atomic Test #2 - List Windows Firewall Rules
Enumerates Windows Firewall Rules using netsh.

Upon successful execution, cmd.exe will spawn netsh.exe to list firewall rules. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
netsh advfirewall firewall show rule name=all
```

Invoke-AtomicTest T1016 -TestNumbers 2

### Atomic Test #3 - System Network Configuration Discovery
Identify network configuration information.

Upon successful execution, sh will spawn multiple commands and output will be via stdout.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
if [ -x "$(command -v arp)" ]; then arp -a; else echo "arp is missing from the machine. skipping..."; fi;
if [ -x "$(command -v ifconfig)" ]; then ifconfig; else echo "ifconfig is missing from the machine. skipping..."; fi;
if [ -x "$(command -v ip)" ]; then ip addr; else echo "ip is missing from the machine. skipping..."; fi;
if [ -x "$(command -v netstat)" ]; then netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c; else echo "netstat is missing from the machine. skipping..."; fi;
```

Invoke-AtomicTest T1016 -TestNumbers 3

### Atomic Test #4 - System Network Configuration Discovery (TrickBot Style)
Identify network configuration information as seen by Trickbot and described here https://www.sneakymonkey.net/2019/10/29/trickbot-analysis-part-ii/

Upon successful execution, cmd.exe will spawn `ipconfig /all`, `net config workstation`, `net view /all /domain`, `nltest /domain_trusts`. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts
```

Invoke-AtomicTest T1016 -TestNumbers 4

### Atomic Test #5 - List Open Egress Ports
This is to test for what ports are open outbound.  The technique used was taken from the following blog:
https://www.blackhillsinfosec.com/poking-holes-in-the-firewall-egress-testing-with-allports-exposed/

Upon successful execution, powershell will read top-128.txt (ports) and contact each port to confirm if open or not. Output will be to Desktop\open-ports.txt.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$ports = Get-content #{port_file}
$file = "#{output_file}"
$totalopen = 0
$totalports = 0
New-Item $file -Force
foreach ($port in $ports) {
    $test = new-object system.Net.Sockets.TcpClient
    $wait = $test.beginConnect("allports.exposed", $port, $null, $null)
    $wait.asyncwaithandle.waitone(250, $false) | Out-Null
    $totalports++ | Out-Null
    if ($test.Connected) {
        $result = "$port open" 
        Write-Host -ForegroundColor Green $result
        $result | Out-File -Encoding ASCII -append $file
        $totalopen++ | Out-Null
    }
    else {
        $result = "$port closed" 
        Write-Host -ForegroundColor Red $result
        $totalclosed++ | Out-Null
        $result | Out-File -Encoding ASCII -append $file
    }
}
$results = "There were a total of $totalopen open ports out of $totalports ports tested."
$results | Out-File -Encoding ASCII -append $file
Write-Host $results
```

Invoke-AtomicTest T1016 -TestNumbers 5

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).