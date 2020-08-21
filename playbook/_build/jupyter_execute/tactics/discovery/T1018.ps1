# T1018 - Remote System Discovery
Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  [Ping](https://attack.mitre.org/software/S0097) or <code>net view</code> using [Net](https://attack.mitre.org/software/S0039). Adversaries may also use local host files (ex: <code>C:\Windows\System32\Drivers\etc\hosts</code> or <code>/etc/hosts</code>) in order to discover the hostname to IP address mappings of remote systems. 

Specific to macOS, the <code>bonjour</code> protocol exists to discover additional Mac-based systems within the same broadcast domain.

Within IaaS (Infrastructure as a Service) environments, remote systems include instances and virtual machines in various states, including the running or stopped state. Cloud providers have created methods to serve information about remote systems, such as APIs and CLIs. For example, AWS provides a <code>DescribeInstances</code> API within the Amazon EC2 API and a <code>describe-instances</code> command within the AWS CLI that can return information about all instances within an account.(Citation: Amazon Describe Instances API)(Citation: Amazon Describe Instances CLI) Similarly, GCP's Cloud SDK CLI provides the <code>gcloud compute instances list</code> command to list all Google Compute Engine instances in a project, and Azure's CLI <code>az vm list</code> lists details of virtual machines.(Citation: Google Compute Instances)(Citation: Azure VM List)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Remote System Discovery - net
Identify remote systems with net.exe.

Upon successful execution, cmd.exe will execute `net.exe view` and display results of local systems on the network that have file and print sharing enabled.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net view /domain
net view
```

Invoke-AtomicTest T1018 -TestNumbers 1

### Atomic Test #2 - Remote System Discovery - net group Domain Computers
Identify remote systems with net.exe querying the Active Directory Domain Computers group.

Upon successful execution, cmd.exe will execute cmd.exe against Active Directory to list the "Domain Computers" group. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
net group "Domain Computers" /domain
```

Invoke-AtomicTest T1018 -TestNumbers 2

### Atomic Test #3 - Remote System Discovery - nltest
Identify domain controllers for specified domain.

Upon successful execution, cmd.exe will execute nltest.exe against a target domain to retrieve a list of domain controllers. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
nltest.exe /dclist:#{target_domain}
```

Invoke-AtomicTest T1018 -TestNumbers 3

### Atomic Test #4 - Remote System Discovery - ping sweep
Identify remote systems via ping sweep.

Upon successful execution, cmd.exe will perform a for loop against the 192.168.1.1/24 network. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
for /l %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i
```

Invoke-AtomicTest T1018 -TestNumbers 4

### Atomic Test #5 - Remote System Discovery - arp
Identify remote systems via arp. 

Upon successful execution, cmd.exe will execute arp to list out the arp cache. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
arp -a
```

Invoke-AtomicTest T1018 -TestNumbers 5

### Atomic Test #6 - Remote System Discovery - arp nix
Identify remote systems via arp.

Upon successful execution, sh will execute arp to list out the arp cache. Output will be via stdout.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
arp -a | grep -v '^?'
```

Invoke-AtomicTest T1018 -TestNumbers 6

### Atomic Test #7 - Remote System Discovery - sweep
Identify remote systems via ping sweep.

Upon successful execution, sh will perform a ping sweep on the 192.168.1.1/24 and echo via stdout if an IP is active.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
for ip in $(seq #{start_host} #{stop_host}); do ping -c 1 #{subnet}.$ip; [ $? -eq 0 ] && echo "#{subnet}.$ip UP" || : ; done
```

Invoke-AtomicTest T1018 -TestNumbers 7

### Atomic Test #8 - Remote System Discovery - nslookup
Powershell script that runs nslookup on cmd.exe against the local /24 network of the first network adaptor listed in ipconfig.

Upon successful execution, powershell will identify the ip range (via ipconfig) and perform a for loop and execute nslookup against that IP range. Output will be via stdout.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$pieces = $localip.split(".")
$firstOctet = $pieces[0]
$secondOctet = $pieces[1]
$thirdOctet = $pieces[2]
foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}
```

Invoke-AtomicTest T1018 -TestNumbers 8

### Atomic Test #9 - Remote System Discovery - adidnsdump
This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks
Python 3 and adidnsdump must be installed, use the get_prereq_command's to meet the prerequisites for this test.
Successful execution of this test will list dns zones in the terminal.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
adidnsdump -u #{user_name} -p #{acct_pass} --print-zones #{host_name}
```

Invoke-AtomicTest T1018 -TestNumbers 9

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Normal, benign system and network events related to legitimate remote system discovery may be uncommon, depending on the environment and how they are used. Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

In cloud environments, the usage of particular commands or APIs to request information about remote systems may be common. Where possible, anomalous usage of these commands and APIs or the usage of these commands and APIs in conjunction with additional unexpected commands may be a sign of malicious use. Logging methods provided by cloud providers that capture history of CLI commands executed or API usage may be utilized for detection.