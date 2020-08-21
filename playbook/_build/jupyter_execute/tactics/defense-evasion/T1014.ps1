# T1014 - Rootkit
Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. (Citation: Symantec Windows Rootkits) 

Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or [System Firmware](https://attack.mitre.org/techniques/T1542/001). (Citation: Wikipedia Rootkit) Rootkits have been seen for Windows, Linux, and Mac OS X systems. (Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX Rootkit)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Loadable Kernel Module based Rootkit
Loadable Kernel Module based Rootkit

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
sudo insmod #{rootkit_path}
```

Invoke-AtomicTest T1014 -TestNumbers 1

### Atomic Test #2 - Loadable Kernel Module based Rootkit
Loadable Kernel Module based Rootkit

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
sudo modprobe #{rootkit_name}
```

Invoke-AtomicTest T1014 -TestNumbers 2

### Atomic Test #3 - Windows Signed Driver Rootkit Test
This test exploits a signed driver to execute code in Kernel.
SHA1 C1D5CF8C43E7679B782630E93F5E6420CA1749A7
We leverage the work done here:
https://zerosum0x0.blogspot.com/2017/07/puppet-strings-dirty-secret-for-free.html
The hash of our PoC Exploit is
SHA1 DD8DA630C00953B6D5182AA66AF999B1E117F441
This will simulate hiding a process.
It would be wise if you only run this in a test environment

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
puppetstrings #{driver_path}
```

Invoke-AtomicTest T1014 -TestNumbers 3

## Detection
Some rootkit protections may be built into anti-virus or operating system software. There are dedicated rootkit detection tools that look for specific types of rootkit behavior. Monitor for the existence of unrecognized DLLs, devices, services, and changes to the MBR. (Citation: Wikipedia Rootkit)