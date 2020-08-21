# T1082 - System Information Discovery
An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Tools such as [Systeminfo](https://attack.mitre.org/software/S0096) can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS <code>systemsetup</code> command, but it requires administrative privileges.

Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.(Citation: Amazon Describe Instance)(Citation: Google Instances Resource)(Citation: Microsoft Virutal Machine API)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - System Information Discovery
Identify System Info. Upon execution, system info and time info will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
```

Invoke-AtomicTest T1082 -TestNumbers 1

### Atomic Test #2 - System Information Discovery
Identify System Info

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
system_profiler
ls -al /Applications
```

Invoke-AtomicTest T1082 -TestNumbers 2

### Atomic Test #3 - List OS Information
Identify System Info

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
uname -a >> #{output_file}
if [ -f /etc/lsb-release ]; then cat /etc/lsb-release >> #{output_file}; fi;
if [ -f /etc/redhat-release ]; then cat /etc/redhat-release >> #{output_file}; fi;      
if [ -f /etc/issue ]; then cat /etc/issue >> #{output_file}; fi;
uptime >> #{output_file}
cat #{output_file} 2>/dev/null
```

Invoke-AtomicTest T1082 -TestNumbers 3

### Atomic Test #4 - Linux VM Check via Hardware
Identify virtual machine hardware. This technique is used by the Pupy RAT and other malware.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
if [ -f /sys/class/dmi/id/bios_version ]; then cat /sys/class/dmi/id/bios_version | grep -i amazon; fi;
if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"; fi;
if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"; fi;
if [ -x "$(command -v dmidecode)" ]; then sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"; fi;
if [ -f /proc/scsi/scsi ]; then cat /proc/scsi/scsi | grep -i "vmware\|vbox"; fi;
if [ -f /proc/ide/hd0/model ]; then cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"; fi;
if [ -x "$(command -v lspci)" ]; then sudo lspci | grep -i "vmware\|virtualbox"; fi;
if [ -x "$(command -v lscpu)" ]; then sudo lscpu | grep -i "Xen\|KVM\|Microsoft"; fi;
```

Invoke-AtomicTest T1082 -TestNumbers 4

### Atomic Test #5 - Linux VM Check via Kernel Modules
Identify virtual machine guest kernel modules. This technique is used by the Pupy RAT and other malware.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
sudo lsmod | grep -i "vboxsf\|vboxguest"
sudo lsmod | grep -i "vmw_baloon\|vmxnet"
sudo lsmod | grep -i "xen-vbd\|xen-vnif"
sudo lsmod | grep -i "virtio_pci\|virtio_net"
sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"
```

Invoke-AtomicTest T1082 -TestNumbers 5

### Atomic Test #6 - Hostname Discovery (Windows)
Identify system hostname for Windows. Upon execution, the hostname of the device will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
hostname
```

Invoke-AtomicTest T1082 -TestNumbers 6

### Atomic Test #7 - Hostname Discovery
Identify system hostname for Linux and macOS systems.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `bash`
```bash
hostname
```

Invoke-AtomicTest T1082 -TestNumbers 7

### Atomic Test #8 - Windows MachineGUID Discovery
Identify the Windows MachineGUID value for a system. Upon execution, the machine GUID will be displayed from registry.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid
```

Invoke-AtomicTest T1082 -TestNumbers 8

## Detection
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

In cloud-based systems, native logging can be used to identify access to certain APIs and dashboards that may contain system information. Depending on how the environment is used, that data alone may not be useful due to benign use during normal operations.