# T1543.002 - Create or Modify System Process: Systemd Service
Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. The systemd service manager is commonly used for managing background daemon processes (also known as services) and other system resources.(Citation: Linux man-pages: systemd January 2014)(Citation: Freedesktop.org Linux systemd 29SEP2018) Systemd is the default initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and Upstart while remaining backwards compatible with the aforementioned init systems.

Systemd utilizes configuration files known as service units to control how services boot and under what conditions. By default, these unit files are stored in the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories and have the file extension <code>.service</code>. Each service unit file may contain numerous directives that can execute system commands:

* ExecStart, ExecStartPre, and ExecStartPost directives cover execution of commands when a services is started manually by 'systemctl' or on system start if the service is set to automatically start. 
* ExecReload directive covers when a service restarts. 
* ExecStop and ExecStopPost directives cover when a service is stopped or manually by 'systemctl'.

Adversaries have used systemd functionality to establish persistent access to victim systems by creating and/or modifying service unit files that cause systemd to execute malicious commands at recurring intervals, such as at system boot.(Citation: Anomali Rocke March 2019)(Citation: gist Arch package compromise 10JUL2018)(Citation: Arch Linux Package Systemd Compromise BleepingComputer 10JUL2018)(Citation: acroread package compromised Arch Linux Mail 8JUL2018)

While adversaries typically require root privileges to create/modify service unit files in the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories, low privilege users can create/modify service unit files in directories such as <code>~/.config/systemd/user/</code> to achieve user-level persistence.(Citation: Rapid7 Service Persistence 22JUNE2016)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Create Systemd Service
This test creates a Systemd service unit file and enables it as a service.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
echo "[Unit]" > #{systemd_service_path}/#{systemd_service_file}
echo "Description=Atomic Red Team Systemd Service" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Service]" >> #{systemd_service_path}/#{systemd_service_file}
echo "Type=simple"
echo "ExecStart=#{execstart_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPre=#{execstartpre_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStartPost=#{execstartpost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecReload=#{execreload_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStop=#{execstop_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "ExecStopPost=#{execstoppost_action}" >> #{systemd_service_path}/#{systemd_service_file}
echo "" >> #{systemd_service_path}/#{systemd_service_file}
echo "[Install]" >> #{systemd_service_path}/#{systemd_service_file}
echo "WantedBy=default.target" >> #{systemd_service_path}/#{systemd_service_file}
systemctl daemon-reload
systemctl enable #{systemd_service_file}
systemctl start #{systemd_service_file}
```

Invoke-AtomicTest T1543.002 -TestNumbers 1

## Detection
Systemd service unit files may be detected by auditing file creation and modification events within the <code>/etc/systemd/system</code>, <code>/usr/lib/systemd/system/</code>, and <code>/home/<username>/.config/systemd/user/</code> directories, as well as associated symbolic links. Suspicious processes or scripts spawned in this manner will have a parent process of ‘systemd’, a parent process ID of 1, and will usually execute as the ‘root’ user.

Suspicious systemd services can also be identified by comparing results against a trusted system baseline. Malicious systemd services may be detected by using the systemctl utility to examine system wide services: <code>systemctl list-units -–type=service –all</code>. Analyze the contents of <code>.service</code> files present on the file system and ensure that they refer to legitimate, expected executables.

Auditing the execution and command-line arguments of the 'systemctl' utility, as well related utilities such as <code>/usr/sbin/service</code> may reveal malicious systemd service execution.