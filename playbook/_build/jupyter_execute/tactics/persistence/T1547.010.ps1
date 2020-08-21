# T1547.010 - Port Monitors
Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup. (Citation: AddMonitor) This DLL can be located in <code>C:\Windows\System32</code> and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. (Citation: Bloxham) Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</code>. 

The Registry key contains entries for the following:

* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port

Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor process API calls to <code>AddMonitor</code>.(Citation: AddMonitor) Monitor DLLs that are loaded by spoolsv.exe for DLLs that are abnormal. New DLLs written to the System32 directory that do not correlate with known good software or patching may be suspicious. 

Monitor Registry writes to <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</code>. Run the Autoruns utility, which checks for this Registry key as a persistence mechanism (Citation: TechNet Autoruns)