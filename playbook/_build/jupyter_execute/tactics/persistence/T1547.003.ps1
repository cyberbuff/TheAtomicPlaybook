# T1547.003 - Time Providers
Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. (Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. (Citation: Microsoft TimeProvider)

Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of  <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\</code>. (Citation: Microsoft TimeProvider) The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed. (Citation: Microsoft TimeProvider)

Adversaries may abuse this architecture to establish persistence, specifically by registering and enabling a malicious DLL as a time provider. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account. (Citation: Github W32Time Oct 2017)

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Baseline values and monitor/analyze activity related to modifying W32Time information in the Registry, including application programming interface (API) calls such as <code>RegCreateKeyEx</code> and <code>RegSetValueEx</code> as well as execution of the W32tm.exe utility. (Citation: Microsoft W32Time May 2017) There is no restriction on the number of custom time providers registrations, though each may require a DLL payload written to disk. (Citation: Github W32Time Oct 2017)

The Sysinternals Autoruns tool may also be used to analyze auto-starting locations, including DLLs listed as time providers. (Citation: TechNet Autoruns)