# T1056.004 - Input Capture: Credential API Hooking
Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001),  this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:

* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.(Citation: Microsoft Hook Overview)(Citation: Endgame Process Injection July 2017)
* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored.(Citation: Endgame Process Injection July 2017)(Citation: Adlice Software IAT Hooks Oct 2014)(Citation: MWRInfoSecurity Dynamic Hooking 2015)
* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow.(Citation: Endgame Process Injection July 2017)(Citation: HighTech Bridge Inline Hooking Sept 2011)(Citation: MWRInfoSecurity Dynamic Hooking 2015)


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Hook PowerShell TLS Encrypt/Decrypt Messages
Hooks functions in PowerShell to read TLS Communications

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
mavinject $pid /INJECTRUNNING #{file_name}
curl #{server_name}
```

Invoke-AtomicTest T1056.004 -TestNumbers 1

## Detection
Monitor for calls to the `SetWindowsHookEx` and `SetWinEventHook` functions, which install a hook procedure.(Citation: Microsoft Hook Overview)(Citation: Volatility Detecting Hooks Sept 2012) Also consider analyzing hook chains (which hold pointers to hook procedures for each type of hook) using tools(Citation: Volatility Detecting Hooks Sept 2012)(Citation: PreKageo Winhook Jul 2011)(Citation: Jay GetHooks Sept 2011) or by programmatically examining internal kernel structures.(Citation: Zairon Hooking Dec 2006)(Citation: EyeofRa Detecting Hooking June 2017)

Rootkits detectors(Citation: GMER Rootkits) can also be used to monitor for various types of hooking activity.

Verify integrity of live processes by comparing code in memory to that of corresponding static binaries, specifically checking for jumps and other instructions that redirect code flow. Also consider taking snapshots of newly started processes(Citation: Microsoft Process Snapshot) to compare the in-memory IAT to the real addresses of the referenced functions.(Citation: StackExchange Hooks Jul 2012)(Citation: Adlice Software IAT Hooks Oct 2014)