# T1574.006 - Hijack Execution Flow: LD_PRELOAD
Adversaries may execute their own malicious payloads by hijacking the dynamic linker used to load libraries. The dynamic linker is used to load shared library dependencies needed by an executing program. The dynamic linker will typically check provided absolute paths and common directories for these dependencies, but can be overridden by shared objects specified by LD_PRELOAD to be loaded before all others.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries)

Adversaries may set LD_PRELOAD to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program. LD_PRELOAD can be set via the environment variable or <code>/etc/ld.so.preload</code> file.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries) Libraries specified by LD_PRELOAD with be loaded and mapped into memory by <code>dlopen()</code> and <code>mmap()</code> respectively.(Citation: Code Injection on Linux and macOS) (Citation: Uninformed Needle) (Citation: Phrack halfdead 1997)

LD_PRELOAD hijacking may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. Execution via LD_PRELOAD hijacking may also evade detection from security products since the execution is masked under a legitimate process.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Shared Library Injection via /etc/ld.so.preload
This test adds a shared library to the `ld.so.preload` list to execute and intercept API calls. This technique was used by threat actor Rocke during the exploitation of Linux web servers. This requires the `glibc` package.

Upon successful execution, bash will echo `../bin/T1574.006.so` to /etc/ld.so.preload. 

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
sudo sh -c 'echo #{path_to_shared_library} > /etc/ld.so.preload'
```

Invoke-AtomicTest T1574.006 -TestNumbers 1

### Atomic Test #2 - Shared Library Injection via LD_PRELOAD
This test injects a shared object library via the LD_PRELOAD environment variable to execute. This technique was used by threat actor Rocke during the exploitation of Linux web servers. This requires the `glibc` package.

Upon successful execution, bash will utilize LD_PRELOAD to load the shared object library `/etc/ld.so.preload`. Output will be via stdout.

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
LD_PRELOAD=#{path_to_shared_library} ls
```

Invoke-AtomicTest T1574.006 -TestNumbers 2

## Detection
Monitor for changes to environment variables and files associated with loading shared libraries such as LD_PRELOAD, as well as the commands to implement these changes.

Monitor processes for unusual activity (e.g., a process that does not use the network begins to do so). Track library metadata, such as a hash, and compare libraries that are loaded at process execution time against previous executions to detect differences that do not correlate with patching or updates.