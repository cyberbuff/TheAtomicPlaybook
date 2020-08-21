# T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key. (Citation: Microsoft CryptUnprotectData ‎April 2018)
 
Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc. (Citation: Proofpoint Vega Credential Stealer May 2018)(Citation: FireEye HawkEye Malware July 2017)

Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials.(Citation: GitHub Mimikittenz July 2016)

After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Run Chrome-password Collector
A modified sysinternals suite will be downloaded and staged. The Chrome-password collector, renamed accesschk.exe, will then be executed from #{file_path}.

Successful execution will produce stdout message stating "Copying db ... passwordsDB DB Opened. statement prepare DB connection closed properly". Upon completion, final output will be a file modification of $env:TEMP\sysinternals\passwordsdb.

Adapted from [MITRE ATTACK Evals](https://github.com/mitre-attack/attack-arsenal/blob/66650cebd33b9a1e180f7b31261da1789cdceb66/adversary_emulation/APT29/CALDERA_DIY/evals/data/abilities/credential-access/e7cab9bb-3e3a-4d93-99cc-3593c1dc8c6d.yml)

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Set-Location -path "#{file_path}\Sysinternals";
./accesschk.exe -accepteula .;
```

Invoke-AtomicTest T1555.003 -TestNumbers 1

### Atomic Test #2 - Search macOS Safari Cookies
This test uses `grep` to search a macOS Safari binaryCookies file for specified values. This was used by CookieMiner malware.

Upon successful execution, MacOS shell will cd to `~/Libraries/Cookies` and grep for `Cookies.binarycookies`.

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
cd ~/Library/Cookies
grep -q "#{search_string}" "Cookies.binarycookies"
```

Invoke-AtomicTest T1555.003 -TestNumbers 2

## Detection
Identify web browser files that contain credentials such as Google Chrome’s Login Data database file: <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code>. Monitor file read events of web browser files that contain credentials, especially when the reading process is unrelated to the subject web browser. Monitor process execution logs to include PowerShell Transcription focusing on those that perform a combination of behaviors including reading web browser process memory, utilizing regular expressions, and those that contain numerous keywords for common web applications (Gmail, Twitter, Office365, etc.).