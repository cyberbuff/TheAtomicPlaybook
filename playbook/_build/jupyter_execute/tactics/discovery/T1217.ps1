# T1217 - Browser Bookmark Discovery
Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.

Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially [Credentials In Files](https://attack.mitre.org/techniques/T1552/001) associated with logins cached by a browser.

Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - List Mozilla Firefox Bookmark Database Files on Linux
Searches for Mozilla Firefox's places.sqlite file (on Linux distributions) that contains bookmarks and lists any found instances to a text file.

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
find / -path "*.mozilla/firefox/*/places.sqlite" 2>/dev/null -exec echo {} >> #{output_file} \;
cat #{output_file} 2>/dev/null
```

Invoke-AtomicTest T1217 -TestNumbers 1

### Atomic Test #2 - List Mozilla Firefox Bookmark Database Files on macOS
Searches for Mozilla Firefox's places.sqlite file (on macOS) that contains bookmarks and lists any found instances to a text file.

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
find / -path "*/Firefox/Profiles/*/places.sqlite" -exec echo {} >> #{output_file} \;
cat #{output_file} 2>/dev/null
```

Invoke-AtomicTest T1217 -TestNumbers 2

### Atomic Test #3 - List Google Chrome Bookmark JSON Files on macOS
Searches for Google Chrome's Bookmark file (on macOS) that contains bookmarks in JSON format and lists any found instances to a text file.

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
find / -path "*/Google/Chrome/*/Bookmarks" -exec echo {} >> #{output_file} \;
cat #{output_file} 2>/dev/null
```

Invoke-AtomicTest T1217 -TestNumbers 3

### Atomic Test #4 - List Google Chrome Bookmarks on Windows with powershell
Searches for Google Chromes's Bookmarks file (on Windows distributions) that contains bookmarks.
Upon execution, paths that contain bookmark files will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Get-ChildItem -Path C:\Users\ -Filter Bookmarks -Recurse -ErrorAction SilentlyContinue -Force
```

Invoke-AtomicTest T1217 -TestNumbers 4

### Atomic Test #5 - List Google Chrome / Edge Chromium Bookmarks on Windows with command prompt
Searches for Google Chromes's and Edge Chromium's Bookmarks file (on Windows distributions) that contains bookmarks.
Upon execution, paths that contain bookmark files will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
where /R C:\Users\ Bookmarks
```

Invoke-AtomicTest T1217 -TestNumbers 5

### Atomic Test #6 - List Mozilla Firefox bookmarks on Windows with command prompt
Searches for Mozilla Firefox bookmarks file (on Windows distributions) that contains bookmarks in a SQLITE database.
Upon execution, paths that contain bookmark files will be displayed.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
where /R C:\Users\ places.sqlite
```

Invoke-AtomicTest T1217 -TestNumbers 6

## Detection
Monitor processes and command-line arguments for actions that could be taken to gather browser bookmark information. Remote access tools with built-in features may interact directly using APIs to gather information. Information may also be acquired through system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Collection and Exfiltration, based on the information obtained.