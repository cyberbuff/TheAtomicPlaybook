# T1113 - Screen Capture
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)


## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Screencapture
Use screencapture command to collect a full desktop screenshot

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
screencapture #{output_file}
```

Invoke-AtomicTest T1113 -TestNumbers 1

### Atomic Test #2 - Screencapture (silent)
Use screencapture command to collect a full desktop screenshot

**Supported Platforms:** macos
#### Attack Commands: Run with `bash`
```bash
screencapture -x #{output_file}
```

Invoke-AtomicTest T1113 -TestNumbers 2

### Atomic Test #3 - X Windows Capture
Use xwd command to collect a full desktop screenshot and review file with xwud

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
xwd -root -out #{output_file}
xwud -in #{output_file}
```

Invoke-AtomicTest T1113 -TestNumbers 3

### Atomic Test #4 - Import
Use import command to collect a full desktop screenshot

**Supported Platforms:** linux
#### Attack Commands: Run with `bash`
```bash
import -window root #{output_file}
```

Invoke-AtomicTest T1113 -TestNumbers 4

## Detection
Monitoring for screen capture behavior will depend on the method used to obtain data from the operating system and write output files. Detection methods could include collecting information from unusual processes using API calls used to obtain image data, and monitoring for image files written to disk. The sensor data may need to be correlated with other events to identify malicious activity, depending on the legitimacy of this behavior within a given network environment.