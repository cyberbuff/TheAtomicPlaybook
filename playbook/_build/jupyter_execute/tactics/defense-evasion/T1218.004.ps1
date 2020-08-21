# T1218.004 - Signed Binary Proxy Execution: InstallUtil
Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. (Citation: MSDN InstallUtil) InstallUtil is digitally signed by Microsoft and located in the .NET directories on a Windows system: <code>C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe</code> and <code>C:\Windows\Microsoft.NET\Framework64\v<version>\InstallUtil.exe</code>.

InstallUtil may also be used to bypass application control through use of attributes within the binary that execute the class decorated with the attribute <code>[System.ComponentModel.RunInstaller(true)]</code>. (Citation: LOLBAS Installutil)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - CheckIfInstallable method call
Executes the CheckIfInstallable class constructor runner instead of executing InstallUtil. Upon execution, the InstallUtil test harness will be executed.
If no output is displayed the test executed successfuly.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
CheckIfInstallable method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 1

### Atomic Test #2 - InstallHelper method call
Executes the InstallHelper class constructor runner instead of executing InstallUtil. Upon execution, no output will be displayed if the test
executed successfuly.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallHelper method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 2

### Atomic Test #3 - InstallUtil class constructor method call
Executes the installer assembly class constructor. Upon execution, version information will be displayed the .NET framework install utility.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil class constructor execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 3

### Atomic Test #4 - InstallUtil Install method call
Executes the Install Method. Upon execution, version information will be displayed the .NET framework install utility.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=install `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Install_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Install method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 4

### Atomic Test #5 - InstallUtil Uninstall method call - /U variant
Executes the Uninstall Method. Upon execution, version information will be displayed the .NET framework install utility.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /U `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 5

### Atomic Test #6 - InstallUtil Uninstall method call - '/installtype=notransaction /action=uninstall' variant
Executes the Uninstall Method. Upon execution, version information will be displayed the .NET framework install utility.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/logfile= /logtoconsole=false /installtype=notransaction /action=uninstall `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil Uninstall method execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 6

### Atomic Test #7 - InstallUtil HelpText method call
Executes the Uninstall Method. Upon execution, help information will be displayed for InstallUtil.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "#{assembly_dir}"
$InstallerAssemblyFileName = "#{assembly_filename}"
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "/? `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_HelpText_'

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = '#{invocation_method}'
    CommandLine = $CommandLine
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
InstallUtil HelpText property execution test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 7

### Atomic Test #8 - InstallUtil evasive invocation
Executes an InstallUtil assembly by renaming InstallUtil.exe and using a nonstandard extension for the assembly. Upon execution, "Running a transacted installation."
will be displayed, along with other information about the opperation. "The transacted install has completed." will be displayed upon completion.

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
# Import the required test harness function, Invoke-BuildAndInvokeInstallUtilAssembly
. #{test_harness}

$InstallerAssemblyDir = "$Env:windir\System32\Tasks"
$InstallerAssemblyFileName = 'readme.txt'
$InstallerAssemblyFullPath = Join-Path -Path $InstallerAssemblyDir -ChildPath $InstallerAssemblyFileName

$CommandLine = "readme.txt"
$ExpectedOutput = 'Constructor_'

# Explicitly set the directory so that a relative path to readme.txt can be supplied.
Set-Location "$Env:windir\System32\Tasks"

Copy-Item -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())InstallUtil.exe" -Destination "$Env:windir\System32\Tasks\notepad.exe"

$TestArgs = @{
    OutputAssemblyDirectory = $InstallerAssemblyDir
    OutputAssemblyFileName = $InstallerAssemblyFileName
    InvocationMethod = 'Executable'
    CommandLine = $CommandLine
    InstallUtilPath = "$Env:windir\System32\Tasks\notepad.exe"
}

$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly

if ($ActualOutput -ne $ExpectedOutput) {
    throw @"
Evasive Installutil invocation test failure. Installer assembly execution output did not match the expected output.
Expected: $ExpectedOutput
Actual: $ActualOutput
"@
}
```

Invoke-AtomicTest T1218.004 -TestNumbers 8

## Detection
Use process monitoring to monitor the execution and arguments of InstallUtil.exe. Compare recent invocations of InstallUtil.exe with prior history of known good arguments and executed binaries to determine anomalous and potentially adversarial activity. Command arguments used before and after the InstallUtil.exe invocation may also be useful in determining the origin and purpose of the binary being executed.