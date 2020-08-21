# T1560.001 - Archive Collected Data: Archive via Utility
An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities. Many utilities exist that can archive data, including 7-Zip(Citation: 7zip Homepage), WinRAR(Citation: WinRAR Homepage), and WinZip(Citation: WinZip Homepage). Most utilities include functionality to encrypt and/or compress data.

Some 3rd party utilities may be preinstalled, such as `tar` on Linux and macOS or `zip` on Windows systems.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Compress Data for Exfiltration With Rar
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration.
When the test completes you should find the txt files from the %USERPROFILE% directory compressed in a file called T1560.001-data.rar in the %USERPROFILE% directory 

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
"#{rar_exe}" a -r #{output_file} #{input_path}\*#{file_extension}
```

Invoke-AtomicTest T1560.001 -TestNumbers 1

### Atomic Test #2 - Compress Data and lock with password for Exfiltration with winrar
Note: Requires winrar installation
rar a -p"blue" hello.rar (VARIANT)

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
rar a -hp"blue" hello.rar
dir
```

Invoke-AtomicTest T1560.001 -TestNumbers 2

### Atomic Test #3 - Compress Data and lock with password for Exfiltration with winzip
Note: Requires winzip installation
wzzip sample.zip -s"blueblue" *.txt (VARIANT)

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
"#{winzip_exe}" -min -a -s"hello" archive.zip *
dir
```

Invoke-AtomicTest T1560.001 -TestNumbers 3

### Atomic Test #4 - Compress Data and lock with password for Exfiltration with 7zip
Note: Requires 7zip installation

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
mkdir $PathToAtomicsFolder\T1560.001\victim-files
cd $PathToAtomicsFolder\T1560.001\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
7z a archive.7z -pblue
dir
```

Invoke-AtomicTest T1560.001 -TestNumbers 4

### Atomic Test #5 - Data Compressed - nix - zip
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration. This test uses standard zip compression.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
zip #{output_file} #{input_files}
```

Invoke-AtomicTest T1560.001 -TestNumbers 5

### Atomic Test #6 - Data Compressed - nix - gzip Single File
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration. This test uses standard gzip compression.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
test -e #{input_file} && gzip -k #{input_file} || (echo '#{input_content}' >> #{input_file}; gzip -k #{input_file})
```

Invoke-AtomicTest T1560.001 -TestNumbers 6

### Atomic Test #7 - Data Compressed - nix - tar Folder or File
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration. This test uses standard gzip compression.

**Supported Platforms:** linux, macos
#### Attack Commands: Run with `sh`
```sh
tar -cvzf #{output_file} #{input_file_folder}
```

Invoke-AtomicTest T1560.001 -TestNumbers 7

### Atomic Test #8 - Data Encrypted with zip and gpg symmetric
Encrypt data for exiltration

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
mkdir -p #{test_folder}
cd #{test_folder}; touch a b c d e f g
zip --password "#{encryption_password}" #{test_folder}/#{test_file} ./*
echo "#{encryption_password}" | gpg --batch --yes --passphrase-fd 0 --output #{test_folder}/#{test_file}.zip.gpg -c #{test_folder}/#{test_file}.zip
ls -l #{test_folder}
```

Invoke-AtomicTest T1560.001 -TestNumbers 8

## Detection
Common utilities that may be present on the system or brought in by an adversary may be detectable through process monitoring and monitoring for command-line arguments for known archival utilities. This may yield a significant number of benign events, depending on how systems in the environment are typically used.

Consider detecting writing of files with extensions and/or headers associated with compressed or encrypted file types. Detection efforts may focus on follow-on exfiltration activity, where compressed or encrypted files can be detected in transit with a network intrusion detection or data loss prevention system analyzing file headers.(Citation: Wikipedia File Header Signatures)