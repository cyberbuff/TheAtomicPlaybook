# T1027.002 - Obfuscated Files or Information: Software Packing
Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018) 

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, (Citation: Wikipedia Exe Compression) but adversaries may create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.  

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Binary simply packed by UPX (linux)
Copies and then runs a simple binary (just outputting "the cake is a lie"), that was packed by UPX.
No other protection/compression were applied.

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
cp #{bin_path} /tmp/packed_bin && /tmp/packed_bin
```

Invoke-AtomicTest T1027.002 -TestNumbers 1

### Atomic Test #2 - Binary packed by UPX, with modified headers (linux)
Copies and then runs a simple binary (just outputting "the cake is a lie"), that was packed by UPX.

The UPX magic number (`0x55505821`, "`UPX!`") was changed to (`0x4c4f5452`, "`LOTR`"). This prevents the binary from being detected
by some methods, and especially UPX is not able to uncompress it any more.

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
cp #{bin_path} /tmp/packed_bin && /tmp/packed_bin
```

Invoke-AtomicTest T1027.002 -TestNumbers 2

### Atomic Test #3 - Binary simply packed by UPX
Copies and then runs a simple binary (just outputting "the cake is a lie"), that was packed by UPX.
No other protection/compression were applied.

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
cp #{bin_path} /tmp/packed_bin && /tmp/packed_bin
```

Invoke-AtomicTest T1027.002 -TestNumbers 3

### Atomic Test #4 - Binary packed by UPX, with modified headers
Copies and then runs a simple binary (just outputting "the cake is a lie"), that was packed by UPX.

The UPX magic number (`0x55505821`, "`UPX!`") was changed to (`0x4c4f5452`, "`LOTR`"). This prevents the binary from being detected
by some methods, and especially UPX is not able to uncompress it any more.

**Supported Platforms:** macos
#### Attack Commands: Run with `sh`
```sh
cp #{bin_path} /tmp/packed_bin && /tmp/packed_bin
```

Invoke-AtomicTest T1027.002 -TestNumbers 4

## Detection
Use file scanning to look for known software packers or artifacts of packing techniques. Packing is not a definitive indicator of malicious activity, because legitimate software may use packing techniques to reduce binary size or to protect proprietary code.