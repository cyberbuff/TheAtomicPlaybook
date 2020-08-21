# T1553.004 - Subvert Trust Controls: Install Root Certificate
Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. (Citation: Wikipedia Root Certificate) Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.

Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials. (Citation: Operation Emmental)

Atypical root certificates have also been pre-installed on systems by the manufacturer or in the software supply chain and were used in conjunction with malware/adware to provide a man-in-the-middle capability for intercepting information transmitted over secure TLS/SSL communications. (Citation: Kaspersky Superfish)

Root certificates (and their associated chains) can also be cloned and reinstalled. Cloned certificate chains will carry many of the same metadata characteristics of the source and can be used to sign malicious code that may then bypass signature validation tools (ex: Sysinternals, antivirus, etc.) used to block execution and/or uncover artifacts of Persistence. (Citation: SpectorOps Code Signing Dec 2017)

In macOS, the Ay MaMi malware uses <code>/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/malicious/cert</code> to install a malicious certificate as a trusted root certificate into the system keychain. (Citation: objective-see ay mami 2018)

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Install root CA on CentOS/RHEL
Creates a root CA with openssl

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
openssl genrsa -out #{key_filename} 4096
openssl req -x509 -new -nodes -key #{key_filename} -sha256 -days 365 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" -out #{cert_filename}

if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -le "5" ];
then
  cat rootCA.crt >> /etc/pki/tls/certs/ca-bundle.crt
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -ge "7" ];
  cp rootCA.crt /etc/pki/ca-trust/source/anchors/
  update-ca-trust
fi
```

Invoke-AtomicTest T1553.004 -TestNumbers 1

### Atomic Test #2 - Install root CA on Debian/Ubuntu
Creates a root CA with openssl

**Supported Platforms:** linux
#### Attack Commands: Run with `sh`
```sh
mv #{cert_filename} /usr/local/share/ca-certificates
echo sudo update-ca-certificates
```

Invoke-AtomicTest T1553.004 -TestNumbers 2

### Atomic Test #3 - Install root CA on macOS
Creates a root CA with openssl

**Supported Platforms:** macos
#### Attack Commands: Run with `command_prompt`
```command_prompt
sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "#{cert_filename}"
```

Invoke-AtomicTest T1553.004 -TestNumbers 3

### Atomic Test #4 - Install root CA on Windows
Creates a root CA with Powershell

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
$cert = Import-Certificate -FilePath #{pfx_path} -CertStoreLocation Cert:\LocalMachine\My
Move-Item -Path $cert.PSPath -Destination "Cert:\LocalMachine\Root"
```

Invoke-AtomicTest T1553.004 -TestNumbers 4

## Detection
A system's root certificates are unlikely to change frequently. Monitor new certificates installed on a system that could be due to malicious activity. (Citation: SpectorOps Code Signing Dec 2017) Check pre-installed certificates on new systems to ensure unnecessary or suspicious certificates are not present. Microsoft provides a list of trustworthy root certificates online and through authroot.stl. (Citation: SpectorOps Code Signing Dec 2017) The Sysinternals Sigcheck utility can also be used (<code>sigcheck[64].exe -tuv</code>) to dump the contents of the certificate store and list valid certificates not rooted to the Microsoft Certificate Trust List. (Citation: Microsoft Sigcheck May 2017)

Installed root certificates are located in the Registry under <code>HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates\</code> and <code>[HKLM or HKCU]\Software[\Policies\]\Microsoft\SystemCertificates\Root\Certificates\</code>. There are a subset of root certificates that are consistent across Windows systems and can be used for comparison: (Citation: Tripwire AppUNBlocker)

* 18F7C1FCC3090203FD5BAA2F861A754976C8DD25
* 245C97DF7514E7CF2DF8BE72AE957B9E04741E85
* 3B1EFD3A66EA28B16697394703A72CA340A05BD5
* 7F88CD7223F3C813818C994614A89C99FA3B5247
* 8F43288AD272F3103B6FB1428485EA3014C0BCFE
* A43489159A520F0D93D032CCAF37E7FE20A8B419
* BE36A4562FB2EE05DBB3D32323ADF445084ED656
* CDD4EEAE6000AC7F40C3802C171E30148030C072