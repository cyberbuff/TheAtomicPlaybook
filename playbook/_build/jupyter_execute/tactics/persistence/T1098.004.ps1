# T1098.004 - SSH Authorized Keys
Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions and macOS commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under <code>&lt;user-home&gt;/.ssh/authorized_keys</code>.(Citation: SSH Authorized Keys) Users may edit the system’s SSH config file to modify the directives PubkeyAuthentication and RSAAuthentication to the value “yes” to ensure public key and RSA authentication are enabled. The SSH config file is usually located under <code>/etc/ssh/sshd_config</code>.

Adversaries may modify SSH <code>authorized_keys</code> files directly with scripts or shell commands to add their own adversary-supplied public keys. This ensures that an adversary possessing the corresponding private key may log in as an existing user via SSH.(Citation: Venafi SSH Key Abuse) (Citation: Cybereason Linux Exim Worm)

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Use file integrity monitoring to detect changes made to the <code>authorized_keys</code> file for each user on a system. Monitor for suspicious processes modifying the <code>authorized_keys</code> file.

Monitor for changes to and suspicious processes modifiying <code>/etc/ssh/sshd_config</code>.