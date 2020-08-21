# T1134.002 - Create Process with Token
Adversaries may create a new process with a duplicated token to escalate privileges and bypass access controls. An adversary can duplicate a desired access token with <code>DuplicateToken(Ex)</code> and use it with <code>CreateProcessWithTokenW</code> to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
If an adversary is using a standard command-line shell, analysts can detect token manipulation by auditing command-line activity. Specifically, analysts should look for use of the <code>runas</code> command. Detailed command-line logging is not enabled by default in Windows.(Citation: Microsoft Command-line Logging)

If an adversary is using a payload that calls the Windows token APIs directly, analysts can detect token manipulation only through careful analysis of user network activity, examination of running processes, and correlation with other endpoint and network behavior.

Analysts can also monitor for use of Windows APIs such as <code>DuplicateToken(Ex)</code> and <code>CreateProcessWithTokenW</code> and correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.