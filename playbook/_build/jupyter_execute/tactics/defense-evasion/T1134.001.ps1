# T1134.001 - Token Impersonation/Theft
Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using <code>DuplicateToken(Ex)</code>. The token can then be used with <code>ImpersonateLoggedOnUser</code> to allow the calling thread to impersonate a logged on user's security context, or with <code>SetThreadToken</code> to assign the impersonated token to a thread.

An adversary may do this when they have a specific, existing process they want to assign the new token to. For example, this may be useful for when the target user has a non-network logon session on the system.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
If an adversary is using a standard command-line shell, analysts can detect token manipulation by auditing command-line activity. Specifically, analysts should look for use of the <code>runas</code> command. Detailed command-line logging is not enabled by default in Windows.(Citation: Microsoft Command-line Logging)

Analysts can also monitor for use of Windows APIs such as <code>DuplicateToken(Ex)</code>, <code> ImpersonateLoggedOnUser </code>, and <code> SetThreadToken </code> and correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.