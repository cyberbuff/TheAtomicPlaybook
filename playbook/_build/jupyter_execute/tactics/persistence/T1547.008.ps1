# T1547.008 - LSASS Driver
Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process. (Citation: Microsoft Security Subsystem)

Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)), an adversary can use LSA operations to continuously execute malicious payloads.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
With LSA Protection enabled, monitor the event logs (Events 3033 and 3063) for failed attempts to load LSA plug-ins and drivers. (Citation: Microsoft LSA Protection Mar 2014) Also monitor DLL load operations in lsass.exe. (Citation: Microsoft DLL Security)

Utilize the Sysinternals Autoruns/Autorunsc utility (Citation: TechNet Autoruns) to examine loaded drivers associated with the LSA. 