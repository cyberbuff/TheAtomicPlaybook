# T1555 - Credentials from Password Stores
Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Monitor system calls, file read events, and processes for suspicious activity that could indicate searching for a password  or other activity related to performing keyword searches (e.g. password, pwd, login, store, secure, credentials, etc.) in process memory for credentials. File read events should be monitored surrounding known password storage applications.