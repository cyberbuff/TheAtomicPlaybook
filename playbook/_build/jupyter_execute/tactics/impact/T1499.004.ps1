# T1499.004 - Application or System Exploitation
Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent DoS condition.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack. Externally monitor the availability of services that may be targeted by an Endpoint DoS.