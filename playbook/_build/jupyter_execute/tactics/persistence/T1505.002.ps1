# T1505.002 - Server Software Component: Transport Agent
Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails.(Citation: Microsoft TransportAgent Jun 2016)(Citation: ESET LightNeuron May 2019) Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks. 

Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events.(Citation: ESET LightNeuron May 2019) Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria. For example, the transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary. 

## Atomic Tests

#Import the Module before running the tests.
Import-Module /Users/0x6c/AtomicRedTeam/atomics/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 - Force

### Atomic Test #1 - Install MS Exchange Transport Agent Persistence
Install a Microsoft Exchange Transport Agent for persistence. This requires execution from an Exchange Client Access Server and the creation of a DLL with specific exports. Seen in use by Turla.
More details- https://docs.microsoft.com/en-us/exchange/transport-agents-exchange-2013-help

**Supported Platforms:** windows
#### Attack Commands: Run with `powershell`
```powershell
Install-TransportAgent -Name #{transport_agent_identity} -TransportAgentFactory #{class_factory} -AssemblyPath #{dll_path}
Enable-TransportAgent #{transport_agent_identity}
Get-TransportAgent | Format-List Name,Enabled
```

Invoke-AtomicTest T1505.002 -TestNumbers 1

## Detection
Consider monitoring application logs for abnormal behavior that may indicate suspicious installation of application software components. Consider monitoring file locations associated with the installation of new application software components such as paths from which applications typically load such extensible components.