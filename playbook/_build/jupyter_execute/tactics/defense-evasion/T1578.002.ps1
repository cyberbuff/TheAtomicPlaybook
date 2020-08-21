# T1578.002 - Create Cloud Instance
An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses. Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances currently residing within an account. An adversary may [Create Snapshot](https://attack.mitre.org/techniques/T1578/001) of one or more volumes in an account, create a new instance, mount the snapshots, and then apply a less restrictive security policy to collect [Data from Local System](https://attack.mitre.org/techniques/T1005) or for [Remote Data Staging](https://attack.mitre.org/techniques/T1074/002).(Citation: Mandiant M-Trends 2020)

Creating a new instance may also allow an adversary to carry out malicious activity within an environment without affecting the execution of current running instances.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
The creation of a new instance or VM is a common part of operations within many cloud environments. Events should then not be viewed in isolation, but as part of a chain of behavior that could lead to other activities. For example, the creation of an instance by a new user account or the unexpected creation of one or more snapshots followed by the creation of an instance may indicate suspicious activity.

In AWS, CloudTrail logs capture the creation of an instance in the <code>RunInstances</code> event, and in Azure the creation of a VM may be captured in Azure activity logs.(Citation: AWS CloudTrail Search)(Citation: Azure Activity Logs) Google's Admin Activity audit logs within their Cloud Audit logs can be used to detect the usage of <code>gcloud compute instances create</code> to create a VM.(Citation: Cloud Audit Logs)