Then create `docs/threat-model.md` and paste:

```md
# Threat Model

## Scope

This lab simulates common Windows endpoint threats in an isolated, authorized environment to practice SOC monitoring, alert triage, detection engineering, and incident response.

## Assets

- Windows endpoint identity and local accounts
- Endpoint logs and telemetry
- PowerShell execution activity
- Scheduled tasks and persistence mechanisms
- Security monitoring platform configuration
- Incident evidence and investigation reports

## Initial Threat Scenarios

| Scenario                    | Goal                                                    | Example Evidence                        |
| --------------------------- | ------------------------------------------------------- | --------------------------------------- |
| Failed logon activity       | Detect authentication abuse patterns                    | Windows Security Event ID 4625          |
| Suspicious PowerShell       | Detect potentially malicious command execution          | PowerShell logs, Sysmon Event ID 1      |
| Local account creation      | Detect potentially unauthorized local account creation  | Windows Security Event ID 4720          |
| Scheduled task registration | Detect potentially unauthorized scheduled task creation | Task Scheduler Operational Event ID 106 |
| Suspicious process chain    | Identify abnormal parent-child processes                | Sysmon Event ID 1                       |

## Safety Boundaries

- Only authorized testing inside this lab.
- No real malware, credential theft, external scanning, or attacks against public systems.
- All simulations must be documented and reversible.
```
