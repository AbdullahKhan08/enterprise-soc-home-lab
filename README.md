# Enterprise SOC Home Lab

### Windows Endpoint Detection, Threat Hunting, and Incident Triage

A portfolio-grade Security Operations Center (SOC) home lab built to practice Windows endpoint monitoring, detection engineering, alert triage, MITRE ATT&CK mapping, and incident documentation.

The lab uses a Windows 11 endpoint monitored by Wazuh, with Sysmon, PowerShell Script Block Logging, Windows Security auditing, Task Scheduler telemetry, and File Integrity Monitoring.

> All simulations in this repository were performed in an isolated, authorized lab environment. No real malware, credential theft, external scanning, or attacks against public systems were used.

---

## Project Goals

- Deploy and operate a Windows-focused SOC monitoring environment.
- Collect high-value endpoint telemetry.
- Build and validate custom Wazuh detection rules.
- Investigate alerts using process, user, command-line, file, and event-log evidence.
- Map detections to MITRE ATT&CK.
- Document analyst workflows through incident reports.
- Maintain a clean, recruiter-ready GitHub portfolio project.

---

## Architecture

```text
MacBook Pro M1 (macOS)
│
├── Docker Desktop
│   └── Wazuh SIEM / XDR
│       ├── Wazuh Manager
│       ├── Wazuh Indexer
│       └── Wazuh Dashboard
│
└── UTM Virtual Machine
    └── Windows 11 Pro ARM — SOC-WIN11-01
        ├── Wazuh Agent
        ├── Sysmon
        ├── PowerShell Script Block Logging
        ├── Windows Security Event Logging
        ├── Task Scheduler Operational Logging
        └── Wazuh File Integrity Monitoring
```

### Telemetry Flow

1. Windows events and endpoint activity are generated on `SOC-WIN11-01`.
2. Sysmon, Windows Security logs, PowerShell logs, Task Scheduler logs, and FIM generate telemetry.
3. The Wazuh agent forwards selected event channels and integrity events to Wazuh.
4. Wazuh parses, indexes, correlates, and displays alerts.
5. Alerts are investigated using event details, command lines, parent-child process chains, user context, and MITRE ATT&CK mapping.

---

## Lab Components

| Component                       | Purpose                                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------------- |
| Wazuh                           | SIEM/XDR platform for event collection, alerting, investigation, and threat hunting     |
| Docker Desktop                  | Runs the Wazuh single-node deployment on macOS                                          |
| Windows 11 Pro ARM              | Monitored endpoint hosted in UTM                                                        |
| Wazuh Agent                     | Forwards Windows telemetry to the Wazuh Manager                                         |
| Sysmon                          | Provides process creation, parent-child process, command-line, hash, and file telemetry |
| PowerShell Script Block Logging | Captures PowerShell script content through Event ID `4104`                              |
| Windows Security Logs           | Captures account-management and authentication events                                   |
| Task Scheduler Operational Log  | Captures scheduled task registration events                                             |
| Wazuh FIM                       | Monitors selected files and persistence-relevant Windows paths                          |

---

## Detection Coverage

| Rule ID  | Detection                            | Source                     | Key Event / Logic                                                                    | MITRE ATT&CK                                   |
| -------- | ------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------- |
| `100100` | PowerShell process creation          | Sysmon                     | Sysmon Event ID `1` where image ends in `powershell.exe`                             | `T1059.001` PowerShell                         |
| `100101` | Suspicious PowerShell parameters     | Sysmon                     | Detects `-ExecutionPolicy Bypass`, `-EncodedCommand`, or hidden execution parameters | `T1059.001` PowerShell                         |
| `100102` | Scheduled task registration          | Task Scheduler Operational | Builds on Wazuh Rule `67014` for scheduled task registration                         | `T1053.005` Scheduled Task/Job                 |
| `100103` | File added to Windows Startup folder | Wazuh FIM                  | Detects file creation in the Windows Startup folder                                  | `T1547.001` Registry Run Keys / Startup Folder |
| `100104` | Local account creation               | Windows Security Log       | Event ID `4720`                                                                      | `T1098` Account Manipulation                   |
| `100105` | `cmd.exe` launching PowerShell       | Sysmon                     | Detects `cmd.exe → powershell.exe` parent-child process chain                        | `T1059.001` PowerShell                         |

### Built-In Wazuh Coverage Validated

| Scenario             | Event / Rule                                 | Notes                                                              |
| -------------------- | -------------------------------------------- | ------------------------------------------------------------------ |
| Failed network logon | Windows Event ID `4625` / Wazuh Rule `60122` | Validated using a safe local SMB authentication failure simulation |

---

## Incident Reports

| Incident ID | Scenario                                                        | Outcome                           |
| ----------- | --------------------------------------------------------------- | --------------------------------- |
| IR-001      | Suspicious PowerShell execution using `-ExecutionPolicy Bypass` | Closed — Authorized Test Activity |
| IR-002      | Scheduled task registration                                     | Closed — Authorized Test Activity |
| IR-003      | Windows Startup folder file creation                            | Closed — Authorized Test Activity |
| IR-004      | Local account creation                                          | Closed — Authorized Test Activity |
| IR-005      | PowerShell launched by `cmd.exe`                                | Closed — Authorized Test Activity |

Each report includes alert evidence, investigation steps, root cause, impact assessment, response actions, lessons learned, and cleanup verification.

---

## Safe Simulations Performed

### PowerShell Process Creation

```powershell
powershell.exe -NoProfile -Command "Get-Date"
```

### Suspicious PowerShell Parameter Detection

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Date"
```

### Scheduled Task Registration

```powershell
schtasks /Create /TN "SOC-Lab-Persistence-Test-2" /TR "cmd.exe /c echo PersistenceTest2" /SC ONCE /ST 23:57 /F
```

### Windows Startup Folder File Creation

```powershell
Set-Content -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SOC-Lab-Startup-Test-3.txt" -Value "Authorized startup-folder FIM validation"
```

### Local Account Creation

```powershell
net user SOCLabTemp3 "<temporary-lab-password>" /add
```

### Suspicious Process Chain

```powershell
cmd.exe /c powershell.exe -NoProfile -Command "Get-Date"
```

### Failed Network Logon

```powershell
net use \\localhost\IPC$ /user:.\SOCLabFailTest <incorrect-test-password>
```

All temporary users, scheduled tasks, startup-folder files, and SMB connections were removed after validation.

---

## Evidence

Evidence screenshots are stored in the [`screenshots`](./screenshots) directory.

Examples of evidence captured include:

- Wazuh agent enrollment and endpoint status
- Sysmon Event ID `1` process creation telemetry
- PowerShell command-line evidence
- MITRE ATT&CK mappings
- Scheduled task registration alerts
- File Integrity Monitoring alerts
- Local account creation alerts
- Parent-child process-chain evidence

---

## Repository Structure

```text
enterprise-soc-home-lab/
│
├── architecture/
│   └── lab-architecture.md
│
├── detections/
│   ├── powershell-process-creation.md
│   ├── suspicious-powershell-parameters.md
│   ├── scheduled-task-registration.md
│   ├── windows-startup-folder-fim.md
│   ├── local-account-creation.md
│   └── cmd-to-powershell-process-chain.md
│
├── docs/
│   ├── setup-guide.md
│   ├── threat-model.md
│   └── lessons-learned.md
│
├── incident-reports/
│   ├── IR-001-suspicious-powershell-execution.md
│   ├── IR-002-scheduled-task-registration.md
│   ├── IR-003-startup-folder-file-creation.md
│   ├── IR-004-local-account-creation.md
│   └── IR-005-cmd-to-powershell-process-chain.md
│
├── screenshots/
├── scripts/
│   └── sysmonconfig.xml
│
└── README.md
```

---

## Skills Demonstrated

- Wazuh SIEM/XDR deployment and administration
- Windows endpoint onboarding and telemetry collection
- Sysmon configuration and process telemetry analysis
- PowerShell Script Block Logging analysis
- Windows Security Event Log analysis
- Wazuh custom rule development
- Rule chaining using `if_sid`
- Detection engineering and tuning considerations
- MITRE ATT&CK mapping
- Threat hunting and alert triage
- Parent-child process-chain analysis
- File Integrity Monitoring
- Persistence monitoring
- Incident response documentation
- Git and GitHub project documentation

---

## Current Status

- [x] Wazuh Docker deployment completed
- [x] Windows 11 endpoint enrolled and active
- [x] Sysmon deployed and collected by Wazuh
- [x] PowerShell Script Block Logging collected by Wazuh
- [x] Task Scheduler Operational events collected by Wazuh
- [x] Startup folder File Integrity Monitoring configured
- [x] Windows Security account-management telemetry validated
- [x] Six custom Wazuh detections created and tested
- [x] Five incident reports completed
- [x] Evidence screenshots added to the repository
- [x] Safe test artifacts cleaned up

---

## Future Enhancements

- Add local Administrators group membership detection.
- Add failed-logon thresholding and brute-force correlation.
- Add Windows Defender event collection and alert triage.
- Expand FIM coverage to additional persistence-relevant paths.
- Add a Linux endpoint for cross-platform monitoring.
- Add Active Directory and multiple Windows endpoints.
- Add Sigma-rule mapping for selected detections.
- Add alert dashboards and detection metrics.
- Build a SOC analyst playbook for each detection category.

---

## Safety Notes

This project is designed only for authorized defensive security learning.

No real malware, credential theft, phishing, external scanning, exploitation of public systems, or unauthorized access was performed.
