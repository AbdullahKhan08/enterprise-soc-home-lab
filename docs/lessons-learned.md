# Lessons Learned

## Detection Engineering

- Endpoint telemetry must be validated before creating custom detections. Sysmon Event ID 1, PowerShell Script Block Logging Event ID 4104, and Task Scheduler Event ID 106 were confirmed locally before relying on Wazuh alerts.
- Custom Wazuh rules can build on built-in rules. Scheduled task Rule `100102` successfully chained from built-in Rule `67014`.
- Detection logic should match the telemetry source that contains the required evidence. Suspicious PowerShell parameters were detected from the Sysmon command line rather than Script Block Logging because launcher parameters may not appear in Event ID 4104.

## Alert Triage

- A high-severity alert does not automatically indicate malicious activity.
- PowerShell execution, execution-policy bypass, and scheduled task registration require analyst context before classification.
- Useful triage fields include command line, parent process, user context, task name, endpoint identity, event ID, and MITRE ATT&CK mapping.

## Operational Practices

- Authorized simulations should be documented, reversible, and cleaned up after testing.
- Incident reports should record detection logic, evidence, investigation steps, impact assessment, and cleanup verification.
- Screenshots should show meaningful evidence rather than only dashboard summaries.
- Built-in SIEM detections can provide useful coverage without a custom rule; failed network logon Event ID `4625` was validated through Wazuh Rule `60122`.
- Custom rules should only be retained when they add clear value beyond built-in coverage. An attempted duplicate failed-logon custom rule was removed after it did not improve detection quality.
