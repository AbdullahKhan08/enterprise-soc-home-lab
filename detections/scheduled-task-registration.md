# Detection: Scheduled Task Registration

## Detection Summary

This detection identifies Windows scheduled task registration events collected from the Task Scheduler Operational event channel.

Scheduled task creation can be legitimate administrative activity, but it is also commonly used for persistence, execution, or recurring automation. Alerts require analyst review before being classified as malicious.

## Detection ID

- **Wazuh Rule ID:** `100102`
- **Severity Level:** `9`
- **Telemetry Source:** `Microsoft-Windows-TaskScheduler/Operational`
- **Windows Event ID:** `106`
- **Built-in Wazuh Parent Rule:** `67014`

## Detection Logic

The custom rule builds on Wazuh’s built-in scheduled-task registration rule and raises a higher-priority alert for investigation.

```xml
<rule id="100102" level="9">
  <if_sid>67014</if_sid>
  <description>Custom Detection: Scheduled task registered on Windows endpoint.</description>
  <group>scheduled_task,persistence,</group>
  <mitre>
    <id>T1053.005</id>
  </mitre>
</rule>
```

## MITRE ATT&CK Mapping

- **Tactic:** Persistence
- **Technique:** `T1053.005` — Scheduled Task/Job: Scheduled Task

## Test Activity

The detection was validated in the authorized lab using:

```powershell
schtasks /Create /TN "SOC-Lab-Persistence-Test-2" /TR "cmd.exe /c echo PersistenceTest2" /SC ONCE /ST 23:57 /F
```

## Evidence Investigated

The resulting Wazuh alert contained:

- Endpoint hostname
- User context
- Task name
- Task Scheduler Operational channel
- Windows Event ID `106`
- Wazuh Rule ID `100102`
- Severity level `9`
- MITRE ATT&CK mapping to `T1053.005`

## Analyst Notes

A scheduled task registration event is not inherently malicious. Analysts should investigate:

- Task name and task path
- Command or executable configured to run
- Trigger type and schedule frequency
- User or account that created the task
- Whether the task runs with elevated privileges
- Whether the task launches PowerShell, scripts, temporary files, or unusual binaries
- Whether similar tasks were created on other endpoints
- Whether the activity is approved or expected

## Potential Tuning

Future tuning can increase severity when a scheduled task launches PowerShell, uses suspicious command-line parameters, runs from temporary directories, or is created by an unusual user account.
