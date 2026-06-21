# Detection: PowerShell Process Creation

## Detection Summary

This detection identifies PowerShell process creation events from Windows endpoints using Sysmon Event ID 1 telemetry.

## Detection ID

- **Wazuh Rule ID:** `100100`
- **Severity Level:** `7`
- **Telemetry Source:** Microsoft-Windows-Sysmon/Operational
- **Sysmon Event ID:** `1`

## Detection Logic

The rule triggers when a Sysmon Process Create event contains an image path ending in `powershell.exe`.

```xml
<rule id="100100" level="7">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
  <description>Custom Detection: PowerShell process creation detected on Windows endpoint.</description>
  <group>sysmon,powershell,process_creation,</group>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

MITRE ATT&CK Mapping
Tactic: Execution
Technique: T1059.001 — PowerShell
Test Activity

The detection was validated using the following safe command:

powershell.exe -NoProfile -Command "Get-Date"
Evidence Investigated

The resulting Wazuh alert contained:

Endpoint hostname
User context
PowerShell image path
Full command line
Parent process details
Process GUID and Process ID
SHA-256 hash
MITRE ATT&CK technique mapping
Wazuh custom rule ID and severity
Analyst Notes

PowerShell execution is not inherently malicious. An analyst should investigate the command line, parent process, user context, frequency, destination activity, and whether the execution is expected for the endpoint or user.

Potential Tuning

Potential future tuning could exclude approved automation accounts, trusted management tools, or known administrative scripts while retaining visibility into unusual PowerShell execution.
