# Detection: Suspicious PowerShell Parameters

## Detection Summary

This detection identifies PowerShell executions that use commonly abused parameters such as `-ExecutionPolicy Bypass`, `-EncodedCommand`, or `-WindowStyle Hidden`.

## Detection ID

- **Wazuh Rule ID:** `100101`
- **Severity Level:** `10`
- **Telemetry Source:** `Microsoft-Windows-Sysmon/Operational`
- **Sysmon Event ID:** `1`

## Detection Logic

The detection builds on Rule `100100`, which identifies PowerShell process creation. It then inspects the Sysmon command line for suspicious PowerShell parameters.

```xml
<rule id="100101" level="10">
  <if_sid>100100</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand|-executionpolicy\s+bypass|-windowstyle\s+hidden)</field>
  <description>Custom Detection: Suspicious PowerShell execution parameter detected.</description>
  <group>powershell,suspicious_command,execution,</group>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

## MITRE ATT&CK Mapping

- **Tactic:** Execution
- **Technique:** `T1059.001` — PowerShell

## Test Activity

The detection was validated using this safe lab command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Date"
```

## Evidence Investigated

The Wazuh alert showed:

- Endpoint hostname
- User context
- PowerShell executable path
- Full command line
- `-ExecutionPolicy Bypass` parameter
- Parent process details
- SHA-256 hash
- Wazuh Rule ID `100101`
- Severity level `10`
- MITRE ATT&CK mapping `T1059.001`

## Analyst Notes

`-ExecutionPolicy Bypass` does not automatically mean malicious activity, but it is a high-value investigation signal because attackers frequently use it to avoid script execution restrictions.

An analyst should review the command line, parent process, user identity, endpoint role, execution frequency, downloaded content, network connections, and whether the activity is approved.

## Potential Tuning

Future tuning can exclude approved automation scripts or trusted management tools while still alerting on unusual users, endpoints, parent processes, or combinations of suspicious PowerShell parameters.
