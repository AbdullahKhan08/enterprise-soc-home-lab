# Detection: cmd.exe Launching PowerShell

## Detection Summary

This detection identifies PowerShell process creation where the parent process is `cmd.exe`.

The process chain `cmd.exe → powershell.exe` is not automatically malicious, but it is useful for SOC triage because command shells are often used to launch PowerShell-based activity.

## Detection ID

- **Wazuh Rule ID:** `100105`
- **Severity Level:** `8`
- **Telemetry Source:** `Microsoft-Windows-Sysmon/Operational`
- **Sysmon Event ID:** `1`
- **Parent Detection Rule:** `100100`

## Detection Logic

The rule builds on the PowerShell process-creation detection and checks whether PowerShell was launched by `cmd.exe`.

```xml
<rule id="100105" level="8">
  <if_sid>100100</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\cmd\.exe$</field>
  <description>Custom Detection: PowerShell launched by cmd.exe.</description>
  <group>sysmon,powershell,process_chain,command_shell,</group>
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
cmd.exe /c powershell.exe -NoProfile -Command "Get-Date"
```

## Evidence Investigated

The Wazuh alert contained:

- Endpoint hostname
- PowerShell command line
- Parent process image: `cmd.exe`
- Parent command line
- PowerShell executable path
- Wazuh Rule ID `100105`
- Severity level `8`
- MITRE ATT&CK mapping to `T1059.001`

## Analyst Notes

A `cmd.exe → powershell.exe` process chain can be legitimate administrative activity. Analysts should investigate:

- Full PowerShell command line
- Parent command line and initiating process
- User context
- Script block contents
- Whether bypass, encoded, hidden, or download-related parameters were used
- Process ancestry beyond `cmd.exe`
- Related network connections, file writes, persistence activity, or credential access behavior

## Potential Tuning

Future tuning can increase severity when this process chain includes suspicious PowerShell parameters, unusual parent processes, temporary-file execution, encoded commands, or unexpected user accounts.
