# Detection: Windows Startup Folder File Creation

## Detection Summary

This detection identifies files added to the Windows Startup folder using Wazuh File Integrity Monitoring (FIM).

Files placed in the Startup folder may execute when a user logs on. This can be legitimate, but it is also a common persistence technique and should be investigated.

## Detection ID

- **Wazuh Rule ID:** `100103`
- **Severity Level:** `9`
- **Telemetry Source:** Wazuh File Integrity Monitoring
- **Built-in Wazuh Parent Rule:** `554`
- **Monitored Path:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`

## Detection Logic

The rule builds on Wazuh’s built-in file-added rule and checks whether the file path is inside the Windows Startup folder.

```xml
<rule id="100103" level="9">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">(?i)^c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\</field>
  <description>Custom Detection: File added to Windows Startup folder.</description>
  <group>fim,persistence,startup_folder,</group>
  <mitre>
    <id>T1547.001</id>
  </mitre>
</rule>
```

## MITRE ATT&CK Mapping

- **Tactics:** Persistence, Privilege Escalation
- **Technique:** `T1547.001` — Registry Run Keys / Startup Folder

## Test Activity

The detection was validated using an authorized lab file:

```powershell
Set-Content -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SOC-Lab-Startup-Test-3.txt" -Value "Authorized startup-folder FIM validation"
```

## Evidence Investigated

The Wazuh alert contained:

- Endpoint hostname
- Monitored file path
- File-added event context
- Wazuh Rule ID `100103`
- Severity level `9`
- MITRE ATT&CK tactics and technique mapping

## Analyst Notes

A file added to the Startup folder is not automatically malicious. An analyst should investigate the file type, contents, creating user or process, file hash, timestamp, endpoint role, and whether the file is expected or approved.

## Potential Tuning

Future tuning can increase severity for executable files, scripts, shortcut files, unsigned binaries, files created by unusual users, or Startup-folder files associated with suspicious process chains.
