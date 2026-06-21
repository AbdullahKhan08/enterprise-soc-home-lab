# Detection: Local Account Creation

## Detection Summary

This detection identifies local user account creation events on Windows endpoints using Windows Security Event ID `4720`.

Local account creation can be legitimate administrative activity, but it is also relevant to persistence, privilege abuse, and unauthorized access. Alerts require analyst validation before being classified as malicious.

## Detection ID

- **Wazuh Rule ID:** `100104`
- **Severity Level:** `10`
- **Telemetry Source:** Windows Security Event Log
- **Windows Event ID:** `4720`
- **Built-in Wazuh Parent Rule:** `60109`

## Detection Logic

The custom rule builds on Wazuh’s built-in user-account management rule and limits the detection to Event ID `4720`, which represents local user account creation.

```xml
<rule id="100104" level="10">
  <if_sid>60109</if_sid>
  <field name="win.system.eventID">^4720$</field>
  <description>Custom Detection: Local user account created on Windows endpoint.</description>
  <group>account_management,persistence,local_account,</group>
  <mitre>
    <id>T1098</id>
  </mitre>
</rule>
```

## MITRE ATT&CK Mapping

- **Tactic:** Persistence
- **Technique:** `T1098` — Account Manipulation

## Test Activity

The detection was validated using an authorized lab account:

```powershell
net user SOCLabTemp3 "<temporary-lab-password>" /add
```

## Evidence Investigated

The Wazuh alert contained:

- Endpoint hostname
- Creating account
- Created account name
- Windows Event ID `4720`
- Wazuh Rule ID `100104`
- Severity level `10`
- MITRE ATT&CK mapping to `T1098`

## Analyst Notes

A local account creation event is not inherently malicious. An analyst should investigate:

- Account name and naming pattern
- Creating user or process
- Whether the account was added to privileged local groups
- Whether the account has interactive or remote logon capability
- Whether the account was created outside approved onboarding workflows
- Whether similar account-creation activity occurred on other endpoints
- Whether the account was used shortly after creation

## Potential Tuning

Future tuning can increase severity for accounts created by unusual users, accounts added to privileged groups, accounts created outside business hours, or accounts with suspicious naming patterns.
