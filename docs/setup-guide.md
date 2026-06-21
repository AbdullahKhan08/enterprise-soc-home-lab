# Setup Guide

## Lab Objective

Build a portfolio-grade SOC monitoring lab that collects Windows endpoint telemetry in Wazuh, investigates suspicious activity, maps detections to MITRE ATT&CK, and documents incident-response workflows.

## Phase 1 Architecture

- **Host:** MacBook Pro M1, macOS
- **SIEM/XDR:** Wazuh deployed with Docker Desktop on macOS
- **Endpoint:** Windows 11 Pro ARM virtual machine in UTM
- **Endpoint hostname:** `SOC-WIN11-01`
- **Endpoint telemetry:** Windows Event Logs, Sysmon, PowerShell logging, Wazuh Agent
- **Network mode:** UTM shared/NAT

## Current Progress

- [x] GitHub repository created
- [x] Project folder structure initialized
- [x] Windows 11 Pro ARM VM created in UTM
- [x] Internet connectivity verified inside the VM
- [x] UTM guest tools installed
- [x] Endpoint renamed to `SOC-WIN11-01`
- [ ] Windows Update completed
- [ ] Clean baseline copy created
- [ ] Wazuh deployed using Docker
- [ ] Wazuh Agent enrolled
- [ ] Sysmon installed
- [ ] First detection validated

## Security Notes

- This lab is isolated and used only for safe, authorized simulations.
- No real malware will be executed.
- Do not commit passwords, API keys, private IP details, machine IDs, or personal data.
