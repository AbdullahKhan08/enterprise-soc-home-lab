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
- [x] Windows Update completed
- [x] Clean baseline copy created
- [x] Wazuh deployed using Docker
- [x] Wazuh Dashboard access validated
- [x] Wazuh Agent installed on `SOC-WIN11-01`
- [x] Windows endpoint successfully enrolled and communicating with Wazuh
- [x] Agent network connectivity validated on TCP port 1514
- [ ] Sysmon installed
- [ ] Enhanced PowerShell logging configured
- [ ] First detection validated
- [ ] First incident report completed

## Evidence Captured

- Wazuh Dashboard is accessible through the Docker-based single-node deployment.
- The Windows endpoint `SOC-WIN11-01` is enrolled in Wazuh and visible in the Agents inventory.
- Connectivity between the endpoint and Wazuh Manager was validated using TCP port 1514.
- Screenshots will be stored in the `screenshots/` directory after sensitive local details are reviewed and cropped where necessary.

## Security Notes

- This lab is isolated and used only for safe, authorized simulations.
- No real malware will be executed.
- Do not commit passwords, API keys, private IP addresses, machine IDs, certificates, or personal data.
- Sensitive information visible in screenshots must be cropped or blurred before committing.
