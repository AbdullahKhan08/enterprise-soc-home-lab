# Lab Architecture

## Phase 1: Single-Endpoint SOC Lab

```text
MacBook Pro M1 (macOS)
│
├── Docker Desktop
│   └── Wazuh SIEM/XDR
│       ├── Wazuh Manager
│       ├── Wazuh Indexer
│       └── Wazuh Dashboard
│
└── UTM Virtual Machine
    └── SOC-WIN11-01
        ├── Windows Security Event Logs
        ├── Sysmon
        ├── PowerShell Logging
        └── Wazuh Agent
```
