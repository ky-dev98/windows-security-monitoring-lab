# Windows Security Monitoring Lab

## Overview

This repository documents a hands-on Windows security monitoring and detection engineering lab using Sysmon, Splunk, and mitmproxy.

The project focuses on collecting endpoint and network telemetry, analyzing security events, developing detection logic, and validating detection rules through controlled testing.

The primary objective is to gain practical experience in security monitoring, log analysis, event correlation, and detection engineering.

This repository serves as a technical record of the lab environment, implementation decisions, troubleshooting, detection development, and lessons learned.

## Project Objectives

The main objectives of this project are:

- Build a Windows security monitoring environment.
- Collect process, network, DNS, and other security-related events.
- Forward and analyze endpoint telemetry using Splunk.
- Monitor HTTP/HTTPS activity using mitmproxy.
- Develop behavioral detection rules using Splunk SPL.
- Correlate process execution and network activity.
- Validate detection logic through controlled testing.
- Document implementation challenges, limitations, and improvements.

## Architecture

The monitoring environment consists of a Windows endpoint and a Splunk instance running on an Ubuntu virtual machine.

```text
                 Windows Endpoint
                        |
          +-------------+-------------+
          |                           |
          v                           v
        Sysmon                    mitmproxy
          |                           |
          |                    HTTP/HTTPS Logs
          |                           |
          v                           v
   Windows Event Log             JSONL Files
          |                           |
          +-------------+-------------+
                        |
                        v
              Splunk Universal
                  Forwarder
                        |
                        v
                 Splunk Enterprise
                        |
          +-------------+-------------+
          |                           |
          v                           v
      Log Analysis              Detection Rules
          |                           |
          +-------------+-------------+
                        |
                        v
                Security Monitoring
```

## Technologies

| Component | Technology |
|---|---|
| Endpoint OS | Windows 11 |
| Endpoint telemetry | Microsoft Sysmon |
| Network traffic inspection | mitmproxy |
| Log processing | Python |
| SIEM | Splunk Enterprise |
| Log forwarding | Splunk Universal Forwarder |
| SIEM host OS | Ubuntu 24.04 |
| Detection language | Splunk SPL |

## Implementation

### 1. Sysmon Monitoring

Configured Sysmon to collect Windows endpoint telemetry.

The monitoring configuration includes the following event types:

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 3 | Network Connection |
| 22 | DNS Query |
| 26 | File Delete Detected |

These events provide visibility into process execution, network activity, DNS queries, and selected file operations.

The collected events are forwarded to Splunk for analysis.

### 2. HTTP/HTTPS Monitoring

Implemented HTTP/HTTPS traffic monitoring using mitmproxy.

Custom Python scripts are used to process captured traffic and export structured JSONL logs.

The implementation includes:

- HTTP/HTTPS request and response monitoring.
- Structured log generation.
- JSONL output for downstream analysis.
- Flow cleanup to reduce memory consumption.

The objective is to improve visibility into application-layer network activity and understand the challenges of collecting and processing HTTP/HTTPS telemetry.

### 3. Splunk Log Collection and Analysis

Configured Splunk to collect and analyze security telemetry from the Windows endpoint.

The environment supports:

- Sysmon event collection.
- HTTP/HTTPS log ingestion.
- Process execution analysis.
- Network connection analysis.
- DNS activity investigation.
- Event correlation using SPL.

### 4. Detection Engineering

Developed behavioral detection logic using Sysmon events and Splunk SPL.

The initial detection scenario focuses on identifying a suspicious process execution chain followed by outbound network activity.

```text
wscript.exe
    |
    v
cmd.exe
    |
    v
powershell.exe
    |
    v
Outbound TCP Connections
```

The detection uses:

- Sysmon Event ID 1 for process creation.
- Sysmon Event ID 3 for network connections.
- `ProcessGuid` and `ParentProcessGuid` for process lineage correlation.
- Time-based conditions for identifying related network activity.
- SPL aggregation to analyze multiple network connections.

The detection logic was initially implemented using `join` and subsequently improved using `stats` and `eventstats`.

### 5. Detection Validation

Detection logic was validated through controlled testing.

The tests included:

**Positive Detection**

Verified that the expected process chain and outbound network connections were detected.

**Negative Detection**

Verified that a direct PowerShell network connection without the expected process chain did not trigger the detection.

**Time Boundary Validation**

Verified that network activity occurring outside the configured 60-second detection window was excluded.

**Multiple Connection Correlation**

Verified that multiple network connections originating from the same PowerShell process were correctly correlated and counted.

These tests helped evaluate detection accuracy and identify limitations in event correlation.

## Documentation

Detailed implementation notes and detection reports are maintained in the repository.

| Topic | Description |
|---|---|
| Sysmon Monitoring | Sysmon configuration, event collection, and troubleshooting |
| HTTP Monitoring | HTTP/HTTPS traffic collection using mitmproxy |
| Splunk Detection | Behavioral detection logic, SPL queries, and validation results |

- [Lab Documentation](/docs)

## Challenges and Lessons Learned

### Sysmon Disk Usage

During implementation, excessive disk usage was observed due to Sysmon file deletion archiving.

The configuration was reviewed and adjusted to reduce unnecessary storage consumption.

This highlighted the importance of understanding telemetry collection behavior and its operational impact.

### Event Correlation

Process and network events must be correlated using reliable identifiers.

Using `ProcessGuid` and `ParentProcessGuid` provides a more reliable method of reconstructing process relationships than relying only on process names or process IDs.

### Detection Query Design

Initial correlation logic used multiple Splunk `join` operations.

The detection was later redesigned using `stats` and `eventstats` to reduce reliance on `join` and support multiple network connections.

### Detection Limitations

Detection logic must account for:

- Missing or delayed events.
- Search time window limitations.
- Legitimate activity that resembles suspicious behavior.
- Event volume and query performance.
- Incomplete visibility from individual telemetry sources.

These considerations are important when moving from a controlled lab environment toward production security monitoring.

## Project Scope

This repository focuses on security monitoring and detection engineering using existing telemetry collection and analysis tools.

The primary areas are:

- Endpoint telemetry collection.
- Network traffic monitoring.
- SIEM integration.
- Log analysis.
- Detection rule development.
- Detection validation and improvement.

Development of a standalone endpoint security product, including a custom Windows agent, detection engine, and management interface, will be maintained as a separate software development project.

This separation allows the monitoring lab to remain focused on detection engineering while supporting future security product development.

## Future Improvements

Potential improvements to this lab include:

- Additional behavioral detection scenarios.
- Detection rule conversion to Sigma.
- Expanded Windows security event monitoring.
- Detection coverage evaluation.
- False-positive analysis and tuning.
- Further improvements to event correlation and search performance.

## Disclaimer

This repository is intended for educational and research purposes.

All testing is performed in a controlled lab environment.

The detection logic and configurations are proof-of-concept implementations and have not been validated for production deployment.

Environment-specific identifiers and sensitive configuration details should be removed or anonymized before publication.
