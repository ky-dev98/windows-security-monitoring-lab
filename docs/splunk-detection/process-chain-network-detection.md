# Process Chain and Network Activity Detection Using Sysmon and Splunk

## Overview

This project demonstrates a detection engineering workflow using Windows Sysmon logs and Splunk.

The objective is to detect a suspicious process execution chain followed by outbound network connections.

The detection scenario focuses on the following behavior:

```text
wscript.exe
    └── cmd.exe
          └── powershell.exe
                ├── TCP connection 1
                ├── TCP connection 2
                └── TCP connection 3
```

The project covers process lineage analysis, network event correlation, time-based detection conditions, and validation through positive and negative testing.

The detection logic was initially implemented using Splunk `join` commands and later improved using `stats` and `eventstats`.

## Objectives

The main objectives of this project are:

- Understand how Sysmon records process creation and network connection events.
- Identify parent-child process relationships using process GUIDs.
- Correlate process creation events with outbound network connections.
- Implement time-based detection conditions.
- Validate detection logic using positive and negative tests.
- Improve SPL correlation logic by reducing reliance on `join`.

## Environment

| Component | Technology |
|---|---|
| Endpoint | Windows |
| Endpoint telemetry | Sysmon |
| SIEM | Splunk |
| Log index | `sysmon` |
| Process telemetry | Sysmon Event ID 1 |
| Network telemetry | Sysmon Event ID 3 |
| Test scripts | VBScript and PowerShell |

## Detection Scenario

The test scenario simulates a process execution chain in which a VBScript launches a command shell, which subsequently executes PowerShell.

The PowerShell process establishes multiple outbound TCP connections.

The objective is to identify the complete process chain and correlate the network activity with the originating PowerShell process.

### Process Execution

```text
wscript.exe
    |
    | launches
    v
cmd.exe
    |
    | launches
    v
powershell.exe
    |
    | establishes outbound TCP connections
    v
External IP addresses
```

### Sysmon Events

**Event ID 1 — Process Creation**

Used to identify process execution and reconstruct parent-child relationships.

Relevant fields:

- `Computer`
- `Image`
- `CommandLine`
- `ProcessGuid`
- `ParentProcessGuid`
- `_time`

**Event ID 3 — Network Connection**

Used to identify network connections associated with the PowerShell process.

Relevant fields:

- `Computer`
- `Image`
- `ProcessGuid`
- `DestinationIp`
- `DestinationPort`
- `Protocol`
- `_time`

## Detection Logic

The detection consists of four main stages.

### 1. Process Lineage Correlation

Identify the following process chain:

```text
wscript.exe → cmd.exe → powershell.exe
```

Process relationships are validated by comparing:

```text
Parent ProcessGuid = Child ParentProcessGuid
```

The correlation is performed on the same endpoint using the `Computer` field.

### 2. Network Event Correlation

Sysmon Event ID 1 and Event ID 3 are correlated using the PowerShell process GUID.

```text
Event ID 1: PowerShell ProcessGuid
                  |
                  | Match
                  v
Event ID 3: Network ProcessGuid
```

This ensures that the network connection belongs to the identified PowerShell process.

### 3. Time-Based Detection

Only TCP connections occurring within 60 seconds after PowerShell process creation are considered.

```text
0 <= Network Event Time - PowerShell Start Time <= 60 seconds
```

### 4. Destination Filtering

The detection excludes selected non-public IPv4 address ranges:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16
```

This is a basic filtering approach and is not a complete public-IP classification mechanism.

## Splunk Detection Query

The following SPL correlates the process chain with outbound TCP connections without using `join`.

```spl
index=sysmon (EventCode=1 OR EventCode=3)
(Image="*\\wscript.exe" OR Image="*\\cmd.exe" OR Image="*\\powershell.exe")

| eval process_guid=lower(ProcessGuid)
| eval parent_guid=lower(ParentProcessGuid)
| eval process_name=lower(mvindex(split(Image, "\\"), -1))

| eval cmd_guid=case(
    EventCode=1 AND process_name="cmd.exe", process_guid,
    EventCode=1 AND process_name="powershell.exe", parent_guid
)

| eventstats
    values(eval(if(EventCode=1 AND process_name="cmd.exe", process_guid, null()))) as cmd_process_guid
    values(eval(if(EventCode=1 AND process_name="cmd.exe", parent_guid, null()))) as wscript_guid
    min(eval(if(EventCode=1 AND process_name="cmd.exe", _time, null()))) as cmd_time
    by Computer cmd_guid

| eval wscript_key=case(
    EventCode=1 AND process_name="wscript.exe", process_guid,
    EventCode=1 AND process_name="cmd.exe", parent_guid,
    EventCode=1 AND process_name="powershell.exe", wscript_guid
)

| eventstats
    values(eval(if(EventCode=1 AND process_name="wscript.exe", process_guid, null()))) as wscript_process_guid
    min(eval(if(EventCode=1 AND process_name="wscript.exe", _time, null()))) as wscript_time
    by Computer wscript_key

| eventstats
    values(eval(if(EventCode=1 AND process_name="powershell.exe"
        AND isnotnull(cmd_process_guid)
        AND isnotnull(wscript_process_guid),
        process_guid, null()))) as valid_ps_guid
    min(eval(if(EventCode=1 AND process_name="powershell.exe"
        AND isnotnull(cmd_process_guid)
        AND isnotnull(wscript_process_guid),
        _time, null()))) as ps_time
    values(eval(if(EventCode=1 AND process_name="powershell.exe"
        AND isnotnull(cmd_process_guid)
        AND isnotnull(wscript_process_guid),
        CommandLine, null()))) as ps_command
    by Computer process_guid

| where isnotnull(valid_ps_guid)

| eval time_diff=_time-ps_time

| where EventCode=3
    AND time_diff>=0
    AND time_diff<=60
    AND lower(Protocol)="tcp"
    AND isnotnull(DestinationIp)

| where NOT cidrmatch("10.0.0.0/8", DestinationIp)
    AND NOT cidrmatch("172.16.0.0/12", DestinationIp)
    AND NOT cidrmatch("192.168.0.0/16", DestinationIp)
    AND NOT cidrmatch("127.0.0.0/8", DestinationIp)
    AND NOT cidrmatch("169.254.0.0/16", DestinationIp)

| eval destination=DestinationIp.":".DestinationPort

| stats
    count as connection_count
    dc(DestinationIp) as unique_destination_count
    values(destination) as destinations
    min(time_diff) as first_connection_delay
    max(time_diff) as last_connection_delay
    values(ps_command) as ps_command
    by Computer process_guid

| rename process_guid as ps_guid

| table Computer ps_guid connection_count unique_destination_count
        destinations first_connection_delay last_connection_delay ps_command

| sort - connection_count
```

## Validation

The detection was tested using controlled process execution and network connection scenarios.

### Test 1 — Positive Detection

**Objective:** Confirm that the expected process chain and outbound network connections are detected.

**Test behavior:**

```text
wscript.exe
    └── cmd.exe
          └── powershell.exe
                ├── example.com:443
                ├── 1.1.1.1:443
                └── 8.8.8.8:443
```

**Expected result:**

- Detect the complete process chain.
- Correlate the network connections with PowerShell.
- Count three outbound TCP connections.

**Result: PASS**

The detection successfully identified the process chain and three network connections.

### Test 2 — Negative Detection

**Objective:** Verify that a PowerShell network connection without the expected process chain does not trigger the detection.

**Test behavior:**

PowerShell was executed directly and established an outbound TCP connection.

**Expected result:**

- Sysmon Event ID 3 is recorded.
- The process-chain detection does not trigger.

**Result: PASS**

The network event was recorded, but the process-chain detection did not match.

### Test 3 — Time Boundary Validation

**Objective:** Verify the 60-second detection window.

**Test behavior:**

A delay of 70 seconds was introduced before the PowerShell network connection.

**Expected result:**

- Sysmon Event ID 3 is recorded.
- The connection is excluded by the 60-second condition.
- Removing the time condition allows the activity to be detected.

**Result: PASS**

The detection behaved as expected.

### Test 4 — Multiple Network Connections

**Objective:** Confirm that multiple connections from the same PowerShell process are counted correctly.

**Expected result:**

```text
connection_count = 3
unique_destination_count = 3
```

**Observed result:**

| Field | Value |
|---|---|
| connection_count | 3 |
| unique_destination_count | 3 |
| destinations | 1.1.1.1:443, 104.20.23.154:443, 8.8.8.8:443 |
| first_connection_delay | 4.757 seconds |
| last_connection_delay | 6.760 seconds |

**Result: PASS**

All three network connections were correlated with the PowerShell process.

## Detection Improvements

### Initial Approach: `join`

The initial detection used multiple Splunk `join` commands to correlate process creation and network events.

This approach was useful for understanding the relationships between Sysmon events.

However, `join` can introduce performance limitations, particularly when processing large event volumes.

### Improved Approach: `stats` and `eventstats`

The detection was subsequently redesigned using `stats` and `eventstats`.

The improved approach:

- Avoids multiple `join` operations.
- Uses process GUIDs as correlation keys.
- Supports multiple network connections from the same process.
- Applies the 60-second condition to individual network events before aggregation.
- Preserves destination IP and port combinations.

This implementation was validated in the lab environment. Search performance at production scale has not been benchmarked.

## Limitations

The current implementation has several limitations.

**1. Specific process chain**

The detection only targets:

```text
wscript.exe → cmd.exe → powershell.exe
```

Other suspicious process chains are outside the current detection scope.

**2. False positives**

Legitimate administrative scripts may produce similar process behavior.

Additional contextual analysis and exclusion conditions would be required in a production environment.

**3. Search time range**

The required process creation events and network connection events must be included in the search window.

Missing process creation events can prevent successful correlation.

**4. IP filtering**

The current implementation excludes selected IPv4 ranges but does not fully classify public, private, reserved, or IPv6 addresses.

**5. Performance**

The use of multiple `eventstats` commands may affect performance when processing large datasets.

Production-scale performance testing has not been performed.

**6. Validation scope**

The detection was validated using controlled test scripts rather than real-world malicious activity.

## Key Learnings

This project provided practical experience in:

- Windows endpoint telemetry analysis
- Sysmon Event ID 1 and Event ID 3
- Process lineage reconstruction
- Process GUID-based event correlation
- Time-based detection engineering
- SPL development and optimization
- Positive and negative detection testing
- Detection limitations and operational considerations

## Future Work

The next step is to develop a lightweight Windows endpoint detection agent using Python.

Planned capabilities include:

- Collecting Sysmon events programmatically
- Maintaining process lineage information
- Implementing rule-based detection
- Correlating process and network events
- Managing detection exclusions
- Generating structured alerts

The goal is to better understand endpoint detection architecture by implementing detection logic outside Splunk.
