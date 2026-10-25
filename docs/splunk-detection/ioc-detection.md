# IoC-Based Detection Using Sysmon and Splunk

## 1. Objective

The objective of this implementation is to detect network activity associated with predefined Indicators of Compromise (IoCs) using Sysmon logs and Splunk.

IP addresses and domains are maintained in a CSV lookup file and compared against Sysmon events.

The detection focuses on:

- **Sysmon Event ID 3 (Network Connection):** Detecting connections or connection attempts to IP addresses listed in the IoC file.
- **Sysmon Event ID 22 (DNS Query):** Detecting DNS queries for domains listed in the IoC file.

This implementation uses a manually prepared IoC list to validate the basic detection mechanism. Automated Threat Intelligence collection and lifecycle management are outside the current scope.

## 2. Detection Design

### 2.1 Architecture

The detection process consists of the following steps:

1. Collect network connection and DNS query events using Sysmon.
2. Forward Sysmon events to Splunk using the Universal Forwarder.
3. Compare event fields against a CSV lookup containing predefined IoCs.
4. Identify matching events.
5. Generate alerts when matching events are found.

### 2.2 IoC Lookup File

A CSV file is used to maintain IoC information.

Example: `ioc_list.csv`

```csv
ioc_type,ioc_value,source,first_seen,last_seen,last_updated,expires_at,status
ip,192.168.56.10,lab-test,2026-10-01T00:00:00Z,2026-10-20T00:00:00Z,2026-10-24T00:00:00Z,2026-11-20T00:00:00Z,active
domain,malicious.example,lab-test,2026-09-01T00:00:00Z,2026-09-20T00:00:00Z,2026-10-01T00:00:00Z,2026-11-15T00:00:00Z,active
domain,suspicious.example,lab-test,2026-09-01T00:00:00Z,2026-09-07T00:00:00Z,2026-09-25T00:00:00Z,2026-10-15T00:00:00Z,expired
```

The example IP address is reserved for documentation, and the domain is used only as a benign test indicator. Neither is identified as malicious.

The CSV contains the following fields:

| Field | Description |
|---|---|
| `ioc_type` | Indicator type (`ip` or `domain`) |
| `ioc_value` | IP address or domain name |
| `source` | Source of the IoC information |
| `first_seen` | First observation reported by the source |
| `last_seen` | Most recent observation reported by the source |
| `last_updated` | Last update to the IoC information |
| `expires_at` | Expiration or review date defined by the source or operational policy |
| `status` | Management status of the IoC |

The timestamps and statuses in this example are manually assigned test values.

CSV files can be easily uploaded to Splunk and used for lookups.



An expired IoC does not necessarily indicate that the IP address or domain is no longer malicious. Therefore, `expires_at` is retained as reference information rather than used as an automatic detection exclusion condition.

### 2.3 Detection Fields

| IoC Type | Sysmon Event ID | Matching Field |
|---|---|---|
| IP address | 3 | `DestinationIp` |
| Domain | 22 | `QueryName` |

The initial implementation uses exact matching.

CIDR matching, subdomain matching, and additional normalization are not included in the current implementation.

## 3. Implementation

### 3.1 CSV Lookup Configuration

The IoC CSV file is uploaded to Splunk and configured as a lookup table.

Lookup file name:

`ioc_sample.csv`

The lookup is used to enrich Sysmon events with matching IoC information.

### 3.2 Detection Search

The following SPL query identifies Sysmon events that match the IoC lookup.

```spl
index=sysmon (EventCode=3 OR EventCode=22)
| eval ioc_type=case(
    EventCode=3, "ip",
    EventCode=22, "domain"
  )
| eval ioc_value=case(
    EventCode=3, DestinationIp,
    EventCode=22, QueryName
  )
| lookup ioc_list.csv ioc_type ioc_value OUTPUT source
| where isnotnull(source)
| table _time EventCode Image ioc_type ioc_value source DestinationPort
```

The query:

1. Retrieves Sysmon Event IDs 3 and 22.
2. Extracts the relevant IP address or domain name.
3. Compares the extracted value with the CSV lookup.
4. Returns events that match registered IoCs.
5. Displays the associated IoC metadata.



This search does not automatically exclude expired IoCs.

## 4. Validation

### 4.1 Domain IoC Detection

A test domain is registered in the CSV lookup.

A DNS query is generated using PowerShell:

```powershell
Resolve-DnsName www.iana.org
```

The generated Sysmon Event ID 22 is checked in Splunk.

The detection is validated by confirming that the `QueryName` field matches the domain registered in the lookup file.

This test verifies DNS query detection. It does not demonstrate that a network connection to the destination website was established.

### 4.2 IP Address IoC Detection

The IP address of the Splunk server was registered in the CSV lookup as a test IoC.

Since the Windows endpoint was already communicating with the Splunk server, no additional commands were required to generate network traffic.

The detection was validated by confirming that Sysmon Event ID 3 recorded the connection and that the DestinationIp field matched the IP address registered in the lookup file.

This test confirmed that existing network activity could be detected through IoC matching without manually generating additional traffic.

### 4.3 Validation Result

The validation confirmed that IoC matching can be performed using Sysmon events and a Splunk CSV lookup.

The basic detection mechanism was verified using:

- DNS queries for registered domains.
- Existing network connections to the Splunk server registered as a test IoC.
- Lookup-based filtering of matching Sysmon events.

The implementation demonstrates IoC matching against available telemetry, rather than comprehensive detection of all network traffic.


## 5. Findings and Limitations

### 5.1 Difference Between DNS Queries and Network Connections

Sysmon Event IDs 3 and 22 represent different types of activity.

Event ID 22 records DNS query activity and does not prove that a connection to the resolved destination occurred.

Event ID 3 records network connection activity, but the presence of an event does not necessarily prove that the connection succeeded.

These differences should be reflected in alert names and investigation procedures.

### 5.2 DNS Visibility Limitations

During a separate investigation, some DNS queries generated by Microsoft Edge were visible in Wireshark but were not recorded in Sysmon Event ID 22.

DNS over HTTPS (DoH) was confirmed for some browser queries. However, disabling Secure DNS did not eliminate all visibility gaps.

Therefore, domain-based IoC detection relying exclusively on Sysmon Event ID 22 may miss some DNS activity.

For details, see [DNS Visibility Investigation](dns-visibility-investigation.md).

### 5.3 IoC Expiration and Reliability

An IoC expiration date represents an information-management or review decision, not proof that an indicator is no longer malicious.

An IP address or domain may remain associated with malicious activity after its configured expiration date.

Conversely, previously malicious infrastructure may later be reassigned or used for legitimate purposes.

For this implementation, expired IoCs are not automatically excluded from matching.

In a production environment, IoC confidence, source reliability, recent observations, and revocation information should be considered when determining alert priority or suppression policies.

### 5.4 Exact-Match Limitations

The current detection performs exact matching only.

For example, an IoC entry for `example.com` does not automatically match `sub.example.com`.

Similarly, individual IP address matching does not cover an entire CIDR range.

Additional matching and normalization logic may be required depending on the Threat Intelligence source and detection requirements.

## 6. Future Improvements

Potential improvements include:

- Automatically collecting IoCs from Threat Intelligence feeds such as ThreatFox or AlienVault OTX.
- Updating IoC lookup files periodically.
- Handling revoked, outdated, or low-confidence indicators.
- Supporting CIDR and subdomain matching.
- Adding IoC confidence and contextual information to detection results.
- Improving alert prioritization and suppression.
- Combining Sysmon telemetry with DNS server logs, firewall logs, or other network telemetry to improve visibility.

A CSV lookup provides a simple way to manage predefined IP addresses and domains, while Splunk correlates those indicators with collected endpoint events.

Although the matching logic is straightforward, reliable IoC detection depends on the quality of Threat Intelligence data, telemetry coverage, and appropriate interpretation of the resulting alerts.
