## DNS Query Visibility Investigation

### Objective

Before implementing domain-based Indicator of Compromise (IoC) detection in Splunk, I conducted a preliminary test to verify whether DNS query events collected by Sysmon contained the domain names accessed through a web browser.

The expected behavior was that DNS queries generated during web browsing would be recorded in Sysmon Event ID 22 and forwarded to Splunk, where the queried domain names could be compared against known malicious domains.

### Issue Encountered

During testing with Microsoft Edge, some domains, including `www.youtube.com` and `www.iana.org`, were not found in Sysmon Event ID 22, even though the websites were successfully accessed.

However, DNS queries generated explicitly through PowerShell using `Resolve-DnsName` were recorded successfully.

This suggested that the issue was not simply caused by disabled DNS query logging or a failure in the Sysmon-to-Splunk log forwarding pipeline.

### Investigation

The following tests were performed to identify the cause.

| Test | Observation |
|---|---|
| Verify Sysmon configuration | DNS query logging was enabled. |
| Execute `Resolve-DnsName` in PowerShell | The queried domain was recorded in Sysmon Event ID 22 and Splunk. |
| Access `www.iana.org` through Edge with Secure DNS enabled | The domain was not found in Sysmon Event ID 22 or standard DNS packet captures. |
| Analyze Edge NetLog | Confirmed that Edge performed the DNS query using DNS over HTTPS (DoH). |
| Disable Secure DNS in Edge | DNS queries, including `www.iana.org`, became visible in Wireshark. |
| Check Sysmon Event ID 22 again | The corresponding domain was still missing from both Windows Event Viewer and Splunk. |
| Launch Edge with `--disable-async-dns` | The argument appeared in `edge://version`, but the missing DNS event issue remained. |

#### DNS over HTTPS Verification

Edge NetLog showed the following information when accessing `www.iana.org` with Secure DNS enabled:

```text
HOST_RESOLVER_DNS_TASK
  secure = true

DNS_TRANSACTION_HTTPS_ATTEMPT
  source_dependency = DNS_OVER_HTTPS

DOH_URL_REQUEST
  hostname = "www.iana.org"
  url = "https://doh.xfinity.com/dns-query?dns=..."

HTTP_TRANSACTION_READ_RESPONSE_HEADERS
  HTTP/1.1 200
  content-type: application/dns-message
```

These results confirmed that Edge used the Xfinity DoH endpoint to resolve `www.iana.org`.

Because the DNS request was transmitted over HTTPS, the queried domain was not visible as a conventional DNS query in Wireshark.

#### Testing with Secure DNS Disabled

After disabling Secure DNS in Edge, Wireshark successfully captured standard DNS queries over UDP port 53, including queries for `www.iana.org`.

However, the corresponding domain was still absent from Sysmon Event ID 22 in both Windows Event Viewer and Splunk.

This indicated that disabling DoH alone did not resolve the visibility issue.

An additional test was performed by launching Edge with the `--disable-async-dns` argument. Although the argument was visible in `edge://version`, it did not resolve the issue. Whether the argument actually changed DNS resolver behavior in the tested Edge version was not verified.

### Findings

The investigation identified two important limitations.

**1. DNS over HTTPS limits visibility into conventional DNS traffic.**

When Edge used DoH, the DNS request was transmitted through an encrypted HTTPS connection rather than conventional DNS traffic over port 53.

As a result, the queried domain was not visible through standard DNS packet inspection.

**2. Sysmon Event ID 22 does not necessarily capture every DNS query sent by an endpoint.**

Even when Wireshark confirmed that Edge sent a conventional DNS query, the corresponding domain was not always recorded in Sysmon Event ID 22.

One possible explanation is that Edge used a DNS resolution mechanism that was not observed by Sysmon's DNS query monitoring.

However, the exact internal mechanism responsible for the missing events was not conclusively identified.

### Lessons Learned

- Successful DNS resolution does not guarantee that a corresponding Sysmon Event ID 22 will be generated.
- DNS visibility depends on both the resolution mechanism used by the application and the monitoring method.
- DoH can prevent conventional network DNS monitoring from observing queried domain names.
- Sysmon Event ID 22 alone should not be considered a comprehensive source of DNS activity for domain-based IoC detection.
- DNS server logs and network DNS monitoring can provide additional visibility into conventional DNS queries, but they cannot capture queries that bypass the monitored DNS infrastructure, including external DoH traffic.
