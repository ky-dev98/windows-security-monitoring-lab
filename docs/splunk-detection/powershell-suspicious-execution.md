# Splunk Detection Engineering

# Suspicious PowerShell Execution Detection

## 1. Overview

This detection focuses on identifying potentially suspicious PowerShell execution patterns using Sysmon Event ID 1 (Process Creation) logs collected in Splunk Enterprise.

The detection targets the following behaviors:

- Execution of Base64-encoded commands using `-EncodedCommand`
- Dynamic command execution using `Invoke-Expression` or its alias `IEX`
- Hidden PowerShell execution using `-WindowStyle Hidden`

These behaviors may be associated with malicious activity, but they can also occur during legitimate administrative operations.

The objective is to identify potentially suspicious PowerShell executions for further investigation rather than classify every matching event as malicious.

## 2. Required Data Source

- **Data source:** Sysmon
- **Event ID:** 1 (Process Creation)
- **SIEM:** Splunk Enterprise
- **Index:** `sysmon`
- **Key fields:** `Image`, `CommandLine`, `ParentImage`, `User`, `Computer`

## 3. Detection Logic

The initial detection rule focuses on identifying PowerShell processes launched with the `-EncodedCommand` parameter.

The rule uses Sysmon Event ID 1 (Process Creation) and examines the process image and command-line arguments.

```spl
index=sysmon EventCode=1
| where match(lower(Image), "(powershell|pwsh)\.exe$")
| where match(lower(CommandLine), "(?<![a-z])-enc(?:odedcommand)?\s+")
| table _time Computer User ParentImage Image CommandLine
| sort - _time
```

This rule is intended to identify potentially suspicious PowerShell executions for further investigation. The use of `-EncodedCommand` alone does not necessarily indicate malicious activity.

## 4. Test Procedure and Results

### 4.1 Test Procedure

I executed a harmless PowerShell command using the `-EncodedCommand` parameter to generate a test event.

```powershell
$command = 'Write-Output "Detection Test"'
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($command)
)

powershell.exe -NoProfile -EncodedCommand $encoded
```

I also executed a normal PowerShell command without the `-EncodedCommand` parameter to compare the results.

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Normal Test'"
```

#### 4.2 Test Results

**01. PowerShell Process Creation Log Verification**

Verified that PowerShell process creation events were successfully collected through Sysmon Event ID 1 and could be searched in Splunk Enterprise.

![PowerShell Process Creation Log Verification](../../images/splunk-detection/splunk_detection_suspicious_powershell_01.png)

**02. Encoded PowerShell Command Detection**

Confirmed that the detection rule successfully identified PowerShell execution using the `-EncodedCommand` parameter.

![Encoded PowerShell Command Detection](../../images/splunk-detection/splunk_detection_suspicious_powershell_02.png)

**03. Detection Validation with Normal PowerShell Execution**

Confirmed that the normal PowerShell execution did not match the detection rule, while the encoded command execution remained visible in the search results.

![Detection Validation with Normal PowerShell Execution](../../images/splunk-detection/splunk_detection_suspicious_powershell_03.png)

## 5. False Positives and Limitations

*To be added after analyzing the test results.*

## 6. Findings and Lessons Learned

*To be added after completing the validation.*

## 5. Future Work
