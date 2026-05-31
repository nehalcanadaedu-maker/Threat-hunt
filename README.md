# EmberForge Source Leak Investigation (Active Directory Attack Investigation)

This threat hunt investigation was conducted within a Microsoft Sentinel environment following reports of unauthorized activity within the EmberForge Studios environment.

# Environment Details

| Item                 | Value                                       |
| -------------------- | ------------------------------------------- |
| SIEM Platform        | Microsoft Sentinel                          |
| Workspace            | law-cyber-range                             |
| Investigation Window | 2026-01-30 21:00 UTC – 2026-01-31 00:00 UTC |
| Custom Log Table     | EmberForgeX_CL                              |

---

# Q01 - Target Directory


**Category:** impact-assessment collection  

CISO:  
> "I have a board meeting in 4 hours. Before I care about how they got in, I need to know what they took and where it went. Legal needs the scope for breach notification."

The attacker needed to package data before stealing it. The compression commands reveal exactly what they were targeting. What directory was the source of the stolen data?

**Format:** Full path (e.g., `C:\folder\subfolder`)

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

# Q02 - Exfil Destination

**Category:** impact-assessment exfiltration  

The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details. What cloud provider received the data?

**Format:** Provider name

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "gamedev.zip"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


### Screenshot
<img width="1000" height="315" alt="image" src="https://github.com/user-attachments/assets/19e0639e-25cd-4f62-9d19-b3628e2e0aca" />

---


# Q03 - Attacker Attribution

**Category:** impact-assessment attribution  

Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line. What email account was used to authenticate to the cloud service?

**Format:** `email@domain.tld`

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeGenerated, Computer, EventCode_s, CommandLine_s
| order by TimeGenerated asc
```

### Screenshot
<img width="973" height="302" alt="image" src="https://github.com/user-attachments/assets/6a69f464-3bb7-465b-8f67-7aca0ee6e4a5" />



---
# Q04 - Domain Compromise Evidence

**Category:** impact-assessment credential-access  

This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file. This file contains every credential in the domain. What was it?

**Format:** `filename.ext`

## Query Used

```kql id="fwm0m7"
EmberForgeX_CL
| where CommandLine_s has_any ("vssadmin", "shadow", "ntds", "diskshadow", "copy")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


<img width="1031" height="331" alt="4" src="https://github.com/user-attachments/assets/90feb888-ea33-4f58-ab14-07e933c80e84" />

---
# Q05 - Exfil Tool

**Category:** exfiltration tools  

CISO:  
> "I need to understand the exfiltration path. What tools did they use? Where did they stage from? Can we confirm this was the only way data left the network?"

Data does not always leave from the machine it was found on. Check all hosts.

A cloud synchronisation tool was used to upload data externally. This tool is legitimate software commonly abused by threat actors. It was executed multiple times, not all successfully.

**Format:** `filename.exe`

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("vssadmin", "shadow", "ntds", "diskshadow", "copy")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```



### Screenshot
<img width="1031" height="331" alt="image" src="https://github.com/user-attachments/assets/9cdad307-888b-4d68-9e8b-2fc03438a868" />


---

# Q06 - Exfil Destination IP
 
**Category:** exfiltration network  

The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3). What IP address received the stolen data?

**Format:** IP address
  
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



# Q07 - Attacker Credential Exposure

**Category:** exfiltration credential-exposure  

The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution method exposed credentials far more recklessly than the others. Compare all executions and find the plaintext password.

**Format:** Plaintext password

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

# Q08 - Archive Method

**Category:** collection living-off-the-land  

Before exfiltration, the stolen data was compressed into an archive. The attacker used a built-in OS capability rather than third-party tools. This is a Living Off The Land technique. What cmdlet created the archive?

**Format:** PowerShell cmdlet name

## Query Used

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("zip", "rar", "7z", "tar", "archive", "compress")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| order by TimeGenerated asc
```


<img width="1005" height="336" alt="image" src="https://github.com/user-attachments/assets/6b339eff-f4b5-4ee8-b58c-eba398be3c03" />


# Q09 - Staging Server

**Category:** infrastructure tool-transfer  

The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

**Format:** `subdomain.domain.tld`
  
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


### Screenshot
<img width="876" height="277" alt="Screenshot 2026-05-30 105825" src="https://github.com/user-attachments/assets/95532dc2-7034-4dc0-a8da-615a9bb91099" />



---




