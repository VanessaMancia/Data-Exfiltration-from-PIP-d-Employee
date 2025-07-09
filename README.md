# 🛡️ Insider Threat Hunting: Suspected Data Exfiltration from PIP'd Employee

## Overview

Jane Doe, a potential insider threat, was placed on a Performance Improvement Plan (PIP) after exhibiting behavior indicative of possible data exfiltration. The investigation utilized Microsoft Defender for Endpoint (MDE) data tables to identify, analyze, and respond to suspicious file archiving activity.

---

## 🧭 1. Preparation

### 🎯 Goal:
Set up the hunt by defining what you're looking for.

### Scenario:
Jane Doe, an employee with access to a SCIF (Sensitive Compartmented Information Facility), was placed on a Performance Improvement Plan (PIP). Following signs of emotional distress, management became concerned about the risk of insider threats, including potential exfiltration of sensitive or classified information

### Hypothesis:
Jane has admin rights on her corporate device `nessa-windows`, including unrestricted PowerShell usage. She may compress and archive files and upload them to an external source.

---

## 🗃️ 2. Data Collection

### 🎯 Goal:
Gather relevant data from logs, network traffic, and endpoints.

### Action:
Searched the following Microsoft Defender for Endpoint tables:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

#### Initial Findings:
Located multiple instances of ZIP file creation and movement to a `backup` directory.

```kql
DeviceFileEvents
| where DeviceName == "nessa-windows"
| where FileName contains "zip"
| sort by Timestamp desc
```

![image](https://github.com/user-attachments/assets/88f85eb0-3029-42a2-a826-ef7c425a26c2)

---

## 📊 3. Data Analysis

### 🎯 Goal
Analyze data to test your hypothesis.

### Findings
- Used a specific ZIP file creation timestamp to investigate surrounding events.

### Observed
- PowerShell silently installed 7-Zip.
- 7-Zip was used to archive employee data.

```kql
let VMName = "nessa-windows";
let specificTime = datetime(22025-07-09T22:09:37.7116195Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/8348dfa3-824f-4daa-91c4-2f900181ca9e)

### Exfiltration Check

No signs of external data transfer found in `DeviceNetworkEvents`.

```kql
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == "nessa-windows"
| order by Timestamp desc
```

---

## 🕵️‍♂️ 4. Investigation

### 🎯 Goal
Investigate any suspicious findings.

### MITRE ATT&CK TTPs

| Tactic          | Technique                  | Description                                               |
|-----------------|----------------------------|-----------------------------------------------------------|
| Execution       | PowerShell (T1086)         | Used to silently install and execute 7-Zip                |
| Persistence     | Scheduled Task/Job (T1053) | Potential persistence vector for automated archiving      |
| Defense Evasion | Masquerading (T1036)       | Use of 7-Zip may mask malicious intent                    |
| Collection      | Data Staged (T1074)        | Data prepared in ZIP archive potentially for exfiltration |


---

## 🚨 5. Response

### 🎯 Goal  
Mitigate any confirmed threats.

### Actions Taken
- All findings were escalated to Jane's manager for HR handling.  
- No evidence of data exfiltration was found.  
- Recommended monitoring of Jane's device for further activity.
- Implement DLP (Data Loss Prevention) methods to alert on data exfiltration attempts. 

---

## 📝 6. Documentation

### 🎯 Goal  
Record your findings and learn from them.

### 📚 What was Documented
- Query logs with timestamps  
- Observed file and process behavior  
- MITRE ATT&CK mapping  
- Management escalation actions

---

## 🔄 7. Improvement

### 🎯 Goal  
Improve your security posture or refine your methods.

### Prevention Recommendations:
- **PowerShell Logging & Restrictions**: Enable Script Block and Module Logging, and apply Constrained Language Mode.  
- **Least Privilege**: Restrict unnecessary admin rights and software installation privileges.  
- **Application Whitelisting**: Prevent unauthorized tools like 7-Zip from being silently installed.  
- **Behavioral Alerts**: Create alerts for:
  - PowerShell installing programs
  - Mass ZIP file creation
  - Admin user archiving sensitive files

### ⚙️ Hunting Process Enhancements:
- Automate correlation between `DeviceFileEvents` and `DeviceProcessEvents`
- Add scheduled process hunting based on timestamp-based anomalies
- Improve user behavior baselining (e.g., who normally uses 7-Zip?)

---

## 📌 Summary

This investigation highlights how behavioral analysis and endpoint telemetry can uncover early signs of insider threats. Even without confirmed exfiltration, the act of staging data for compression on a sensitive employee’s device warrants serious scrutiny.


