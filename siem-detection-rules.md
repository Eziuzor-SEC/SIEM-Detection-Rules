# SIEM Detection Rules

**Report ID:** SIEM-DR-001  
**Category:** Detection Engineering  
**Platforms:** Splunk | Microsoft Sentinel (KQL) | IBM QRadar  
**Analyst:** Michael Eziuzor  
**Date:** April 2026  

---

## 1. Overview

This document contains custom detection rules written for three major 
SIEM platforms — Splunk (SPL), Microsoft Sentinel (KQL), and IBM QRadar 
(AQL). Each rule is designed to detect a specific attack technique 
commonly encountered in SOC environments and is mapped to the MITRE 
ATT&CK framework.

---

## 2. Brute Force Attack Detection

**Description:**
Detects a high volume of failed logon attempts from a single source 
within a short timeframe indicating a brute force or password spraying 
attack.

**MITRE ATT&CK:** T1110 — Brute Force  
**Severity:** High

### Splunk (SPL)
index=windows EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 10
| sort -count
| table _time, src_ip, user, count

### Microsoft Sentinel (KQL)
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| sort by FailedAttempts desc

### IBM QRadar (AQL)
SELECT sourceip, username, COUNT(*) as attempts
FROM events
WHERE qid = 28250802
AND LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'
AND username IS NOT NULL
GROUP BY sourceip, username
HAVING attempts > 10
LAST 60 MINUTES

---

## 3. Successful Logon After Brute Force

**Description:**
Detects a successful authentication event following multiple failed 
attempts from the same source — indicating a successful brute force attack.

**MITRE ATT&CK:** T1110 — Brute Force  
**Severity:** Critical

### Splunk (SPL)
index=windows EventCode=4625
| stats count as failures by src_ip, user
| where failures > 5
| join src_ip, user
[search index=windows EventCode=4624
| stats count as successes by src_ip, user]
| where successes > 0
| table src_ip, user, failures, successes

### Microsoft Sentinel (KQL)
let Failures = SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailCount = count() by IpAddress, Account
| where FailCount > 5;
let Successes = SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(1h)
| project IpAddress, Account, TimeGenerated;
Failures
| join kind=inner Successes on IpAddress, Account
| project IpAddress, Account, FailCount, TimeGenerated

### IBM QRadar (AQL)
SELECT sourceip, username, COUNT(*) as failed_attempts
FROM events
WHERE qid = 28250802
AND eventdirection = 'L2L'
GROUP BY sourceip, username
HAVING failed_attempts > 5
AND sourceip IN
(SELECT sourceip FROM events
WHERE qid = 28250800
LAST 60 MINUTES)
LAST 60 MINUTES

---

## 4. Windows Credential Vault Access

**Description:**
Detects enumeration of stored Windows Credential Vault credentials 
indicating possible credential harvesting activity.

**MITRE ATT&CK:** T1555.004 — Windows Credential Manager  
**Severity:** High

### Splunk (SPL)
index=windows EventCode=5381
| table _time, host, user, Message
| sort _time

### Microsoft Sentinel (KQL)
SecurityEvent
| where EventID == 5381
| where TimeGenerated > ago(24h)
| project TimeGenerated, Computer, Account, Activity
| sort by TimeGenerated desc

### IBM QRadar (AQL)
SELECT starttime, sourceip, username, eventdirection
FROM events
WHERE qid IN (SELECT id FROM qidmap WHERE name ILIKE '%vault%')
ORDER BY starttime ASC
LAST 24 HOURS
---

## 5. Audit Log Cleared

**Description:**
Detects when the Windows Security event log is cleared — a strong 
indicator of an attacker attempting to destroy forensic evidence.

**MITRE ATT&CK:** T1070.001 — Clear Windows Event Logs  
**Severity:** Critical

### Splunk (SPL)
index=windows EventCode=1102
| table _time, host, user, Message
| sort -_time

### Microsoft Sentinel (KQL)
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
| sort by TimeGenerated desc

### IBM QRadar (AQL)
SELECT starttime, sourceip, username, LOGSOURCENAME(logsourceid)
FROM events
WHERE qid = 28250818
ORDER BY starttime DESC
LAST 24 HOURS

---

## 6. Privilege Escalation — Admin Group Addition

**Description:**
Detects when a user account is added to a privileged group such as 
Domain Admins or local Administrators outside of approved change 
management procedures.

**MITRE ATT&CK:** T1078 — Valid Accounts  
**Severity:** Critical

### Splunk (SPL)
index=windows (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| search Group_Name="Admin" OR Group_Name="Administrator"
| table _time, host, user, Group_Name, Member_Name
| sort -_time

### Microsoft Sentinel (KQL)
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TimeGenerated > ago(24h)
| extend GroupName = tostring(parse_json(EventData).TargetUserName)
| where GroupName contains "Admin"
| project TimeGenerated, Account, GroupName, Computer
| sort by TimeGenerated desc

### IBM QRadar (AQL)
SELECT starttime, sourceip, username, GROUP_NAME(groupid)
FROM events
WHERE qid IN (28250813, 28250814, 28250815)
AND GROUP_NAME(groupid) ILIKE '%admin%'
ORDER BY starttime DESC
LAST 24 HOURS

---

## 7. XWorm C2 Communication Detection

**Description:**
Detects outbound connections to known XWorm C2 infrastructure on 
port 6000 — XWorm's default command and control port.

**MITRE ATT&CK:** T1571 — Non-Standard Port  
**Severity:** Critical

### Splunk (SPL)
index=network dest_port=6000
| stats count by src_ip, dest_ip, dest_port
| where count > 5
| sort -count
| table src_ip, dest_ip, dest_port, count

### Microsoft Sentinel (KQL)
NetworkCommunicationEvents
| where RemotePort == 6000
| where TimeGenerated > ago(1h)
| summarize count() by LocalIP, RemoteIP, RemotePort
| sort by count_ desc

### IBM QRadar (AQL)
SELECT sourceip, destinationip, destinationport, COUNT(*) as connections
FROM events
WHERE destinationport = 6000
AND eventdirection = 'L2R'
GROUP BY sourceip, destinationip, destinationport
HAVING connections > 5
LAST 60 MINUTES

---

## 8. Suspicious PowerShell Execution

**Description:**
Detects encoded or obfuscated PowerShell commands commonly used 
by attackers to execute malicious code while evading detection.

**MITRE ATT&CK:** T1059.001 — PowerShell  
**Severity:** High

### Splunk (SPL)
index=windows EventCode=4688
(CommandLine="-enc" OR CommandLine="-EncodedCommand"
OR CommandLine="FromBase64String" OR CommandLine="-ep bypass")
| table _time, host, user, CommandLine
| sort -_time

### Microsoft Sentinel (KQL)
SecurityEvent
| where EventID == 4688
| where CommandLine contains "-enc"
or CommandLine contains "-EncodedCommand"
or CommandLine contains "FromBase64String"
or CommandLine contains "-ep bypass"
| project TimeGenerated, Computer, Account, CommandLine
| sort by TimeGenerated desc

### IBM QRadar (AQL)
SELECT starttime, sourceip, username, Command
FROM events
WHERE Command ILIKE '%-enc%'
OR Command ILIKE '%-EncodedCommand%'
OR Command ILIKE '%FromBase64String%'
ORDER BY starttime DESC
LAST 24 HOURS

---

## 9. Detection Rules Summary

| Rule | Attack Type | MITRE ID | Severity |
|------|-------------|----------|----------|
| Brute Force Detection | Brute Force | T1110 | High |
| Successful Logon After Brute Force | Brute Force | T1110 | Critical |
| Credential Vault Access | Credential Access | T1555.004 | High |
| Audit Log Cleared | Defence Evasion | T1070.001 | Critical |
| Privilege Escalation | Privilege Escalation | T1078 | Critical |
| XWorm C2 Detection | C2 | T1571 | Critical |
| Suspicious PowerShell | Execution | T1059.001 | High |

---

**Analyst:** Michael Eziuzor | github.com/Eziuzor-SEC  
**Date:** April 2026
