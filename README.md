# Splunk Threat Detection Lab
Project is base off this URL:   https://www.ic3.gov/PSA/2026/PSA260515

## Project Overview
A cloud threat hunting and detection engineering lab built in local Splunk Enterprise, modeling threat vectors from FBI IC3 Alert I-051526-PSA (ShinyHunters Cloud & LMS platform intrusions).


## Architecture & Data Sources
* **SIEM:** Splunk Enterprise (Local)
* **Log Types:** Simulated AWS CloudTrail & LMS API audit telemetry (`index="cloud_logs"`)
* **Framework Alignment:** MITRE ATT&CK & NIST SP 800-61

## Objectives
1. Ingest enterprise cloud audit logs into a dedicated index.
2. Author modular SPL (Search Processing Language) detection rules for session hijacking, administrative persistence, and data exfiltration.
3. Construct an interactive SOC triage dashboard utilizing Risk-Based Alerting (RBA) logic.

-Created account through Splunk for local host enterprise
-Once logged in, created an index called "cloud_log"
-Add json data file in splunk account
-Check to see if logs from json files are respoding through splunk instance. 


This SPL code is to confirm results of json file:

index="cloud_logs" | table _time, user, src_ip, eventName, status

## Query 1 ( session, hijacking , Dual IP login)

Typing SPL code:

index="cloud_logs" eventName="PutBucketPolicy" OR eventName="StopLogging" 
| table _time, user, src_ip, eventName, requestParameters, target, status


With this result confirms the DUal IP anomaly which was successfully detected.

## Query 2 (Admin Persitence & Log Tampering Detection)

`Typing SPL Code:

index="cloud_logs" eventName="PutBucketPolicy" OR eventName="StopLogging" 
| table _time, user, src_ip, eventName, requestParameters, target, status

This seeks for 2 critical post-compromised actions  use by attackers in cloud intrusions.

## Query 3 (Data Exfiltration)

Typing SPL Code:

index="cloud_logs" eventName="GetObject" 
| stats count, sum(bytes_sent) as total_bytes_sent, values(bucket) as targeted_buckets by user, src_ip 
| eval total_MB = round(total_bytes_sent / 1024 / 1024, 2) 
| table user, src_ip, targeted_buckets, count, total_MB 
| where total_MB > 100

In the ShinyHunters playbook, once persistence is established and logs are muted, the final goal is pulling sensitive records (e.g., database exports or LMS records).
