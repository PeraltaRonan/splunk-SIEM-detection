# Splunk Threat Detection Lab
## Project Overview
Based on a cyberattack under a Cyber criminal group called "ShinyHunters" caused distruption on scale data breaches and extortion, which targeted major companies across the tech, finance, and retail business which was often stealing millions of data from customer record.

Therefore having to `engineer a cloud detection lab by ingesting a cloud telemetry into Spunk Enterprise` and `authored SPL detection rules` mapped to the MITRE ATT&CK framework, specifically targeting session hijacking, admin log tampering, and mass S3 data exfiltration. To bridge the gap between detection and operations, I have `built a unified SOC Triage Dashboard` and authored an incident response playbook listing containment and credential workflows.

Cloud Detection Lab based off this URL:   https://www.ic3.gov/PSA/2026/PSA260515


## Architecture & Data Sources
* **SIEM:** Splunk Enterprise (Local)
* **Log Types:** Simulated AWS CloudTrail & LMS API audit telemetry (`index="cloud_logs"`)
* **Framework Alignment:** MITRE ATT&CK & NIST SP 800-61

## Objectives
1. Ingest enterprise cloud audit logs into a dedicated index.
2. Author modular SPL (Search Processing Language) detection rules for session hijacking,   administrative persistence, and data exfiltration.
3. Construct an interactive SOC triage dashboard utilizing Risk-Based Alerting (RBA) logic.

- Created account through Splunk for local host enterprise
- Once logged in, created an index called "cloud_logs"
- Ingested the JSON telemetry dataset into Splunk Enterprise.
- Verified log ingestion by executing search queries in Splunk.



## Repository Structure

![Cloud Logs](screenshots/repo_structure.JPG)


## Printing of Telemetry
This SPL code is to confirm results of json file:

index="cloud_logs" | table _time, user, src_ip, eventName, status

![Json File](screenshots/shinyhunters_cloud_telemetry.JPG)

![Cloud Logs](screenshots/cloud_logs_jsonfile.JPG)



## Query 1 ( session, hijacking , Dual IP login)

Typing SPL code:

index="cloud_logs" eventName="ConsoleLogin" 
| stats dc(src_ip) as unique_ips, values(src_ip) as ip_addresses by user 
| where unique_ips > 1

With this result confirms the DUal IP anomaly which was successfully detected.


![Query 1 - Dual IP Address](screenshots/query1_dual_ip_address.JPG)


## Query 2 (Admin Persitence & Log Tampering Detection)

Typing SPL Code:

index="cloud_logs" eventName="PutBucketPolicy" OR eventName="StopLogging" 
| table _time, user, src_ip, eventName, requestParameters, target, status

This detects two critical post-compromise actions used by attackers in cloud intrusions.

![Query 2 - Tampering](screenshots/query2_tampering.JPG)


## Query 3 (Data Exfiltration)

Typing SPL Code:

index="cloud_logs" eventName="GetObject" 
| stats count, sum(bytes_sent) as total_bytes_sent, values(bucket) as targeted_buckets by user, src_ip 
| eval total_MB = round(total_bytes_sent / 1024 / 1024, 2) 
| table user, src_ip, targeted_buckets, count, total_MB 
| where total_MB > 100

In the ShinyHunters playbook, once persistence is established and logs are muted, the final goal is pulling sensitive records (e.g., database exports or LMS records).


![Query 3 - Data Exfiltration](screenshots/query3_data_exfiltration.JPG)


## Incident Response & SOC Triage Playbook

When the Splunk SIEM triggers an alert from our detection rules, the on-call SOC analyst follows this standardized 3-phase workflow:

### Phase 1: Triage & Validation
* **Trigger:** Alert fires for `Session Hijacking` (Multi-IP login) or `Administrative Tampering` (`StopLogging` / `PutBucketPolicy`).
* **Analyst Actions:**
  1. Inspect the source IP addresses (`src_ip`) and user agent strings (`userAgent`) associated with the `admin_user` session.
  2. Correlate timestamps against known corporate VPN ranges or geo-IP databases to verify if the dual-IP activity represents legitimate travel or a stolen session cookie (MITRE ATT&CK).
  3. Check for accompanying defensive evasion events (`StopLogging`) to confirm if malicious actors are trying to blind telemetry.

### Phase 2: Containment & Eradication
* **Analyst Actions:**
  1. **Revoke Access:** Immediately invalidate active session tokens and force a password/credential reset for the compromised account via cloud CLI:
     ```bash
     aws iam update-login-profile --user-name admin_user --password-reset-required
     ```
  2. **Re-Enable Defenses:** Reverse log tampering by restoring the CloudTrail logging configuration:
     ```bash
     aws cloudtrail start-logging --name CloudTrail-Main
     ```
  3. **Remediate Bucket Policies:** Inspect and revert unauthorized public exposure changes on target S3 buckets (`PutBucketPolicy` with `principal: "*"`).

### Phase 3: Post-Incident Analysis & Hunting
* **Analyst Actions:**
  1. Run **Query 3** (`GetObject` volume threshold check) to determine if mass data exfiltration (`lms-student-records-db`) occurred prior to containment.
  2. Document indicators of compromise (IOCs) such as malicious attacker source IPs (`203.0.113.19`) for firewall and WAF blacklisting.
  3. File an incident report detailing the attack lifecycle mapped back to the FBI IC3 ShinyHunters intelligence briefing.



## Threat Mapping & MITRE ATT&CK Matrix

This detection suite maps directly to key adversary tactics, techniques, and procedures (TTPs) observed in the **FBI IC3 ShinyHunters Threat Activity Alert**:

| Threat Behavior | Attack Lifecycle Stage | MITRE ATT&CK Technique | Detection Rule / SPL | Alert Severity |
| :--- | :--- | :--- | :--- | :--- |
| **Session Cookie Theft** | Initial Access / Privilege Abuse | `T1078` - Valid Accounts | `query1_duel_ip_login.spl` (Dual-IP Analysis) | **High** |
| **Cloud Audit Log Disruption** | Defense Evasion | `T1562.008` - Impair Defenses: Disable Cloud Logs | `query2_admin_tampering.spl` (`StopLogging`) | **Critical** |
| **Public Storage Bucket Exposure** | Persistence / Privilege Abuse | `T1098` - Account Manipulation | `query2_admin_tampering.spl` (`PutBucketPolicy`) | **High** |
| **Mass S3 Data Exfiltration** | Exfiltration | `T1537` - Transfer Data to Cloud Account | `query3_data_exfiltration.spl` (`GetObject` >100MB) | **Critical** |
