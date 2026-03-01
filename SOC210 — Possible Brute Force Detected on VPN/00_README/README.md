

# 📄 Name of the completed project :
**Incident analysis: Possible Brute Force Detected on VPN**

---

## 📅 Incident Details

- **Event ID**: 162 
- **Event Time**: Jun, 21, 2023, 01:51 PM 
- **Detection Rule**: SOC210 — Possible Brute Force Detected on VPN
- **Source IP Address**: 37.19.221.229
- **Destination IP Address**: 33.33.33.33
- **Destination Hostname**: Mane
- **Alert Level**: Security Analyst  
- **Type**: Brute Force
- **Alert Trigger Reason**: A successful VPN login was detected shortly after failed login attempts from the same source IP address
- **L1 Note**: I checked the authentication logs and saw many login failures from the same IP address. It was also detected that the same IP address was attempting to login for different users. Successful login looks suspicious after these failed login attempts.
---

## 📁 SUMMARY


---

## 🛠️ Tools

The following tools were used in this alert:

- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
  
## 🔐 BRUTE FORCE ATTACK - What is it? - the most important informations

A **brute force attack** is a technique that involves repeatedly and automatically trying different combinations of usernames and passwords in order to gain unauthorized access to a system, application, network service, or user account.

These attacks are usually carried out using automated tools that generate all possible character combinations (full brute force) or combinations based on word lists (dictionary attacks).

The purpose of such an attack may be to:

-- take over user accounts (e.g., *VPN*, *email*, *RDP*, *SSH*),

- gain administrative access,

- increase privileges in the environment,

- prepare for subsequent stages of the attack (e.g., *deploying malware* or *launching ransomware*).

Common indicators in logs (**IoC - Indicators of Compromise**)

This attack can be identified by:

- a large number of failed login attempts in a short period of time,

- repeated login attempts from a single IP address to multiple accounts,

- login attempts to a single account from multiple IP addresses (*distributed brute force*),

- logins at unusual times,

- a sudden increase in traffic directed to authentication services (e.g., *RDP*, *SSH*, *VPN*).

## 📸 Information and photos from the analysis of the Incident:

The alert was generated on **Jun, 21, 2023, 01:51 PM**.
This alert describes an event detected as a potential brute force attack on a VPN service. Multiple failed login attempts to various user accounts were recorded from a single IP address. After a series of failed attempts, a successful login to the account *mane@letsdefend.io*. This pattern of activity is characteristic of a password guessing attack. The event indicates a high risk of user account takeover. The incident requires further analysis of post-login activity and security measures such as password reset and source IP address verification.

<p align="center">
  <img src="../01_Details_about_incident/Incident_Details.png" width="600">
  <br>
  <em>Figure 1: Incident_Details</em>
</p>

A reputation check in VirusTotal showed no malicious activity associated with the source IP address 37.19.221.229. All security vendors reported 0 detections, indicating no known malicious reputation at the time of analysis.

This address originates from the United States.

<p align="center">
  <img src="../02_Tools_VT_&_AbuseIPDB/VirusTotal.png" width="600">
  <br>
  <em>Figure 2: VirusTotal Screenshot</em>

Additionally, we verify this information in the AbuseIPDB database.
The IP address **37.19.221.229** has been reported 64 times in **AbuseIPDB** by various entities. The current risk level (*Confidence of Abuse 11%*) is relatively low. The last report appeared a week ago, so the activity is quite recent. The address belongs to a hosting company (*Datacamp Limited (AS212238*)), i.e., a server in a data center, and not to a regular home user. In the past, it has been linked to brute force attempts, port scanning, website attacks, and other automated activity. This means that this address has a suspicious history and should not be ignored.

</p>
<p align="center">
  <img src="../02_Tools_VT_&_AbuseIPDB/AbuseIPDB_1.png" width="600">
  <br>
  <em>Figure 3: AbuseIPDB_1 Screenshot</em>
</p>

</p>
<p align="center">
  <img src="../02_Tools_VT_&_AbuseIPDB/AbuseIPDB_2.png" width="600">
  <br>
  <em>Figure 4: AbuseIPDB_2 Screenshot</em>
</p>

The next step is to verify the log management information. Many entries were found, and their dates and times are very close to the data contained in the alert.

</p>
<p align="center">
  <img src="../03_Logs_Analysis/Logs.png" width="600">
  <br>
  <em>Figure 5: Log Management</em>
</p>

Analysis of detailed logs revealed numerous failed attempts to log into the **VPN network** from a single IP address. The attacker tried using multiple usernames until the correct account was identified (*mane@letsdefend.io*). After a series of unsuccessful attempts, a successful login to this account was recorded. This pattern of activity is characteristic of a *brute force* and may indicate that credentials have been compromised.
</p>
<p align="center">
  <img src="../03_Logs_Analysis/Logs_Login_Wrong.png" width="600">
  <br>
  <em>Figure 6: Log Management - Incorrect login</em>
</p>

</p>
<p align="center">
  <img src="../03_Logs_Analysis/Logs_Login_Successful.png" width="600">
  <br>
  <em>Figure 5: Log Management - Login Successful!!</em>
</p>

In the next stage, Mane's activity in the Endpoint Security system was verified to check whether any suspicious processes, unusual network connections, or commands had been executed after the incident.
The analysis showed that after the alert was generated, i.e., after successfully logging into the **VPN**, no suspicious system activity was recorded.

It was also noted that the IP address of the end system differs from the destination address indicated in the logs (**33.33.33.33**). This is due to the fact that **33.33.33.33** is the public address of the **VPN gateway**, while after establishing a connection, the user receives an internal IP address within the company network.

</p>
<p align="center">
  <img src="../04_Endpoint_Security/Endpoint_Information.png" width="600">
  <br>
  <em>Figure 6: Endpoint - Victim's original IP address - Mane</em>
</p>
These artifacts include:
</p>
<p align="center">


                          | Value                            | Comment                                    | Type           |
                          | ---------------------------------| ------------------------------------------ | -------------- |
                          | 33[.]33[.]33[.]33                | Destination IP Address                     | IP Address     |  
                          | 37[.]19[.]221[.]229              | Malicious IP address                       | IP Address     |
                          | 172[.]16[.]17[.]210              | Victim's IP address - Mane                 | IP Address     |
                          | mane@letsdefend[.]io             | Compromised credential - Email Address     | Email Address  | 
</p>


The final results after the case was closed:
</p>
<p align="center">
  <img src="../05_Results_of_Investigation/Results_of_my_research.png" width="600">
  <br>
  <em>Figure 7: Results_of_my_research</em>
</p>


**The Summary of the investigation**:



## 🔥 Lessons Learned

After completing the investigation, the alert has been confirmed as a True Positive. 

The findings enhanced our understanding of IDOR attack patterns and helped validate the effectiveness of our detection and response procedures.

Such incidents should never be ignored and require consistent, detailed analysis, as they may contain a variety of artifacts.

Every alert must be properly verified. As SOC analysts, we must remain vigilant and approach each investigation in an orderly and methodical manner.

This laboratory training gave us the following skills:
- it strengthened our skills in using online tools such as AbusedIPDB, VirusTotal an MalwareURL.
- learning a new attack method - IDOR and how to detect and eliminate it
- detecting threats
- gathering information about threats
- documenting incident response

## 📂 Project Structure

```bash
SOC169 - Possible-IDOR-Attack-Detected/
│
├── 00_README/
│   └── README.md
│
├── 01_Details_about_incident/
│   └── Incident_Details.png
│
├── 02_Tools_VT_&_AbuseIPDB/
│   ├── AbuseIPDB.png
│   └── VirusTotal.png
│
├── 03_Logs_Analysis/
│   ├── Logs.png
│   ├── Raw_Log_1.png
│   ├── Raw_Log_2.png
│   └── Raw_Log_3.png
│
├── 04_Results_of_Investigation/
│   ├── Artifacts_table.png
│   └── Results_of_my_research.png

```

