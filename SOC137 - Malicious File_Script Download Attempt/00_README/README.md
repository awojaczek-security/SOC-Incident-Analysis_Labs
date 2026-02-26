
# 📄 Name of the completed project :
**Incident analysis: Malicious File/Script Download Attempt**

---

## 📅 Incident Details

- **Event ID**: 76 
- **Event Time**: Mar, 14, 2021, 07:15 PM 
- **Detection Rule**: SOC137 - Malicious File/Script Download Attempt
- **Alert Level**: Security Analyst
- **File Name**: INVOICE PACKAGE LINK TO DOWNLOAD.docm
- **File Hash**: f2d0c66b801244c059f636d08a474079
- **Type**: Malware
- **Device Action**: Blocked
---

## 📁 SUMMARY

On February 28, 2022, at 10:48 P.M., our monitoring system triggered an alert and identified activity consistent with a potential IDOR attack. The requested URL was “hxxps://172.16.17.15/get_user_info/”, originating from the source IP address 134.209.118.137.

An analysis of the reputation of the suspicious IP address 134.209.118.137 using the VirusTotal tool did not reveal any active detections by security engines. At the time of analysis, the scan result showed 0 detections, which means that there were no confirmed malicious activities according to the available security providers.

However, attention should be paid to the Community Score section, which contained reports suggesting potentially malicious activity. This information cannot be ignored and requires further verification.

The AbuseIPDB tool was also used to confirm the reputation of the IP address, which classified the specified address as malicious. The analysis showed that the IP address is associated with the digitalocean[.]com domain and is located in the United States.

The POST requests sent to the URL by the threat actor were successful, as indicated by the HTTP 200 response status code. Immediate blocking of the identified IP address is recommended, and the incident should be escalated to the SOC L2 team for further investigation.

---

## 🛠️ Tools

The following tools were used in this alert:

- [VirusTotal](https://www.virustotal.com/)
- [Hybrid-Analysis](https://hybrid-analysis.com/)
  
## 🔐 Macros in Office files - What is the Macros VBA? - the most important informations

**A macro in Microsoft Office files** is a set of instructions written in VBA (Visual Basic for Applications) that automate repetitive tasks. It streamlines work by automatically formatting documents, processing data, and generating reports. Macros are most commonly found in files with the extensions *.docm*, *.xlsm*, and *.pptm*, which allow code to be stored and executed.

Despite numerous legitimate uses, macros can pose a security risk. When used maliciously, they can enable the download and execution of malware. An attacker can also use a macro to steal data or modify the system. For this reason, macros are often used as an attack vector in phishing campaigns.

To reduce the risk, it is recommended to run macros only from trusted sources. In addition, it is recommended to use security mechanisms such as blocking macros from the Internet and monitoring their activity.

## 📸 Information and photos from the analysis of the Incident:

The alert was generated on **February 28, 2022, at 10:48 P.M.** and was described as an IDOR attack. The incident involved the **WebServer1005** server with the address **172.16.17.15**(Destination IP Address), to which requests were sent from the external IP address **134.209.118.137**(Source IP Address). Multiple consecutive **POST** requests were detected. 

The User-Agent was identified as **Mozilla/4.0 (MSIE 6.0 on Windows NT 5.1 with .NET CLR 1.1.4322)**, which may suggest the use of an automated tool or a non-standard client. The reason for generating the alert was successive requests to the same page. However, the traffic was marked as **Allowed**, which means that the system did not block the suspicious activity.
<p align="center">
  <img src="../01_Details_about_incident/Incident_Details.png" width="600">
  <br>
  <em>Figure 1: Incident_Details</em>
</p>


The source IP address **134[.]209[.]118[.]137** was analyzed using VirusTotal.
The scan results showed 0 threats detected by all security vendors,indicating that no known malicious activity or reputation issues were found at the time of analysis. Only in the Community Score section do we see information about some malicious activity, which we cannot ignore. To be sure, we will check the same IP address using the AbuseIPDB tool. 

This address originates from the United States.

<p align="center">
  <img src="../02_Tools_VT_&_Hybrid_Analysis/VirusTotal.png" width="600">
  <br>
  <em>Figure 2: VirusTotal Screenshot</em>
</p>
Additionally, we verify this information in the AbuseIPDB database.
The AbuseIPDB website generated a report on the specified IP address **134[.]209[.]118[.]137**. This address was found in the database and has been reported **1,536 times**, with a “Confidence of Abuse” rating of 0%. Technical details are visible, such as the service provider (**DigitalOcean, LLC**), type of use (**Data Center/Web Hosting/Transit**), and the domain digitalocean.com. 

Server location: **United States, North Bergen, New Jersey**.

The “IP Abuse Reports” section contains information on the number of reports from 312 different sources. The table shows sample reports where the comment indicates “SSH-Attack” and its category is “Brute-Force” and “SSH”. After analyzing both sources, it can now be concluded that this address has suspicious intentions.

</p>
<p align="center">
  <img src="../02_Tools_VT_&_AbuseIPD/AbuseIPDB.png" width="600">
  <br>
  <em>Figure 3: AbuseIPDB Screenshot</em>
</p>

The next step is to verify the log management information.
Five entries were found, and their dates and times are very close to the data contained in the alert.

</p>
<p align="center">
  <img src="../03_Logs_Analysis/Logs.png" width="600">
  <br>
  <em>Figure 4: Log Management</em>
</p>
The logs show that the attacker sent POST requests to five different user_ids in a short period of time. The status of each request is 200, which at first glance may indicate that the attack was successful. 

The first example log:
</p>
<p align="center">
  <img src="../03_Logs_Analysis/Raw_Log_1.png" width="600">
  <br>
  <em>Figure 5: Raw_logs_1 - user_id=1</em>
</p>

The second example log:
</p>
<p align="center">
  <img src="../03_Logs_Analysis/Raw_Log_2.png" width="600">
  <br>
  <em>Figure 6: Raw_logs_2 - user_id=2</em>
</p>

The third example log:
</p>
<p align="center">
  <img src="../03_Logs_Analysis/Raw_Log_3.png" width="600">
  <br>
  <em>Figure 7: Raw_logs_3 - user_id=4</em>
</p>

The attacker sent several requests with different values for the user_id=x parameter.

IDOR (Insecure Direct Object Reference) occurs when an application provides a direct reference to a resource (e.g., user_id, order_id, file_id) and does not verify whether the currently logged-in user has access rights to the specified object.

If the application only checks whether the user is logged in, but does not check whether the resource belongs to them, the attacker can modify the parameter in the request and gain access to another user's data, which was most likely the case with this alert.


After completing the investigation and gathering all relevant evidence, the findings were analyzed, final conclusions were determined, and supporting artifacts were included to document the investigation process.

These artifacts include:
</p>
<p align="center">


                          | Value                                | Comment                      | Type        |
                          | -----------------------------------  | ---------------------------- | ----------- |
                          | 178[.]175[.]67[.]109                 | IP Address - MD5             | IP Address  |  
                          | 188[.]114[.]96[.]3                   | IP Address - DNS             | IP Address  |
                          | f2d0c66b801244c059f636d08a474079     | Malicious Hash - MD5         | MD5 Hash    |
                          | 172[.]16[.]17[.]37                   | Source IP Address            | IP Address  | 
</p>


The final results after the case was closed:
</p>
<p align="center">
  <img src="../05_Results_of_Investigation/Results_of_my_research.png" width="600">
  <br>
  <em>Figure 8: Results_of_my_research</em>
</p>


**The Summary of the investigation**:



## 🔥 Lessons Learned

After completing the investigation, the alert was confirmed as a True Positive. The analyzed Office document contained malicious VBA macros that were intentionally obfuscated. Their purpose was to execute commands and potentially download or run additional payloads once the user enabled macros.

We used VirusTotal and Hybrid Analysis to verify the file. These platforms helped us confirm malicious indicators, observe the file’s behavior in a sandbox environment, and compare the results with known threat intelligence. This gave us higher confidence in our final assessment and showed how important it is to use multiple sources during analysis.

**What can be learned from analyzing malicious files containing macros**:

- Checking the hash in tools such as VirusTotal allows for immediate correlation with a  database.

- The presence of macros in an Office document significantly increases the risk level and requires thorough checking of the VBA code.

- Macros are often obfuscated to hide their true purpose.

- Malicious macros can be used to download additional payloads, execute system commands, or establish network connections.

- Sandbox analysis (e.g., Hybrid Analysis) helps to see the actual behavior of the file after it is launched.

- Correlating the hash, static (VBA) and dynamic (sandbox) analyses gives a more complete picture of the threat.

- Hash verification is a quick first step, but it does not replace a full security analysis.

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


