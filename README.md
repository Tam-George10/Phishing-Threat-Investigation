# Phishing-Threat-Investigation
This repository presents a hands-on SOC investigation focused on identifying, analyzing, and responding to phishing-based threats. The project follows a real-world Blue Team workflow, including email artifact analysis, malicious URL and attachment investigation, log correlation, and network traffic analysis. 

<h1>Real-World Scenario</h1>
A Sales Executive at Greenholt PLC received an email that he didn't expect to receive from a customer. He claims that the customer never uses generic greetings such as "Good day" and didn't expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation. 


<h2>Description</h2>
<b>
This project focuses on the full investigation and triage of a suspected phishing email to determine whether it represents a legitimate business communication or a malicious phishing attempt.
</b>
<br /><br />
All analysis is performed within a controlled sandbox environment (VirtualBox) to ensure safe handling of potentially malicious content. The investigation follows a structured SOC workflow, including email header analysis, sender and domain validation, IP reputation analysis, and attachment inspection.
<br /><br />
The objective of this investigation is to answer the following key questions:
<br /><br />
1) What is the transfer reference number listed in the email subject?<br />
2) Who is the email from?<br />
3) What is the sender’s email address?<br />
4) What email address is configured to receive replies?<br />
5) What is the originating IP address?<br />
6) Who owns the originating IP address (defanged)?<br />
7) What is the SPF record for the return-path domain?<br />
8) What is the DMARC record for the return-path domain?<br />
9) What is the name of the attachment?<br />
10) Finding and investigating the SHA256 hash of the attachment<br />
11) What is the file size of the attachment?<br />
12) What is the true file extension of the attachment?<br />
<br />
Based on the findings, a concise incident report is produced summarizing indicators of compromise, analysis results, and final assessment, after which the case is formally closed.



<h2>Tools Used</h2>

- <b>Mozilla Thunderbird:</b> Email client used to safely inspect the phishing message, analyze headers, sender information, and attachment metadata  
- <b>Vim:</b> Lightweight text editor used for reviewing raw email headers and extracting artifacts for analysis  
- <b>VirusTotal:</b> Threat intelligence platform used to investigate the attachment hash and assess malicious indicators across multiple engines  

<h2>Utilities Used</h2>

<p>  <b>Oracle VirtualBox:</b> Provided an isolated sandbox environment for safely handling and analyzing potentially malicious email artifacts. </p>


<h2>Initial Email Inspection via Thunderbird</h2>


<p align="center">
<img src="https://i.imgur.com/LhDCRz4.jpeg" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>

<h2>World map of incoming attacks after 24 hours (built custom logs including geodata)</h2>

<p align="center">
<img src="https://i.imgur.com/krRFrK5.png" height="85%" width="85%" alt="Image Analysis Dataflow"/>
</p>


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
