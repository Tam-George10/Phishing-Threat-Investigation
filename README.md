# Phishing-Threat-Investigation

This repository documents a hands-on SOC investigation focused on identifying, analyzing, and responding to a phishing-based threat. The project follows a real-world Blue Team workflow, including email artifact inspection, header analysis, malicious attachment investigation, domain authentication validation, and threat intelligence correlation.

<h1>Real-World Scenario</h1>
A Sales Executive at Greenholt PLC received an unexpected email purporting to be from a customer. He claims that the customer never uses generic greetings such as "Good day" and did not expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation.

<h2>Description</h2>
<b>
This project focuses on the full investigation and triage of a suspected phishing email to determine whether it represents a legitimate business communication or a malicious phishing attempt.
</b>
<br /><br />

<b>Investigation Workflow Overview:</b>
<ul>
  <li>📧 <b>Email Inspection via Thunderbird and Vim</b></li>
  <li>📝 <b>Email Header Analysis</b></li>
  <li>🌐 <b>Originating IP and Network Analysis</b></li>
  <li>🔒 <b>SPF / DKIM / DMARC Authentication Analysis</b></li>
  <li>📎 <b>Attachment Examination and SHA256 Investigation</b></li>
  <li>📑 <b>Investigation Findings and Reporting</b></li>
</ul>
<br />
All analysis is performed within a controlled sandbox environment (VirtualBox) to ensure safe handling of potentially malicious content.
<br /><br />
Findings are documented in a concise incident report, summarizing indicators of compromise, analysis results, and final assessment.

<h2>Tools Used</h2>

<ul>
  <li><b>Mozilla Thunderbird:</b> Email client used to safely inspect the phishing message, analyze headers, sender information, and attachment metadata</li>
  <li><b>Vim:</b> Lightweight text editor used for reviewing raw email headers and extracting artifacts for analysis</li>
  <li><b>VirusTotal:</b> Threat intelligence platform used to investigate the attachment hash and assess malicious indicators across multiple engines</li>
  <li><b>MXToolbox:</b> Online analysis tool used to inspect email headers, validate SPF/DKIM/DMARC records, analyze sender domains, and identify potential email infrastructure abuse</li>
</ul>

<h2>Utilities Used</h2>
<p>
<b>Oracle VirtualBox:</b> Provided an isolated sandbox environment for safely handling and analyzing potentially malicious email artifacts.
</p>

<h2>Initial Email Inspection via Thunderbird</h2>
<p>
All incoming email content is safely opened in Thunderbird to inspect the message, headers, sender info, subject, and any attachments. This ensures safe triage without executing any malicious content.
</p>

<p align="center">
  <img src="https://i.imgur.com/wxZwol4.png" width="80%" alt="Email Inspection via Thunderbird and Vim"/>
</p>

<h2>Email Header Analysis</h2>
<p>
Inspect email headers to extract sender IP, relay servers, SPF/DMARC information, and trace the email path for authenticity checks. This allows validation of the sender domain and potential spoofing indicators.
</p>

1) What is the Transfer Reference Number listed in the email's Subject?
<p align="center">
  <img src="https://i.imgur.com/hJ5TXDN.png" width="80%" alt="Email Header Analysis"/>
</p>

2) Who is the email from?
<p align="center">
  <img src="https://i.imgur.com/Ns5Iq46.png" width="80%" alt="Email Header Analysis"/>
</p>

3) What is his email address?
<p align="center">
  <img src="https://i.imgur.com/dsGeBSW.png" width="80%" alt="Email Header Analysis"/>
</p>

4) What email address will receive a reply to this email?
<p align="center">
  <img src="https://i.imgur.com/GCcopiG.png" width="80%" alt="Email Header Analysis"/>
</p>

5) What is the Originating IP?
<p align="center">
  <img src="https://i.imgur.com/hOBZu7c.png" width="80%" alt="Email Header Analysis"/>
</p>

<h2>Originating IP and Network Analysis</h2>
<p>
Identify the originating IP from headers and perform geolocation, reputation, and ownership analysis to determine if the source is suspicious or malicious.
</p>

1) Who is the owner of the Originating IP?
<p align="center">
  <img src="https://i.imgur.com/gNYa9A0.png" width="80%" alt="IP Analysis"/>
</p>

<h2>SPF / DKIM / DMARC Authentication Analysis Using MXToolbox</h2>
<p>
Validate SPF and DMARC records for the return-path domain to detect potential spoofing or misconfigured domains.
</p>

1) What is the SPF record for the Return-Path domain?
<p align="center">
  <img src="https://i.imgur.com/6e2MrVR.png" width="80%" alt="SPF Record"/>
</p>

2) What is the DMARC record for the Return-Path domain?
<p align="center">
  <img src="https://i.imgur.com/mT4ie2n.png" width="80%" alt="DMARC Record"/>
</p>

<h2>Attachment Examination and SHA256 Investigation</h2>
<p>
Analyze the attachment in a sandbox environment. Determine the file name, size, actual file extension, and calculate the SHA256 hash to check against threat intelligence platforms like VirusTotal for malicious indicators. No attachment was executed during the investigation.
</p>

1) What is the name of the attachment?
<p align="center">
  <img src="https://i.imgur.com/BL05wHF.png" width="80%" alt="Attachment Name"/>
</p>

2) What is the SHA256 hash of the file attachment?
<p align="center">
  <img src="https://i.imgur.com/HZnKeo8.png" width="80%" alt="SHA256 Hash"/>
</p>

3) Investigation With VirusTotal
<p align="center">
  <img src="https://i.imgur.com/Zgm1V0a.png" width="80%" alt="VirusTotal Analysis"/>
</p>

4) What is the attachment's file size?
<p align="center">
  <img src="https://i.imgur.com/8JcProW.png" width="80%" alt="File Size"/>
</p>

5) What is the actual file extension of the attachment?
<p align="center">
  <img src="https://i.imgur.com/nHXY2mB.png" width="80%" alt="File Extension"/>
</p>

<h2>Investigation Findings and Reporting</h2>

<h3>Incident Summary</h3>
<p>
A suspicious email reported by a Sales Executive at Greenholt PLC was investigated by the SOC team to determine its legitimacy. The email claimed to originate from a known customer but exhibited multiple phishing indicators, including an unexpected financial reference, generic greeting style, and an unsolicited attachment. A full triage and investigation were conducted following standard Blue Team and SOC procedures.
</p>

<h3>Indicators of Compromise (IOCs)</h3>
<ul>
  <li><b>Sender Name:</b> Mr. James Jackson</li>
  <li><b>Sender Email:</b> info@mutawamarine.com</li>
  <li><b>Reply-To Address:</b> info.mutawamarine@mail.com</li>
  <li><b>Transfer Reference Number:</b> 09674321</li>
  <li><b>Originating IP Address:</b> 192.119.71.157</li>
  <li><b>IP Owner:</b> Hostwinds LLC</li>
  <li><b>Attachment Name:</b> SWT_#09674321____PDF__.CAB</li>
  <li><b>Actual File Extension:</b> RAR</li>
  <li><b>Attachment Size:</b> 400.26 KB</li>
  <li><b>SHA256 Hash:</b> 2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f</li>
</ul>

<h3>Threat Analysis and Triage Results</h3>
<p>
Email header analysis revealed that the originating IP address (192.119.71.157) was associated with Hostwinds LLC infrastructure and not directly aligned with the legitimate sending domain, indicating possible abuse of third-party hosting services. The presence of a mismatched reply-to address further supported sender impersonation.
</p>

<p>
Domain authentication analysis identified a valid SPF record (<code>v=spf1 include:spf.protection.outlook.com -all</code>) and a DMARC policy set to quarantine (<code>v=DMARC1; p=quarantine; fo=1</code>). While these controls were present, the email still bypassed detection, suggesting abuse of trusted infrastructure or compromised email services.
</p>

<p>
The attachment was extracted and analyzed within a sandboxed environment. File inspection revealed the attachment was disguised with a misleading filename and extension. Although presented as a PDF-related CAB file, the true file type was identified as a RAR archive.
</p>

<p>
Hash-based analysis using VirusTotal confirmed the attachment as malicious, with detections identifying the file as a <b>Trojan / Ransomware / Spreader</b>. This confirms the attachment was intended as a malware delivery mechanism rather than a legitimate document.
</p>

<h3>MITRE ATT&amp;CK Mapping</h3>
<ul>
  <li><b>T1566.001 – Phishing: Spearphishing Attachment</b></li>
  <li><b>T1036 – Masquerading</b> (misleading filename and extension)</li>
  <li><b>T1204.002 – User Execution: Malicious File</b></li>
  <li><b>T1071 – Application Layer Protocol</b> (email-based delivery)</li>
</ul>

<h3>Final Assessment and Recommendations</h3>
<p>
Based on the collected evidence, the email was conclusively identified as a malicious phishing attempt designed to socially engineer the recipient into trusting a fraudulent financial transaction. The attachment functioned as a malware payload delivery vector with ransomware and trojan characteristics.
</p>

<p>
Recommended actions include:
</p>
<ul>
  <li>Immediate blocking of the sender domain and originating IP at the email gateway</li>
  <li>Hash-based blocking of the attachment across endpoint protection platforms</li>
  <li>Enhanced monitoring for similar phishing campaigns using shared infrastructure</li>
  <li>User awareness reinforcement focused on attachment-based phishing threats</li>
</ul>

<h3>Case Closure</h3>
<p>
The phishing attempt was successfully identified and contained with no evidence of execution or endpoint compromise. All indicators of compromise were documented and shared with defensive controls. The incident has been formally closed following SOC validation and reporting procedures.
</p>

