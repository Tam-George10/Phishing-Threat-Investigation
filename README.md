# Phishing-Threat-Investigation
This repository presents a hands-on SOC investigation focused on identifying, analyzing, and responding to phishing-based threats. The project follows a real-world Blue Team workflow, including email artifact analysis, malicious URL and attachment investigation, log correlation, and network traffic analysis. 

<h1>Real-World Scenario</h1>
A Sales Executive at Greenholt PLC received an email that he didn't expect to receive from a customer. He claims that the customer never uses generic greetings such as "Good day" and didn't expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation. 

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
  <li>🔒 <b>Domain Authentication Records Analysis</b></li>
  <li>📎 <b>Attachment Examination and SHA256 Investigation</b></li>
  <li>📑 <b>Investigation Findings and Reporting</b></li>
</ul>
<br />
All analysis is performed within a controlled sandbox environment (VirtualBox) to ensure safe handling of potentially malicious content. The investigation follows a structured SOC workflow, including inspecting the email content, analyzing headers, validating sender domains, investigating the originating IP, and examining attachments.
<br /><br />
Findings are documented in a concise incident report, summarizing indicators of compromise, analysis results, and final assessment.

<h2>Tools Used</h2>

<ul>
  <li><b>Mozilla Thunderbird:</b> Email client used to safely inspect the phishing message, analyze headers, sender information, and attachment metadata</li>
  <li><b>Vim:</b> Lightweight text editor used for reviewing raw email headers and extracting artifacts for analysis</li>
  <li><b>VirusTotal:</b> Threat intelligence platform used to investigate the attachment hash and assess malicious indicators across multiple engines</li>
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

1) What is the Transfer Reference Number listed in the email's Subject?
<p align="center">
  <img src="https://i.imgur.com/hJ5TXDN.png" width="80%" alt="Email Inspection via Thunderbird and Vim"/>
</p>
</p>

<h2>Originating IP and Network Analysis</h2>
<p>
Identify the originating IP from headers and perform geolocation, reputation, and ownership analysis to determine if the source is suspicious or malicious.
</p>

<h2>Domain Authentication Records Analysis</h2>
<p>
Validate SPF and DMARC records for the return-path domain to detect potential spoofing or misconfigured domains.
</p>

<h2>Attachment Examination and SHA256 Investigation</h2>
<p>
Analyze the attachment in a sandbox environment. Determine the file name, size, actual file extension, and calculate the SHA256 hash to check against threat intelligence platforms like VirusTotal for malicious indicators.
</p>

<h2>Investigation Findings and Reporting</h2>
<p>
Compile all findings into a structured report including:
<ul>
  <li>Indicators of compromise</li>
  <li>Threat analysis and triage results</li>
  <li>Final assessment and recommendations</li>
  <li>Closing the case</li>
</ul>
</p>

<h2>World map of incoming attacks after 24 hours (demo)</h2>
<p align="center">
<img src="https://i.imgur.com/krRFrK5.png" height="85%" width="85%" alt="World map of attacks"/>
</p>
